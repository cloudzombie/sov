//! UPnP IGD port mapping — asking the router to let peers in.
//!
//! # What this is for
//!
//! A node behind NAT can always dial *out*: it syncs, relays and mines fine, and
//! its blocks reach the network. What it cannot do is accept *inbound*
//! connections, so nobody can dial it. It is a leaf rather than a participant,
//! and a network of only leaves has nowhere to connect to.
//!
//! Most home routers will open a port on request via UPnP IGD. This module asks.
//! If the router says no — or does not speak UPnP, or is carrier-grade NAT where
//! no amount of asking helps — nothing breaks: the node keeps working exactly as
//! it does today, unreachable but fully functional. **Every failure here is a
//! silent no-op**, never an error the operator has to care about.
//!
//! # Everything here parses hostile input
//!
//! SSDP is an unauthenticated UDP multicast: *anything* on the LAN can answer,
//! and the first answer usually wins. The device description is then fetched
//! over plain HTTP from an address that reply chose. So a hostile device on the
//! network controls every byte this module reads.
//!
//! That shapes the code more than the protocol does:
//!
//! - every read is bounded before it is allocated;
//! - responses are scanned, never parsed into a document model — a full XML
//!   parser is a large attack surface for what amounts to extracting two
//!   strings;
//! - the control URL is required to be on the SAME host we discovered, so a
//!   reply cannot redirect the SOAP call somewhere else;
//! - nothing panics, and every step has a timeout, so a device that answers
//!   slowly or forever cannot wedge startup.
//!
//! The worst a hostile responder achieves is that no mapping is created, which
//! is the same as having no UPnP at all.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long to wait for SSDP replies.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

/// How long any single HTTP exchange may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest SSDP datagram accepted.
const MAX_SSDP_BYTES: usize = 4 * 1024;

/// Largest HTTP response accepted (device descriptions are a few KB).
const MAX_HTTP_BYTES: usize = 256 * 1024;

/// Requested mapping lifetime, in seconds. Renewed well before expiry, so a
/// crashed node's mapping lapses instead of lingering forever.
pub const MAPPING_LIFETIME_SECS: u32 = 3600;

/// The multicast endpoint SSDP discovery is sent to.
const SSDP_ADDR: &str = "239.255.255.250:1900";

/// A discovered IGD control endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    /// Where the SOAP control endpoint lives.
    pub control: SocketAddr,
    /// The path to POST control actions to.
    pub control_path: String,
    /// The service type to invoke (WANIPConnection or WANPPPConnection, and
    /// version 1 or 2 — routers differ, so it is taken from the device rather
    /// than assumed).
    pub service_type: String,
}

/// Extract the value between `<tag>` and `</tag>`, bounded and total.
///
/// A deliberate substring scan rather than an XML parse. Two strings are needed
/// out of a device description; pulling in a full parser to get them would be a
/// large attack surface for a small convenience, and this cannot recurse,
/// allocate unboundedly, or panic on malformed input.
fn tag_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let rest = xml.get(start..)?;
    let end = rest.find(&close)?;
    let v = rest.get(..end)?.trim();
    (!v.is_empty() && v.len() <= 512).then_some(v)
}

/// Case-insensitively read one HTTP header value.
fn header_value<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let lower_name = name.to_ascii_lowercase();
    response.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        (k.trim().to_ascii_lowercase() == lower_name).then(|| v.trim())
    })
}

/// Find an IGD on the local network via SSDP.
///
/// Returns `None` when nothing answers, which is the common and entirely
/// unremarkable case (no UPnP router, UPnP disabled, or carrier-grade NAT).
pub fn discover_gateway() -> Option<Gateway> {
    // Bind to an ephemeral port on all interfaces; the reply comes back
    // unicast to it.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(DISCOVERY_TIMEOUT)).ok()?;

    // `MX` is the maximum seconds a device may wait before replying — keeping
    // it under our own timeout means a compliant device answers in time.
    let search = "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    sock.send_to(search.as_bytes(), SSDP_ADDR).ok()?;

    // Several devices may answer. Try each in turn rather than trusting the
    // first — a hostile responder is usually fastest, and the honest router may
    // be right behind it.
    let mut buf = [0u8; MAX_SSDP_BYTES];
    let deadline = std::time::Instant::now() + DISCOVERY_TIMEOUT;
    while std::time::Instant::now() < deadline {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            break; // timed out: nothing (more) is answering
        };
        let Some(text) = std::str::from_utf8(&buf[..n.min(MAX_SSDP_BYTES)]).ok() else {
            continue; // not text; ignore rather than fail the whole discovery
        };
        let Some(location) = header_value(text, "LOCATION") else {
            continue;
        };
        if let Some(gw) = describe(location, from.ip()) {
            return Some(gw);
        }
    }
    None
}

/// Fetch and interpret a device description, yielding a control endpoint.
///
/// `expect_host` is the address the SSDP reply came FROM. The description's
/// location must match it, so a reply cannot point us at a third party.
fn describe(location: &str, expect_host: IpAddr) -> Option<Gateway> {
    let (host_port, path) = split_http_url(location)?;
    let addr: SocketAddr = host_port.parse().ok()?;
    if addr.ip() != expect_host {
        // The reply named a different host than it came from. Refuse: this is
        // how an SSDP responder would aim our SOAP calls elsewhere.
        return None;
    }
    let body = http_get(addr, &path)?;

    // Prefer WANIPConnection, fall back to WANPPPConnection; take the version
    // the device actually advertises rather than assuming :1.
    for want in [
        "urn:schemas-upnp-org:service:WANIPConnection:",
        "urn:schemas-upnp-org:service:WANPPPConnection:",
    ] {
        if let Some(idx) = body.find(want) {
            // The controlURL that FOLLOWS this service declaration.
            let tail = body.get(idx..)?;
            let service_type = tag_value(tail, "serviceType")?.to_string();
            let control_path = tag_value(tail, "controlURL")?.to_string();
            if !service_type.starts_with(want) || !control_path.starts_with('/') {
                continue; // malformed or relative in a way we will not guess at
            }
            return Some(Gateway {
                control: addr,
                control_path,
                service_type,
            });
        }
    }
    None
}

/// Split `http://host:port/path` into its address and path.
fn split_http_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("http://")?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (rest.get(..i)?, rest.get(i..)?),
        None => (rest, "/"),
    };
    // A bare host with no port is port 80.
    let host_port = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    Some((host_port, path.to_string()))
}

/// A bounded HTTP GET.
fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nUser-Agent: sov\r\n\r\n"
    );
    http_exchange(addr, req.as_bytes())
}

/// A bounded HTTP request/response. Never panics; every failure is `None`.
fn http_exchange(addr: SocketAddr, request: &[u8]) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr, HTTP_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).ok()?;
    stream.write_all(request).ok()?;
    stream.flush().ok()?;

    // Read with a HARD ceiling: the peer chooses how much to send, so it does
    // not get to choose how much we allocate.
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() + n > MAX_HTTP_BYTES {
                    return None; // oversized: refuse rather than truncate
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(_) => break,
        }
    }
    String::from_utf8(out).ok()
}

/// Ask the gateway to forward `external_port` to `internal_addr`.
///
/// Returns whether the router accepted. A `false` is not an error worth
/// surfacing: it means the node stays outbound-only, which is how it already
/// runs.
pub fn add_port_mapping(
    gw: &Gateway,
    internal_addr: SocketAddr,
    external_port: u16,
    description: &str,
) -> bool {
    // The description is ours, but keep it strictly alphanumeric anyway: it is
    // interpolated into XML, and a value with markup in it would be an
    // injection into our own request.
    let safe_desc: String = description
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ' ')
        .take(64)
        .collect();

    let body = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:AddPortMapping xmlns:u=\"{svc}\">\
         <NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{ext}</NewExternalPort>\
         <NewProtocol>TCP</NewProtocol>\
         <NewInternalPort>{int}</NewInternalPort>\
         <NewInternalClient>{ip}</NewInternalClient>\
         <NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>{desc}</NewPortMappingDescription>\
         <NewLeaseDuration>{life}</NewLeaseDuration>\
         </u:AddPortMapping></s:Body></s:Envelope>",
        svc = gw.service_type,
        ext = external_port,
        int = internal_addr.port(),
        ip = internal_addr.ip(),
        desc = safe_desc,
        life = MAPPING_LIFETIME_SECS,
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{svc}#AddPortMapping\"\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        path = gw.control_path,
        addr = gw.control,
        svc = gw.service_type,
        len = body.len(),
        body = body,
    );
    match http_exchange(gw.control, req.as_bytes()) {
        Some(resp) => resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"),
        None => false,
    }
}

/// Ask the gateway to REMOVE a mapping.
///
/// Called on shutdown so a stopped node does not leave the router forwarding a
/// port to nothing. Routers have finite mapping tables, and a node that restarts
/// often would otherwise fill one.
pub fn delete_port_mapping(gw: &Gateway, external_port: u16) -> bool {
    let body = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:DeletePortMapping xmlns:u=\"{svc}\">\
         <NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{ext}</NewExternalPort>\
         <NewProtocol>TCP</NewProtocol>\
         </u:DeletePortMapping></s:Body></s:Envelope>",
        svc = gw.service_type,
        ext = external_port,
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{svc}#DeletePortMapping\"\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        path = gw.control_path,
        addr = gw.control,
        svc = gw.service_type,
        len = body.len(),
        body = body,
    );
    matches!(http_exchange(gw.control, req.as_bytes()), Some(r)
        if r.starts_with("HTTP/1.1 200") || r.starts_with("HTTP/1.0 200"))
}

/// Whether this node currently believes it is reachable from outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Reachability {
    /// No attempt has completed yet.
    #[default]
    Unknown,
    /// A router accepted a mapping and it is being renewed.
    Mapped,
    /// No router accepted one. The node is outbound-only — fully functional,
    /// just not dialable.
    Unmapped,
}

impl Reachability {
    /// A short word for status output.
    pub fn as_str(self) -> &'static str {
        match self {
            Reachability::Unknown => "unknown",
            Reachability::Mapped => "mapped",
            Reachability::Unmapped => "unmapped",
        }
    }
}

/// Owns a port mapping for the life of the process: establishes it, RENEWS it
/// before the lease expires, and removes it on shutdown.
///
/// Renewal is the part that matters. A mapping is a LEASE — ours is
/// [`MAPPING_LIFETIME_SECS`] — and a node that maps once and forgets goes
/// quietly unreachable an hour later with nothing in the log to explain why.
/// That failure is worse than never mapping at all, because the operator has
/// been told they are reachable.
pub struct PortMapper {
    state: Arc<Mutex<MapperState>>,
    stop: Arc<AtomicBool>,
}

#[derive(Default)]
struct MapperState {
    gateway: Option<Gateway>,
    reachability: Reachability,
    /// Consecutive failures, for backoff — a router that says no should not be
    /// asked again every few seconds.
    failures: u32,
}

impl PortMapper {
    /// Start maintaining a mapping for `internal_addr` in the background.
    ///
    /// Returns immediately: discovery waits seconds for SSDP replies and nothing
    /// should block node startup on a router.
    pub fn start(
        internal_addr: SocketAddr,
        description: &str,
        log: impl Fn(String) + Send + 'static,
    ) -> PortMapper {
        let state = Arc::new(Mutex::new(MapperState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let desc = description.to_string();
        let st = Arc::clone(&state);
        let sp = Arc::clone(&stop);

        std::thread::spawn(move || {
            // Renew at HALF the lease. If one renewal is lost to a transient
            // failure there is still a full half-life to recover before the
            // mapping actually lapses.
            let renew_every = Duration::from_secs((MAPPING_LIFETIME_SECS / 2) as u64);
            while !sp.load(Ordering::Relaxed) {
                let existing = st.lock().ok().and_then(|s| s.gateway.clone());
                let gw = match existing {
                    Some(g) => Some(g),
                    None => discover_gateway(),
                };
                let ok = match &gw {
                    Some(g) => add_port_mapping(g, internal_addr, internal_addr.port(), &desc),
                    None => false,
                };
                let mut backoff = renew_every;
                if let Ok(mut s) = st.lock() {
                    if ok {
                        let first = s.reachability != Reachability::Mapped;
                        s.gateway = gw.clone();
                        s.reachability = Reachability::Mapped;
                        s.failures = 0;
                        if first {
                            if let Some(g) = &gw {
                                log(format!(
                                    "UPnP: router {} mapped port {} — this node accepts \
                                     inbound peers (lease {}s, renewed every {}s)",
                                    g.control.ip(),
                                    internal_addr.port(),
                                    MAPPING_LIFETIME_SECS,
                                    renew_every.as_secs()
                                ));
                            }
                        }
                    } else {
                        // Drop the cached gateway so the next attempt rediscovers:
                        // the router may have rebooted or changed address.
                        s.gateway = None;
                        s.failures = s.failures.saturating_add(1);
                        if s.reachability != Reachability::Unmapped {
                            s.reachability = Reachability::Unmapped;
                            log(format!(
                                "UPnP: no port mapping (no IGD router, UPnP disabled, or \
                                 carrier-grade NAT). The node works normally — it simply \
                                 cannot accept INBOUND peers. Forward TCP {} to make it \
                                 reachable.",
                                internal_addr.port()
                            ));
                        }
                        // Back off so a router that refuses is not hammered:
                        // 1, 2, 4 … minutes, capped at the renewal interval.
                        let mins = 1u64 << s.failures.min(6);
                        backoff = Duration::from_secs(mins * 60).min(renew_every);
                    }
                }
                // Sleep in short slices so shutdown is prompt rather than waiting
                // out a half-hour renewal interval.
                let deadline = std::time::Instant::now() + backoff;
                while std::time::Instant::now() < deadline {
                    if sp.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        });

        PortMapper { state, stop }
    }

    /// What this node believes about its own reachability.
    pub fn reachability(&self) -> Reachability {
        self.state
            .lock()
            .map(|s| s.reachability)
            .unwrap_or_default()
    }

    /// The router currently holding the mapping, if any.
    pub fn gateway(&self) -> Option<Gateway> {
        self.state.lock().ok().and_then(|s| s.gateway.clone())
    }

    /// Stop renewing and REMOVE the mapping.
    pub fn shutdown(&self, internal_port: u16) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(gw) = self.gateway() {
            // Best-effort: a router that has already forgotten us is fine.
            let _ = delete_port_mapping(&gw, internal_port);
        }
    }
}

/// One-shot map, without renewal. Prefer [`PortMapper`] for anything long-lived
/// — a lease that is never renewed lapses.
pub fn try_map_port(internal_addr: SocketAddr, description: &str) -> Option<Gateway> {
    let gw = discover_gateway()?;
    add_port_mapping(&gw, internal_addr, internal_addr.port(), description).then_some(gw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESC: &str = "<?xml version=\"1.0\"?><root>\
        <device><deviceType>InternetGatewayDevice:1</deviceType>\
        <serviceList><service>\
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
        <controlURL>/ctl/IPConn</controlURL>\
        </service></serviceList></device></root>";

    #[test]
    fn tag_values_are_extracted_and_bounded() {
        assert_eq!(tag_value(DESC, "controlURL"), Some("/ctl/IPConn"));
        assert_eq!(
            tag_value(DESC, "serviceType"),
            Some("urn:schemas-upnp-org:service:WANIPConnection:1")
        );
        assert_eq!(tag_value(DESC, "nope"), None);
        // An unclosed tag yields nothing rather than running off the end.
        assert_eq!(tag_value("<a>value", "a"), None);
        // Empty values are refused: they would produce a nonsense control path.
        assert_eq!(tag_value("<a></a>", "a"), None);
        // Absurdly long values are refused rather than carried around.
        let long = format!("<a>{}</a>", "x".repeat(5_000));
        assert_eq!(tag_value(&long, "a"), None);
    }

    /// The parser must survive anything a LAN device can send. It is the first
    /// thing hostile bytes reach, and a panic here is a remote crash.
    #[test]
    fn no_malformed_description_panics() {
        let hostile = [
            "",
            "<",
            "<a>",
            "</a>",
            "<a><a><a><a>",
            "<controlURL>",
            "<controlURL></controlURL>",
            "\0\0\0",
            "<controlURL>\u{202e}evil</controlURL>",
            &"<a>".repeat(10_000),
            &"\u{1F4A5}".repeat(1_000),
        ];
        for h in hostile {
            // The only requirement is that it RETURNS.
            let _ = tag_value(h, "controlURL");
            let _ = tag_value(h, "serviceType");
            let _ = header_value(h, "LOCATION");
            let _ = split_http_url(h);
        }
    }

    #[test]
    fn headers_are_read_case_insensitively() {
        let resp = "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1:80/d.xml\r\nST: x\r\n";
        assert_eq!(
            header_value(resp, "location"),
            Some("http://10.0.0.1:80/d.xml")
        );
        assert_eq!(
            header_value(resp, "LOCATION"),
            Some("http://10.0.0.1:80/d.xml")
        );
        assert_eq!(header_value(resp, "missing"), None);
    }

    #[test]
    fn urls_split_into_address_and_path() {
        assert_eq!(
            split_http_url("http://192.168.1.1:5000/rootDesc.xml"),
            Some(("192.168.1.1:5000".into(), "/rootDesc.xml".into()))
        );
        // No port means 80.
        assert_eq!(
            split_http_url("http://192.168.1.1/d.xml"),
            Some(("192.168.1.1:80".into(), "/d.xml".into()))
        );
        // No path means root.
        assert_eq!(
            split_http_url("http://192.168.1.1:80"),
            Some(("192.168.1.1:80".into(), "/".into()))
        );
        // Anything not plain HTTP is refused — we will not follow https or
        // other schemes from an unauthenticated discovery reply.
        assert_eq!(split_http_url("https://192.168.1.1/d.xml"), None);
        assert_eq!(split_http_url("ftp://x/d"), None);
        assert_eq!(split_http_url("not a url"), None);
    }

    /// A description naming a DIFFERENT host than the one that answered must be
    /// refused. Otherwise an SSDP responder aims our SOAP calls at a third
    /// party, using us to talk to something we never chose.
    #[test]
    fn a_description_pointing_at_another_host_is_refused() {
        // 203.0.113.1 answered, but the location names 198.51.100.9.
        let out = describe(
            "http://198.51.100.9:80/d.xml",
            "203.0.113.1".parse().unwrap(),
        );
        assert!(
            out.is_none(),
            "a redirect to another host must be refused before any request is made"
        );
    }

    /// The mapping description is interpolated into XML we generate, so it must
    /// not be able to carry markup.
    #[test]
    fn the_mapping_description_cannot_inject_markup() {
        let dirty = "sov</NewPortMappingDescription><Evil>x";
        let safe: String = dirty
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ' ')
            .take(64)
            .collect();
        assert_eq!(safe, "sovNewPortMappingDescriptionEvilx");
        assert!(!safe.contains('<') && !safe.contains('>') && !safe.contains('/'));
    }

    /// Discovery on a machine with no IGD must return cleanly, not hang or
    /// panic. This runs on CI, where nothing will answer.
    #[test]
    fn discovery_without_a_gateway_returns_cleanly() {
        let t0 = std::time::Instant::now();
        let _ = discover_gateway();
        assert!(
            t0.elapsed() < DISCOVERY_TIMEOUT * 3,
            "discovery must be bounded by its own timeout"
        );
    }
}
