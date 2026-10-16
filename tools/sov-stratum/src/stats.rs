//! Read-only pool statistics, plus the one authenticated write: miners posting
//! payout transactions they already signed.
//!
//! MiningPoolStats and minerstat scrape `GET /api/stats`. Numbers come from
//! shares the pool actually accepted. Nothing here invents hashrate or miners.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Stats request handler.
pub type Handler = Arc<dyn Fn(&Incoming) -> (u16, String) + Send + Sync>;

/// One HTTP/1.1 request. The stats port serves a single request per connection.
pub struct Incoming {
    /// `GET` or `POST`.
    pub method: String,
    /// Path without the query string.
    pub path: String,
    /// Raw body, capped by the server.
    pub body: Vec<u8>,
    /// Peer address, for the payout-post rate limit.
    pub peer: std::net::IpAddr,
}

/// Bind `addr` (`host:port`, port `0` allowed) and serve until the process exits.
pub fn spawn(addr: &str, handler: Handler) -> Result<std::net::SocketAddr, String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot bind stats {addr}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("stats listener has no address: {e}"))?;
    thread::Builder::new()
        .name("pool-stats".into())
        .spawn(move || accept_loop(listener, handler))
        .map_err(|e| format!("spawn stats thread: {e}"))?;
    Ok(bound)
}

fn accept_loop(listener: TcpListener, handler: Handler) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let handler = Arc::clone(&handler);
        let _ = thread::Builder::new()
            .name("stats-conn".into())
            .spawn(move || {
                if let Err(e) = serve_one(conn, handler.as_ref()) {
                    eprintln!("stats connection: {e}");
                }
            });
    }
}

const MAX_BODY: usize = 256 * 1024;

fn serve_one(
    mut conn: TcpStream,
    handler: &dyn Fn(&Incoming) -> (u16, String),
) -> std::io::Result<()> {
    let peer = conn
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or_else(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if buf.len() > MAX_BODY {
            return write_response(&mut conn, 413, r#"{"error":"headers too large"}"#);
        }
        match conn.read(&mut tmp)? {
            0 => return Ok(()),
            n => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos;
                }
            }
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let Some(request) = lines.next() else {
        return write_response(&mut conn, 400, r#"{"error":"empty request"}"#);
    };
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/");
    let path = target.split('?').next().unwrap_or("/").to_string();
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return write_response(&mut conn, 413, r#"{"error":"body too large"}"#);
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        match conn.read(&mut tmp)? {
            0 => break,
            n => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(content_length);
    let (status, payload) = handler(&Incoming {
        method,
        path,
        body,
        peer,
    });
    write_response(&mut conn, status, &payload)
}

fn write_response(conn: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(resp.as_bytes())?;
    conn.flush()
}
