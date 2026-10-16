//! Built-in TLS for the stratum port.
//!
//! The session loop speaks line-delimited JSON either way. When a certificate
//! is configured, the accepted TCP socket is handed to rustls and the session
//! reads the plaintext end of a socket pair. Miners that do not use TLS keep
//! the plaintext listener, which is what the unit tests and a local devnet use.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::ServerConfig;

use crate::stream::Stream;

/// Load a PEM certificate chain and a PEM private key into a rustls config.
pub fn server_config(cert_pem: &str, key_pem: &str) -> io::Result<Arc<ServerConfig>> {
    install_provider();
    let mut certs_cursor = io::Cursor::new(cert_pem.as_bytes());
    let mut key_cursor = io::Cursor::new(key_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut certs_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("certificate: {e}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate PEM contained no certificates",
        ));
    }
    let key = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("private key: {e}")))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "private key PEM contained no key",
            )
        })?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Arc::new(config))
}

/// Read `--tls-cert` and `--tls-key` from disk.
pub fn load_server_config(cert_path: &str, key_path: &str) -> io::Result<Arc<ServerConfig>> {
    let cert = fs::read_to_string(cert_path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot read {cert_path}: {e}")))?;
    let key = fs::read_to_string(key_path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot read {key_path}: {e}")))?;
    server_config(&cert, &key)
}

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Complete a server handshake on `tcp` and return the plaintext stream.
///
/// The handshake and the byte shuttle run on their own thread. A failed
/// handshake closes the plaintext end, which the session observes as EOF.
pub fn splice(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<Stream> {
    let (local, mut remote) = UnixStream::pair()?;
    thread::Builder::new()
        .name("stratum-tls".into())
        .spawn(move || {
            if shuttle(tcp, &mut remote, config).is_err() {
                let _ = remote.shutdown(std::net::Shutdown::Both);
            }
        })
        .map_err(|e| io::Error::other(format!("tls thread: {e}")))?;
    Ok(Stream::Unix(local))
}

fn shuttle(tcp: TcpStream, unix: &mut UnixStream, config: Arc<ServerConfig>) -> io::Result<()> {
    let _ = tcp.set_nodelay(true);
    tcp.set_read_timeout(Some(Duration::from_millis(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    unix.set_read_timeout(Some(Duration::from_millis(20)))?;
    unix.set_write_timeout(Some(Duration::from_secs(10)))?;
    let conn = rustls::ServerConnection::new(config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut buf = [0u8; 8192];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => unix.write_all(&buf[..n])?,
            Err(e) if timed_out(&e) => {}
            Err(_) => break,
        }
        match unix.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                tls.write_all(&buf[..n])?;
                tls.flush()?;
            }
            Err(e) if timed_out(&e) => {}
            Err(_) => break,
        }
    }
    Ok(())
}

fn timed_out(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
