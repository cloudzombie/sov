//! One stratum byte stream.
//!
//! Plaintext sessions are the accepted TCP socket. TLS sessions are the
//! plaintext end of an in-process splice: rustls owns the TCP socket, and
//! this end is an ordinary stream the session reader and the job writer can
//! both use.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// A stratum connection after the accept path has decided plaintext or TLS.
pub enum Stream {
    /// The miner connected without TLS.
    Tcp(TcpStream),
    /// Plaintext half of a TLS splice.
    Unix(UnixStream),
}

impl Stream {
    /// Wrap an accepted plaintext socket.
    pub fn tcp(stream: TcpStream) -> Self {
        Stream::Tcp(stream)
    }

    /// A second handle for the writer thread. TCP and Unix sockets both clone.
    pub fn try_clone(&self) -> io::Result<Stream> {
        match self {
            Stream::Tcp(stream) => Ok(Stream::Tcp(stream.try_clone()?)),
            Stream::Unix(stream) => Ok(Stream::Unix(stream.try_clone()?)),
        }
    }

    /// How long a read may block.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.set_read_timeout(timeout),
            Stream::Unix(stream) => stream.set_read_timeout(timeout),
        }
    }

    /// How long a write may block.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.set_write_timeout(timeout),
            Stream::Unix(stream) => stream.set_write_timeout(timeout),
        }
    }

    /// Disable Nagle on TCP. Unix pairs have no equivalent, and do not need one.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.set_nodelay(nodelay),
            Stream::Unix(_) => Ok(()),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.read(buf),
            Stream::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.write(buf),
            Stream::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.flush(),
            Stream::Unix(stream) => stream.flush(),
        }
    }
}
