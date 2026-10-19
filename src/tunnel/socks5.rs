//! Minimal, dependency-free SOCKS5 client used by the tunnel engine.
//!
//! The engine always forwards *domain names* for fake-IP destinations so the
//! exit node performs the real DNS lookup. IP literals are forwarded as
//! `ATYP = IPv4/IPv6`. Both username/password (RFC 1929) and no-auth are
//! supported because the local bridge is unauthenticated while a directly
//! configured upstream may not be.

use crate::tunnel::socket_bypass::SocketBypass;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip { ip: IpAddr, port: u16 },
    Domain { name: String, port: u16 },
}

impl TargetAddr {
    pub fn ip(ip: IpAddr, port: u16) -> Self {
        Self::Ip { ip, port }
    }

    pub fn domain(name: impl Into<String>, port: u16) -> Self {
        Self::Domain {
            name: name.into(),
            port,
        }
    }

    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Ip { ip, .. } => ip.to_string(),
            TargetAddr::Domain { name, .. } => name.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip { port, .. } | TargetAddr::Domain { port, .. } => *port,
        }
    }
}

/// SOCKS5 endpoint (usually the GUI's local bridge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Endpoint {
    pub bridge: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Socks5Endpoint {
    pub fn new(bridge: SocketAddr) -> Self {
        Self {
            bridge,
            username: None,
            password: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("SOCKS5 handshake timed out")]
    Timeout,
    #[error("SOCKS5 server offered no acceptable auth method")]
    NoAcceptableAuth,
    #[error("SOCKS5 authentication failed")]
    AuthFailed,
    #[error("SOCKS5 connect failed: reply code {0:#04x}")]
    ConnectFailed(u8),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("invalid domain name for SOCKS5: {0}")]
    InvalidDomain(String),
}

/// Establish a TCP connection to `endpoint.bridge` and issue a SOCKS5 CONNECT.
///
/// `bypass` is only applied when the bridge is not a loopback address: binding
/// a loopback socket to a physical interface would make it unusable.
pub async fn connect_via_socks(
    endpoint: &Socks5Endpoint,
    target: &TargetAddr,
    bypass: Option<&SocketBypass>,
    timeout: Duration,
) -> Result<TcpStream, Socks5Error> {
    let mut stream = tokio::time::timeout(timeout, connect_tcp(endpoint.bridge, bypass))
        .await
        .map_err(|_| Socks5Error::Timeout)??;
    tokio::time::timeout(timeout, handshake(&mut stream, endpoint, target))
        .await
        .map_err(|_| Socks5Error::Timeout)??;
    Ok(stream)
}

async fn connect_tcp(addr: SocketAddr, bypass: Option<&SocketBypass>) -> io::Result<TcpStream> {
    // Fast path: going through socket2 for a loopback bridge buys nothing and
    // makes the non-blocking connect state machine observable in tests.
    if bypass.is_none() || addr.ip().is_loopback() {
        return TcpStream::connect(addr).await;
    }
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    // Loopback traffic never uses the default route; binding it to a physical
    // NIC would fail or black-hole it.
    if !addr.ip().is_loopback() {
        if let Some(bypass) = bypass {
            bypass.bind(&socket)?;
        }
    }
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if is_connect_in_progress(&e) => {}
        Err(e) => return Err(e),
    }
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    stream.writable().await?;
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }
    Ok(stream)
}

fn is_connect_in_progress(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        if e.raw_os_error() == Some(10035) {
            return true;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if e.raw_os_error() == Some(36) {
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if e.raw_os_error() == Some(115) {
            return true;
        }
    }
    false
}

async fn handshake(
    stream: &mut TcpStream,
    endpoint: &Socks5Endpoint,
    target: &TargetAddr,
) -> Result<(), Socks5Error> {
    let wants_auth = endpoint.username.is_some() || endpoint.password.is_some();
    let methods: &[u8] = if wants_auth { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(Socks5Error::Protocol(format!(
            "unexpected SOCKS version {:#04x}",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let user = endpoint.username.as_deref().unwrap_or("");
            let pass = endpoint.password.as_deref().unwrap_or("");
            if user.len() > 255 || pass.len() > 255 {
                return Err(Socks5Error::Protocol("credentials too long".into()));
            }
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(Socks5Error::AuthFailed);
            }
        }
        0xff => return Err(Socks5Error::NoAcceptableAuth),
        other => {
            return Err(Socks5Error::Protocol(format!(
                "server selected unsupported auth method {other:#04x}"
            )))
        }
    }

    let mut request = Vec::with_capacity(262);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    encode_address(&mut request, target)?;
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(Socks5Error::Protocol(format!(
            "unexpected SOCKS version in reply {:#04x}",
            header[0]
        )));
    }
    if header[1] != 0x00 {
        return Err(Socks5Error::ConnectFailed(header[1]));
    }
    skip_reply_address(stream, header[3]).await?;
    Ok(())
}

fn encode_address(buf: &mut Vec<u8>, target: &TargetAddr) -> Result<(), Socks5Error> {
    match target {
        TargetAddr::Ip { ip: IpAddr::V4(ip), .. } => {
            buf.push(0x01);
            buf.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip { ip: IpAddr::V6(ip), .. } => {
            buf.push(0x04);
            buf.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain { name, .. } => {
            let ascii = name.trim_end_matches('.');
            if ascii.is_empty() || ascii.len() > 255 {
                return Err(Socks5Error::InvalidDomain(name.clone()));
            }
            buf.push(0x03);
            buf.push(ascii.len() as u8);
            buf.extend_from_slice(ascii.as_bytes());
        }
    }
    buf.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

async fn skip_reply_address(stream: &mut TcpStream, atyp: u8) -> Result<(), Socks5Error> {
    match atyp {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
        }
        other => {
            return Err(Socks5Error::Protocol(format!(
                "unsupported reply address type {other:#04x}"
            )))
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP ASSOCIATE (optional; used when the upstream supports UDP and QUIC has
// not been disabled). The local GUI bridge currently only implements CONNECT,
// so failures here are expected and handled by the engine.
// ---------------------------------------------------------------------------

/// Ask the SOCKS5 server for a UDP relay address. The returned control
/// connection must be kept alive for as long as the association is used.
pub async fn udp_associate(
    endpoint: &Socks5Endpoint,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), Socks5Error> {
    let mut stream = tokio::time::timeout(timeout, connect_tcp(endpoint.bridge, None))
        .await
        .map_err(|_| Socks5Error::Timeout)??;
    let relay = tokio::time::timeout(timeout, async {
        let wants_auth = endpoint.username.is_some() || endpoint.password.is_some();
        let methods: &[u8] = if wants_auth { &[0x00, 0x02] } else { &[0x00] };
        let mut greeting = vec![0x05, methods.len() as u8];
        greeting.extend_from_slice(methods);
        stream.write_all(&greeting).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply[1] == 0x02 {
            let user = endpoint.username.as_deref().unwrap_or("");
            let pass = endpoint.password.as_deref().unwrap_or("");
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0 {
                return Err(Socks5Error::AuthFailed);
            }
        } else if reply[1] != 0x00 {
            return Err(Socks5Error::NoAcceptableAuth);
        }

        // BND.ADDR is the relay address we must send datagrams to.
        stream
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[1] != 0 {
            return Err(Socks5Error::ConnectFailed(header[1]));
        }
        let relay = read_reply_address(&mut stream, header[3]).await?;
        Ok(relay)
    })
    .await
    .map_err(|_| Socks5Error::Timeout)??;
    Ok((stream, relay))
}

async fn read_reply_address(
    stream: &mut TcpStream,
    atyp: u8,
) -> Result<SocketAddr, Socks5Error> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        0x04 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
            Ok(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let host = String::from_utf8(name)
                .map_err(|_| Socks5Error::Protocol("non-UTF8 relay hostname".into()))?;
            // A domain relay address is unusual; resolve it locally.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((
                host,
                u16::from_be_bytes(port),
            ))
            .await?
            .collect();
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| Socks5Error::Protocol("relay hostname did not resolve".into()))
        }
        other => Err(Socks5Error::Protocol(format!(
            "unsupported reply address type {other:#04x}"
        ))),
    }
}

/// Encode a SOCKS5 UDP request header + payload.
pub fn encode_udp_datagram(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>, Socks5Error> {
    let mut out = vec![0x00, 0x00, 0x00];
    encode_address(&mut out, target)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// Drop the SOCKS5 UDP header, returning the payload.
pub fn decode_udp_datagram(mut datagram: &[u8]) -> Result<Vec<u8>, Socks5Error> {
    if datagram.len() < 4 || datagram[0] != 0 || datagram[1] != 0 {
        return Err(Socks5Error::Protocol("malformed UDP datagram".into()));
    }
    let atyp = datagram[3];
    let skip = match atyp {
        0x01 => 4 + 4,
        0x04 => 4 + 16,
        0x03 => {
            if datagram.len() < 5 {
                return Err(Socks5Error::Protocol("malformed UDP datagram".into()));
            }
            4 + 1 + datagram[4] as usize
        }
        _ => return Err(Socks5Error::Protocol("bad UDP address type".into())),
    };
    if datagram.len() < skip + 2 {
        return Err(Socks5Error::Protocol("short UDP datagram".into()));
    }
    datagram = &datagram[skip + 2..];
    Ok(datagram.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::fake_dns::FakeDns;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A mock SOCKS5 server that records the CONNECT target and echoes one
    /// byte afterwards.
    async fn mock_socks5() -> (SocketAddr, tokio::sync::oneshot::Receiver<(u8, String, u16)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 2];
            socket.read_exact(&mut greet).await.unwrap();
            let mut methods = vec![0u8; greet[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            let mut head = [0u8; 4];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x05);
            assert_eq!(head[1], 0x01);
            let atyp = head[3];
            let host = match atyp {
                0x03 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    let mut name = vec![0u8; len[0] as usize];
                    socket.read_exact(&mut name).await.unwrap();
                    String::from_utf8(name).unwrap()
                }
                0x01 => {
                    let mut b = [0u8; 4];
                    socket.read_exact(&mut b).await.unwrap();
                    Ipv4Addr::from(b).to_string()
                }
                other => panic!("unexpected atyp {other}"),
            };
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).await.unwrap();
            let port = u16::from_be_bytes(port);
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let _ = tx.send((atyp, host.clone(), port));
            let mut buf = [0u8; 32];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let _ = socket.write_all(&buf[..n]).await;
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn test_end_to_end_fake_ip_to_socks5_domain_atyp() {
        let (server, target_rx) = mock_socks5().await;
        let dns = FakeDns::new();
        let fake = dns.allocate("verify.proxybase.xyz");
        assert!(dns.is_fake_ip(fake));
        let domain = dns.reverse_lookup(fake).unwrap();

        let endpoint = Socks5Endpoint::new(server);
        let mut stream = connect_via_socks(
            &endpoint,
            &TargetAddr::domain(domain.clone(), 443),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        let (atyp, host, port) = target_rx.await.unwrap();
        assert_eq!(atyp, 0x03, "must use ATYP=DOMAINNAME, never the 198.18 IP");
        assert_eq!(host, "verify.proxybase.xyz");
        assert_eq!(port, 443);

        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    #[test]
    fn encodes_ipv4_ipv6_and_domain_addresses() {
        let mut buf = Vec::new();
        encode_address(&mut buf, &TargetAddr::ip("1.2.3.4".parse().unwrap(), 80)).unwrap();
        assert_eq!(buf, [0x01, 1, 2, 3, 4, 0, 80]);

        buf.clear();
        encode_address(
            &mut buf,
            &TargetAddr::ip("2001:db8::1".parse().unwrap(), 443),
        )
        .unwrap();
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf.len(), 19);

        buf.clear();
        encode_address(&mut buf, &TargetAddr::domain("example.com", 8080)).unwrap();
        assert_eq!(buf, [0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x1f, 0x90]);
    }
}
