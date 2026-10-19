//! Exit-node verification.
//!
//! The UI must never claim "Connected" merely because routes were installed.
//! This module opens a SOCKS5 connection through the same path user traffic
//! will take, performs a tiny HTTP request to an IP-echo endpoint, and returns
//! the observed exit address and round-trip latency.

use crate::tunnel::socks5::{connect_via_socks, Socks5Endpoint, Socks5Error, TargetAddr};
use crate::tunnel::socket_bypass::SocketBypass;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub exit_ip: String,
    pub latency_ms: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("upstream unreachable: {0}")]
    Upstream(String),
    #[error("exit verification failed: {0}")]
    Verification(String),
    /// The SOCKS5 upstream rejected CONNECT with a reply code. 0x02 / 0x05
    /// usually mean the purchased session ran out of bandwidth or its lease
    /// was revoked.
    #[error("upstream proxy rejected the connection (SOCKS5 reply {0:#04x})")]
    UpstreamRejected(u8),
}

#[derive(Deserialize)]
struct IpEcho {
    #[serde(alias = "ip_address", alias = "origin", alias = "query")]
    ip: Option<String>,
}

/// Verify the exit node by requesting an IP-echo endpoint through the SOCKS5
/// bridge. The total operation is bounded by `timeout`.
pub async fn verify_exit_node(
    endpoint: &Socks5Endpoint,
    bypass: Option<&SocketBypass>,
    timeout: Duration,
) -> Result<ExitInfo, HealthError> {
    let started = Instant::now();
    // ProxyBase's own endpoint first (works over plain HTTP and is already
    // used by the GUI); ipify as an independent fallback.
    let attempts = [
        ("api.proxybase.xyz", 80u16, "/v2/ip"),
        ("api.ipify.org", 80u16, "/?format=json"),
    ];
    let mut last_error = String::new();
    let mut rejected: Option<u8> = None;
    for (host, port, path) in attempts {
        match probe(endpoint, bypass, host, port, path, timeout).await {
            Ok(ip) => {
                let latency_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
                return Ok(ExitInfo {
                    exit_ip: ip,
                    latency_ms,
                });
            }
            Err(HealthError::UpstreamRejected(code)) => {
                rejected = Some(code);
                last_error = format!("proxy rejected CONNECT: {code:#04x}");
            }
            Err(e) => {
                rejected = None;
                last_error = e.to_string();
            }
        }
    }
    if let Some(code) = rejected {
        return Err(HealthError::UpstreamRejected(code));
    }
    Err(HealthError::Verification(last_error))
}

async fn probe(
    endpoint: &Socks5Endpoint,
    bypass: Option<&SocketBypass>,
    host: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> Result<String, HealthError> {
    let mut stream = tokio::time::timeout(
        timeout,
        connect_via_socks(
            endpoint,
            &TargetAddr::domain(host.to_string(), port),
            bypass,
            timeout,
        ),
    )
    .await
    .map_err(|_| HealthError::Upstream("SOCKS5 connect timed out".into()))?
    .map_err(|e| match e {
        Socks5Error::ConnectFailed(code) => HealthError::UpstreamRejected(code),
        other => HealthError::Upstream(other.to_string()),
    })?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: proxybase-tunneld\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| HealthError::Verification(e.to_string()))?;

    let mut response = Vec::with_capacity(4096);
    let read = async {
        let mut buf = [0u8; 2048];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 64 * 1024 {
                        break;
                    }
                    if let Some(body_start) = find_body(&response) {
                        // Stop once the body has data and the connection is
                        // closed or the JSON looks complete.
                        let body = &response[body_start..];
                        if body.contains(&b'}') {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    };
    let _ = tokio::time::timeout(timeout, read).await;

    parse_exit_ip(&response).ok_or_else(|| {
        HealthError::Verification(format!(
            "could not parse an IP address from {}",
            String::from_utf8_lossy(&response[..response.len().min(200)])
        ))
    })
}

fn find_body(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn parse_exit_ip(response: &[u8]) -> Option<String> {
    let body_start = find_body(response)?;
    let body = std::str::from_utf8(&response[body_start..]).ok()?;
    let trimmed = body.trim();
    if let Ok(parsed) = serde_json::from_str::<IpEcho>(trimmed) {
        if let Some(ip) = parsed.ip {
            let candidate = ip.split(',').next().unwrap_or(&ip).trim();
            if candidate.parse::<std::net::IpAddr>().is_ok() {
                return Some(candidate.to_string());
            }
        }
    }
    // Some endpoints return a bare IP.
    let first_line = trimmed.lines().next()?.trim();
    if let Ok(ip) = first_line.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    trimmed
        .split_whitespace()
        .find(|w| w.parse::<std::net::IpAddr>().is_ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_and_plain_ip_echoes() {
        let json = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ip\":\"203.0.113.7\"}";
        assert_eq!(parse_exit_ip(json).as_deref(), Some("203.0.113.7"));

        let plain = b"HTTP/1.1 200 OK\r\n\r\n198.51.100.9\n";
        assert_eq!(parse_exit_ip(plain).as_deref(), Some("198.51.100.9"));

        let comma = b"HTTP/1.1 200 OK\r\n\r\n{\"origin\":\"203.0.113.7, 10.0.0.1\"}";
        assert_eq!(parse_exit_ip(comma).as_deref(), Some("203.0.113.7"));
    }
}
