//! Serializable configuration and IPC schema shared by `libproxybase`,
//! `proxybase-tunneld`, the Tauri shell, and the TypeScript frontend.
//!
//! The types in this module are the wire format for the authenticated local
//! IPC channel. They are deliberately free of platform-specific types so the
//! same definitions compile on desktop and Android.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Public state machine of the system-wide tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected,
    RequestingPrivileges,
    ConfiguringRoutes {
        proxy_id: String,
    },
    VerifyingExitNode {
        proxy_id: String,
    },
    Connected {
        proxy_id: String,
        exit_ip: String,
        country_code: Option<String>,
        isp: Option<String>,
        latency_ms: u32,
        connected_since_unix: u64,
        mode: TunnelMode,
    },
    Reconnecting {
        proxy_id: String,
        attempt: u32,
        last_error: String,
    },
    Disconnecting,
    Error {
        code: TunnelErrorCode,
        message: String,
    },
}

impl TunnelState {
    pub fn proxy_id(&self) -> Option<&str> {
        match self {
            TunnelState::ConfiguringRoutes { proxy_id }
            | TunnelState::VerifyingExitNode { proxy_id }
            | TunnelState::Connected { proxy_id, .. }
            | TunnelState::Reconnecting { proxy_id, .. } => Some(proxy_id),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self,
            TunnelState::RequestingPrivileges
                | TunnelState::ConfiguringRoutes { .. }
                | TunnelState::VerifyingExitNode { .. }
                | TunnelState::Connected { .. }
                | TunnelState::Reconnecting { .. }
                | TunnelState::Disconnecting
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// Full Layer-3 Virtual Network Adapter (Wintun / utun / tun0 / Android VpnService)
    Layer3Tun,
    /// Unprivileged fallback: OS HTTP/SOCKS5 System Proxy settings only
    OsSystemProxyFallback,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelErrorCode {
    PrivilegeElevationDenied,
    VpnPermissionDeniedOnAndroid,
    /// Another full-tunnel VPN owns the system default route.
    ConflictingVpn,
    TunDeviceCreationFailed,
    RoutingConfigurationFailed,
    DnsConfigurationFailed,
    UpstreamProxyUnreachable,
    ExitVerificationFailed,
    QuotaExhausted,
    LeaseExpired,
    InternalError,
}

impl TunnelErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelErrorCode::PrivilegeElevationDenied => "privilege_elevation_denied",
            TunnelErrorCode::VpnPermissionDeniedOnAndroid => "vpn_permission_denied_on_android",
            TunnelErrorCode::ConflictingVpn => "conflicting_vpn",
            TunnelErrorCode::TunDeviceCreationFailed => "tun_device_creation_failed",
            TunnelErrorCode::RoutingConfigurationFailed => "routing_configuration_failed",
            TunnelErrorCode::DnsConfigurationFailed => "dns_configuration_failed",
            TunnelErrorCode::UpstreamProxyUnreachable => "upstream_proxy_unreachable",
            TunnelErrorCode::ExitVerificationFailed => "exit_verification_failed",
            TunnelErrorCode::QuotaExhausted => "quota_exhausted",
            TunnelErrorCode::LeaseExpired => "lease_expired",
            TunnelErrorCode::InternalError => "internal_error",
        }
    }
}

/// Configuration handed to the privileged tunnel daemon (desktop) or the
/// in-process Android engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub proxy_id: String,
    /// Local SOCKS5 bridge address (e.g., 127.0.0.1:10808) backed by libproxybase Yamux stream
    pub socks5_bridge_addr: SocketAddr,
    /// Remote ProxyBase Relay IP that MUST bypass the TUN adapter
    pub upstream_relay_ip: IpAddr,
    pub socks5_username: Option<String>,
    pub socks5_password: Option<String>,
    /// Virtual TUN IPv4 address (Default: 10.255.0.2)
    pub tun_ipv4: Ipv4Addr,
    /// Virtual TUN IPv4 Gateway & internal Fake-DNS listener (Default: 10.255.0.1)
    pub tun_gateway_ipv4: Ipv4Addr,
    /// Virtual TUN Prefix Length (Default: 30)
    pub tun_prefix: u8,
    /// TUN MTU (Default: 1380 to safely accommodate Yamux + TLS framing overhead)
    pub mtu: u16,
    /// Block all internet traffic if the upstream proxy drops unexpectedly
    pub kill_switch: bool,
    /// Reject UDP:443 with ICMP Port Unreachable to force instant HTTP/3 -> HTTP/2 fallback
    pub disable_quic_udp_443: bool,
    /// Block STUN UDP ports (3478, 19302, 5349) when upstream does not support UDP
    pub block_webrtc_stun: bool,
    /// User-defined CIDRs to exclude from tunneling (merged with mandatory RFC1918 LAN CIDRs)
    pub custom_bypass_cidrs: Vec<String>,
    /// Automatically tear down tunnel if the GUI process disconnects from IPC socket
    pub stop_on_gui_exit: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            proxy_id: String::new(),
            socks5_bridge_addr: SocketAddr::from(([127, 0, 0, 1], 10808)),
            upstream_relay_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            socks5_username: None,
            socks5_password: None,
            tun_ipv4: Ipv4Addr::new(10, 255, 0, 2),
            tun_gateway_ipv4: Ipv4Addr::new(10, 255, 0, 1),
            tun_prefix: 30,
            mtu: 1380,
            kill_switch: true,
            disable_quic_udp_443: true,
            block_webrtc_stun: true,
            custom_bypass_cidrs: Vec::new(),
            stop_on_gui_exit: true,
        }
    }
}

impl TunnelConfig {
    /// Validate without executing anything privileged. Never allow malformed
    /// CIDRs or an invalid virtual-network layout to reach a platform API.
    pub fn validate(&self) -> Result<(), String> {
        if self.proxy_id.trim().is_empty() {
            return Err("proxy_id is required".into());
        }
        if self.mtu < 1280 || self.mtu > 9000 {
            return Err(format!("invalid MTU {} (must be 1280..=9000)", self.mtu));
        }
        if self.tun_prefix > 30 {
            return Err(format!(
                "invalid TUN prefix {} (must be <= 30 so both the TUN and gateway fit)",
                self.tun_prefix
            ));
        }
        // The gateway must be usable as the DNS listener and the TUN address
        // must not equal it.
        if self.tun_ipv4 == self.tun_gateway_ipv4 {
            return Err("tun_ipv4 and tun_gateway_ipv4 must differ".into());
        }
        if !self.tun_ipv4.is_private() || !self.tun_gateway_ipv4.is_private() {
            return Err("the virtual TUN addresses must be in a private range".into());
        }
        // The relay must not live inside the virtual network or the Fake-IP
        // pool: either would make its host route shadow the tunnel adapter.
        let tun_net: ipnet::IpNet = format!("{}/{}", self.tun_ipv4, self.tun_prefix)
            .parse()
            .expect("validated TUN network");
        if tun_net.contains(&self.upstream_relay_ip) {
            return Err("upstream_relay_ip must not be inside the TUN subnet".into());
        }
        if let IpAddr::V4(relay) = self.upstream_relay_ip {
            let o = relay.octets();
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return Err("upstream_relay_ip must not be in the Fake-IP range".into());
            }
        }
        for cidr in &self.custom_bypass_cidrs {
            let net: ipnet::IpNet = cidr
                .parse()
                .map_err(|e| format!("invalid bypass CIDR {cidr:?}: {e}"))?;
            // Refuse to bypass the whole IPv4 or IPv6 internet — that would
            // silently disable the tunnel.
            if net.prefix_len() == 0 {
                return Err(format!("refusing to bypass the entire address family: {cidr}"));
            }
        }
        Ok(())
    }

    /// Mandatory non-routable / local subnets from the specification.
    ///
    /// `10.255.0.0/30` is intentionally omitted from the bypass list: the TUN
    /// interface itself owns that prefix and the route manager installs it as a
    /// more specific TUN route (longest-prefix match wins).
    pub fn mandatory_bypass_nets() -> Vec<ipnet::IpNet> {
        const CIDRS: &[&str] = &[
            "127.0.0.0/8",
            "::1/128",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "fe80::/10",
            "224.0.0.0/4",
            "ff00::/8",
            "255.255.255.255/32",
        ];
        CIDRS
            .iter()
            .map(|c| c.parse().expect("static CIDR is valid"))
            .collect()
    }

    /// All bypass networks: mandatory set plus validated user CIDRs.
    pub fn bypass_nets(&self) -> Result<Vec<ipnet::IpNet>, String> {
        let mut nets = Self::mandatory_bypass_nets();
        for cidr in &self.custom_bypass_cidrs {
            let net: ipnet::IpNet = cidr
                .parse()
                .map_err(|e| format!("invalid bypass CIDR {cidr:?}: {e}"))?;
            // Accept host bits in user input but route the canonical network
            // (Linux `ip` rejects e.g. 192.168.50.5/24 outright).
            nets.push(net.trunc());
        }
        nets.sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        nets.dedup();
        Ok(nets)
    }
}

/// IPC Framing between `proxybase-gui` and `proxybase-tunneld` (Length-prefixed JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum TunnelIpcRequest {
    Ping,
    GetState,
    StartTunnel { config: TunnelConfig },
    HotSwapProxy { config: TunnelConfig },
    StopTunnel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunnelIpcResponse {
    Pong { version: String },
    State { state: TunnelState },
    Telemetry {
        rx_bytes_total: u64,
        tx_bytes_total: u64,
        rx_bps: u64,
        tx_bps: u64,
        active_flows: u32,
    },
    Error { code: TunnelErrorCode, message: String },
}

impl TunnelIpcResponse {
    pub fn error(code: TunnelErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Envelope used on the wire. The spec's request/response enums are preserved
/// verbatim; the envelope adds a request ID so telemetry events can stream on
/// the same connection as request/response traffic without ambiguity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TunnelIpcEnvelope {
    Request {
        id: u64,
        request: TunnelIpcRequest,
    },
    Response {
        id: u64,
        response: TunnelIpcResponse,
    },
    /// Unsolicited server push (state changes, telemetry).
    Event { response: TunnelIpcResponse },
}

/// Maximum accepted IPC frame (protects the privileged daemon from memory
/// exhaustion by a misbehaving local peer).
pub const MAX_IPC_FRAME: usize = 1 << 20;

/// Desktop IPC socket path (Unix) and named pipe (Windows). Shared by the
/// daemon and the GUI client so the two can never drift.
#[cfg(unix)]
pub const TUNNELD_SOCKET_PATH: &str = "/var/run/proxybase-tunneld.sock";
#[cfg(windows)]
pub const TUNNELD_PIPE_NAME: &str = r"\\.\pipe\proxybase-tunneld";

/// Encode a length-prefixed frame: `u32` big-endian length followed by JSON.
pub fn encode_ipc_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(value)?;
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_wire_tags_match_the_frontend_contract() {
        let states = [
            TunnelState::Disconnected,
            TunnelState::RequestingPrivileges,
            TunnelState::ConfiguringRoutes {
                proxy_id: "s".into(),
            },
            TunnelState::VerifyingExitNode {
                proxy_id: "s".into(),
            },
            TunnelState::Connected {
                proxy_id: "s".into(),
                exit_ip: "203.0.113.7".into(),
                country_code: Some("US".into()),
                isp: None,
                latency_ms: 12,
                connected_since_unix: 1,
                mode: TunnelMode::Layer3Tun,
            },
            TunnelState::Reconnecting {
                proxy_id: "s".into(),
                attempt: 2,
                last_error: "x".into(),
            },
            TunnelState::Disconnecting,
            TunnelState::Error {
                code: TunnelErrorCode::QuotaExhausted,
                message: "m".into(),
            },
        ];
        for state in states {
            let json = serde_json::to_value(&state).unwrap();
            assert!(json.get("status").is_some(), "missing status tag: {json}");
            let back: TunnelState = serde_json::from_value(json).unwrap();
            assert_eq!(back, state);
        }
    }

    #[test]
    fn bypass_cidrs_are_canonicalized() {
        // Users may type host bits (192.168.50.5/24); Linux's `ip` rejects
        // such prefixes, so bypass_nets() must hand out the network address.
        let mut cfg = TunnelConfig::default();
        cfg.proxy_id = "session".into();
        cfg.custom_bypass_cidrs = vec!["192.168.50.5/24".into()];
        let nets = cfg.bypass_nets().unwrap();
        assert!(nets.contains(&"192.168.50.0/24".parse().unwrap()));
        assert!(!nets.contains(&"192.168.50.5/24".parse().unwrap()));
    }

    #[test]
    fn config_validation_rejects_malformed_input() {
        let mut cfg = TunnelConfig::default();
        cfg.proxy_id = "session".into();
        cfg.custom_bypass_cidrs = vec!["not-a-cidr".into()];
        assert!(cfg.validate().is_err());

        cfg.custom_bypass_cidrs = vec!["0.0.0.0/0".into()];
        assert!(cfg.validate().is_err());

        cfg.custom_bypass_cidrs = vec!["192.168.50.0/24".into()];
        assert!(cfg.validate().is_ok());

        cfg.mtu = 1000;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ipc_envelope_roundtrips_with_length_prefix() {
        let envelope = TunnelIpcEnvelope::Request {
            id: 7,
            request: TunnelIpcRequest::HotSwapProxy {
                config: TunnelConfig::default(),
            },
        };
        let frame = encode_ipc_frame(&envelope).unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let decoded: TunnelIpcEnvelope = serde_json::from_slice(&frame[4..]).unwrap();
        assert!(matches!(
            decoded,
            TunnelIpcEnvelope::Request { id: 7, .. }
        ));
    }
}
