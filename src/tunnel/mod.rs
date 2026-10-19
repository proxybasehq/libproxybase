//! One-click system-wide proxy tunnel (VPN mode).
//!
//! The public entry point is [`SystemTunnelEngine`]. Platform route managers
//! implement the privileged bits; the packet engine is shared between desktop
//! (TUN created by `tun-rs`) and Android (TUN adopted from `VpnService`).

pub mod config;
pub mod engine;
pub mod fake_dns;
pub mod health;
pub mod journal;
pub mod packet;
pub mod platform;
pub mod socks5;
pub mod socket_bypass;

pub use config::{
    TunnelConfig, TunnelErrorCode, TunnelIpcEnvelope, TunnelIpcRequest, TunnelIpcResponse,
    TunnelMode, TunnelState,
};
pub use engine::{SystemTunnelEngine, Telemetry, TunnelError};
pub use fake_dns::FakeDns;
pub use journal::RollbackJournal;
pub use socket_bypass::{
    global_android_protector, install_global_android_protector, AndroidSocketProtector,
    NoopSocketProtector, PhysicalInterfaceInfo, SocketBypass,
};
