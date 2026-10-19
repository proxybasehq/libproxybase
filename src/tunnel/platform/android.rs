//! Android platform glue.
//!
//! Android forbids shell route management and sidecar daemons. Routes, DNS
//! and the TUN device are configured by `android.net.VpnService.Builder` in
//! Kotlin, then the detached file descriptor is handed to the same Rust packet
//! engine used on desktop. This module therefore only exposes the fd adoption
//! helper and a no-op route manager (VpnService owns routes).

use crate::tunnel::config::TunnelConfig;
use crate::tunnel::journal::RollbackJournal;
use crate::tunnel::socket_bypass::PhysicalInterfaceInfo;
use anyhow::anyhow;
use async_trait::async_trait;
use std::net::Ipv4Addr;

pub struct AndroidRouteManager;

#[async_trait]
impl super::PlatformRouteManager for AndroidRouteManager {
    async fn detect_physical_route(&self) -> anyhow::Result<PhysicalInterfaceInfo> {
        Err(anyhow!(
            "Android routing is owned by VpnService.Builder; use start_with_device"
        ))
    }

    async fn apply_routes(
        &self,
        _tun_name: &str,
        _phys: &PhysicalInterfaceInfo,
        _cfg: &TunnelConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_dns(&self, _tun_name: &str, _dns_ip: Ipv4Addr) -> anyhow::Result<()> {
        Ok(())
    }

    async fn restore_all(&self, _journal: &RollbackJournal) -> anyhow::Result<()> {
        Ok(())
    }

    fn platform_name(&self) -> &'static str {
        "android"
    }
}

/// Adopt the `ParcelFileDescriptor.detachFd()` raw descriptor. The caller (the
/// Kotlin VpnService) must have detached it, transferring ownership to Rust.
///
/// # Safety
/// `fd` must be a valid, open TUN file descriptor owned by the caller.
pub unsafe fn adopt_tun_fd(fd: std::os::fd::RawFd) -> std::io::Result<tun_rs::AsyncDevice> {
    unsafe { tun_rs::AsyncDevice::from_fd(fd) }
}
