//! Per-platform route and DNS managers.
//!
//! Every mutation goes through argument-array process invocations or typed
//! Win32 APIs. No unvalidated string ever reaches a shell.

use crate::tunnel::config::TunnelConfig;
use crate::tunnel::journal::RollbackJournal;
use crate::tunnel::socket_bypass::PhysicalInterfaceInfo;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A normalized IPv4/IPv6 route, before it is handed to a platform API.
///
/// Windows is strict where macOS/Linux are forgiving: `CreateIpForwardEntry2`
/// rejects destination prefixes with non-zero host bits (e.g. `10.255.0.2/30`
/// instead of `10.255.0.0/30`) and next hops from the wrong address family
/// with `ERROR_INVALID_PARAMETER` (87). Normalizing every route in one place
/// keeps all callers honest and makes the rules testable off-Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the Windows manager and platform tests
pub(crate) struct RouteSpec {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub next_hop: IpAddr,
    pub metric: u32,
}

impl RouteSpec {
    pub(crate) fn new(
        destination: IpAddr,
        prefix_len: u8,
        next_hop: Option<IpAddr>,
        metric: u32,
    ) -> anyhow::Result<Self> {
        let net = ipnet::IpNet::new(destination, prefix_len)
            .map_err(|e| anyhow::anyhow!("invalid route {destination}/{prefix_len}: {e}"))?;
        // Canonical network address: Windows rejects host bits outside the
        // prefix with ERROR_INVALID_PARAMETER.
        let destination = net.trunc().addr();
        let next_hop = next_hop.unwrap_or_else(|| unspecified_like(destination));
        if destination.is_ipv4() != next_hop.is_ipv4() {
            anyhow::bail!(
                "route {destination}/{prefix_len} cannot use an IPv{} next hop ({next_hop})",
                if destination.is_ipv4() { 4 } else { 6 }
            );
        }
        Ok(Self {
            destination,
            prefix_len,
            next_hop,
            metric,
        })
    }
}

#[allow(dead_code)] // only used on Windows and in platform tests
pub(crate) fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "android")]
pub mod android;

/// Route + DNS configuration for the host OS.
#[async_trait]
pub trait PlatformRouteManager: Send + Sync {
    async fn detect_physical_route(&self) -> anyhow::Result<PhysicalInterfaceInfo>;
    async fn apply_routes(
        &self,
        tun_name: &str,
        phys: &PhysicalInterfaceInfo,
        cfg: &TunnelConfig,
    ) -> anyhow::Result<()>;
    async fn apply_dns(&self, tun_name: &str, dns_ip: Ipv4Addr) -> anyhow::Result<()>;
    async fn restore_all(&self, journal: &RollbackJournal) -> anyhow::Result<()>;

    /// Capture original DNS configuration into the journal *before* any
    /// mutation. Default: nothing to capture.
    async fn snapshot_dns(
        &self,
        _phys: &PhysicalInterfaceInfo,
        _journal: &mut RollbackJournal,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Re-point the upstream relay's host route after a physical network
    /// change. Implementations must use a replace/change operation (not a
    /// delete-then-add) so there is no window in which relay traffic can fall
    /// into the TUN device.
    async fn repin_relay_route(
        &self,
        _relay: std::net::IpAddr,
        _phys: &PhysicalInterfaceInfo,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Re-assert DNS interception and any per-interface DNS leak guards
    /// (notably Windows WFP filters) after a physical network change.
    async fn refresh_dns_guard(
        &self,
        tun_name: &str,
        dns_ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        self.apply_dns(tun_name, dns_ip).await
    }

    /// Remove a stale relay host route after a hot swap.
    async fn remove_relay_route(
        &self,
        _relay: std::net::IpAddr,
        _phys: &PhysicalInterfaceInfo,
    ) {
    }

    fn platform_name(&self) -> &'static str;
}

/// Manager for the running platform.
pub fn current() -> Box<dyn PlatformRouteManager> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsRouteManager::default())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxRouteManager::default())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsRouteManager::default())
    }
    #[cfg(target_os = "android")]
    {
        Box::new(android::AndroidRouteManager)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_os = "android"
    )))]
    {
        Box::new(UnsupportedRouteManager)
    }
}

/// Fallback for unsupported Unix targets.
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "android"
)))]
pub struct UnsupportedRouteManager;

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "android"
)))]
#[async_trait]
impl PlatformRouteManager for UnsupportedRouteManager {
    async fn detect_physical_route(&self) -> anyhow::Result<PhysicalInterfaceInfo> {
        anyhow::bail!("system tunnel is not supported on this platform")
    }
    async fn apply_routes(
        &self,
        _tun_name: &str,
        _phys: &PhysicalInterfaceInfo,
        _cfg: &TunnelConfig,
    ) -> anyhow::Result<()> {
        anyhow::bail!("system tunnel is not supported on this platform")
    }
    async fn apply_dns(&self, _tun_name: &str, _dns_ip: Ipv4Addr) -> anyhow::Result<()> {
        anyhow::bail!("system tunnel is not supported on this platform")
    }
    async fn restore_all(&self, _journal: &RollbackJournal) -> anyhow::Result<()> {
        Ok(())
    }
    fn platform_name(&self) -> &'static str {
        "unsupported"
    }
}

/// Flush the OS DNS cache. Called on both connect and disconnect so stale
/// fake-IP answers cannot outlive the tunnel.
pub async fn flush_dns_cache() {
    #[cfg(target_os = "macos")]
    {
        let _ = run_command("/usr/bin/dscacheutil", &["-flushcache"]).await;
        let _ = run_command("/usr/bin/killall", &["-HUP", "mDNSResponder"]).await;
    }
    #[cfg(target_os = "linux")]
    {
        // systemd-resolved is the common case; fall back to nscd and then to
        // doing nothing (there is no universal Linux DNS cache).
        if let Ok(out) = tokio::process::Command::new("resolvectl")
            .arg("flush-caches")
            .output()
            .await
        {
            if out.status.success() {
                return;
            }
        }
        let _ = tokio::process::Command::new("nscd")
            .args(["-i", "hosts"])
            .output()
            .await;
    }
    #[cfg(target_os = "windows")]
    {
        windows::flush_dns_cache();
    }
    #[cfg(target_os = "android")]
    {
        // Android's netd flushes on VPN changes; nothing else is available to
        // an unprivileged app.
    }
}

/// Run a command with a hard timeout, returning stdout on success.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) async fn run_command(program: &str, args: &[&str]) -> anyhow::Result<String> {
    use std::process::Stdio;
    use tokio::process::Command;

    let fut = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .map_err(|_| anyhow::anyhow!("{program} timed out"))??;
    if !output.status.success() {
        anyhow::bail!(
            "{} {:?} failed: {}",
            program,
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Like [`run_command`] but tolerates a non-zero exit (used for route deletes
/// and idempotent additions).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) async fn run_command_tolerant(program: &str, args: &[&str]) {
    use std::process::Stdio;
    use tokio::process::Command;
    let fut = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match tokio::time::timeout(std::time::Duration::from_secs(10), fut).await {
        Ok(Ok(status)) if !status.success() => {
            tracing::debug!(program, ?args, "command exited non-zero (tolerated)");
        }
        Ok(Err(e)) => tracing::debug!(program, error = %e, "command failed (tolerated)"),
        Err(_) => tracing::debug!(program, "command timed out (tolerated)"),
        _ => {}
    }
}

/// Parse `a.b.c.d` or `::1` from a route command's output line.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn parse_ip_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let rest = line.split_once(marker)?.1.trim();
    Some(rest.split_whitespace().next()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn route_spec_truncates_host_bits() {
        // This exact route (the TUN address with a /30 prefix) used to be sent
        // to CreateIpForwardEntry2 verbatim and was rejected with error 87.
        let spec = RouteSpec::new(v4("10.255.0.2"), 30, None, 1).unwrap();
        assert_eq!(spec.destination, v4("10.255.0.0"));
        assert_eq!(spec.next_hop, v4("0.0.0.0"));
        assert_eq!(spec.prefix_len, 30);

        let spec = RouteSpec::new(v4("128.0.0.1"), 1, None, 1).unwrap();
        assert_eq!(spec.destination, v4("128.0.0.0"));
    }

    #[test]
    fn route_spec_allows_default_next_hop_for_both_families() {
        let spec4 = RouteSpec::new(v4("0.0.0.0"), 1, None, 1).unwrap();
        assert_eq!(spec4.next_hop, v4("0.0.0.0"));

        let spec6 = RouteSpec::new(v6("fd00:255::"), 64, None, 1).unwrap();
        assert_eq!(spec6.next_hop, v6("::"));
    }

    #[test]
    fn route_spec_rejects_family_mismatch() {
        // An IPv6 relay host must never be pinned through an IPv4 gateway:
        // CreateIpForwardEntry2 rejects that row with error 87.
        assert!(RouteSpec::new(v6("2001:db8::1"), 128, Some(v4("192.168.1.1")), 1).is_err());
        assert!(RouteSpec::new(v4("203.0.113.7"), 32, Some(v6("fe80::1")), 1).is_err());
    }

    #[test]
    fn route_spec_rejects_invalid_prefix_length() {
        assert!(RouteSpec::new(v4("10.0.0.0"), 33, None, 1).is_err());
        assert!(RouteSpec::new(v6("fd00::"), 129, None, 1).is_err());
    }
}
