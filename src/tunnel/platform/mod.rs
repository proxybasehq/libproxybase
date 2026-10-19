//! Per-platform route and DNS managers.
//!
//! Every mutation goes through argument-array process invocations or typed
//! Win32 APIs. No unvalidated string ever reaches a shell.

use crate::tunnel::config::TunnelConfig;
use crate::tunnel::journal::RollbackJournal;
use crate::tunnel::socket_bypass::PhysicalInterfaceInfo;
use async_trait::async_trait;
use std::net::Ipv4Addr;

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
