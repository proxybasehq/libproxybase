//! Linux route + DNS management.
//!
//! Routes are managed through `ip` with argument arrays (never a shell).
//! DNS uses `systemd-resolved` when present (the normal case on Ubuntu,
//! Fedora, Arch and Debian) and otherwise atomically rewrites
//! `/etc/resolv.conf` after backing it up.

use super::{flush_dns_cache, run_command, run_command_tolerant};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::journal::RollbackJournal;
use crate::tunnel::socket_bypass::PhysicalInterfaceInfo;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

/// Dedicated policy-routing table for `SO_MARK`-tagged sockets. The main
/// table contains the TUN /1 routes, so marked sockets must not use it.
pub const POLICY_TABLE: u32 = 51821;
pub const SOCKET_MARK: u32 = 0x5042;
pub const RESOLV_BACKUP: &str = "/var/run/proxybase-resolv.conf.bak";
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

#[derive(Default)]
pub struct LinuxRouteManager;

#[async_trait]
impl super::PlatformRouteManager for LinuxRouteManager {
    async fn detect_physical_route(&self) -> anyhow::Result<PhysicalInterfaceInfo> {
        // IPv4 first, then IPv6-only networks.
        if let Some(info) = detect_default(&["route", "show", "default"], false).await? {
            return Ok(info);
        }
        if let Some(info) = detect_default(&["-6", "route", "show", "default"], true).await? {
            return Ok(info);
        }
        Err(anyhow!("no default route found via iproute2"))
    }

    async fn apply_routes(
        &self,
        tun_name: &str,
        phys: &PhysicalInterfaceInfo,
        cfg: &TunnelConfig,
    ) -> anyhow::Result<()> {
        // 1. Relay host route via the physical gateway/interface. Loopback
        //    relays never use the default route and must not be pinned.
        if !cfg.upstream_relay_ip.is_loopback() {
        match cfg.upstream_relay_ip {
            IpAddr::V4(ip) => {
                let prefix = format!("{ip}/32");
                if phys.gateway_ip.is_unspecified() {
                    ip_checked(&["route", "replace", &prefix, "dev", &phys.name]).await?;
                } else {
                    ip_checked(&[
                        "route",
                        "replace",
                        &prefix,
                        "via",
                        &phys.gateway_ip.to_string(),
                        "dev",
                        &phys.name,
                    ])
                    .await?;
                }
            }
            IpAddr::V6(ip) => {
                let prefix = format!("{ip}/128");
                if let IpAddr::V6(gw) = phys.gateway_ip {
                    if gw.is_unspecified() {
                        ip_checked(&["-6", "route", "replace", &prefix, "dev", &phys.name]).await?;
                    } else {
                        ip_checked(&[
                            "-6",
                            "route",
                            "replace",
                            &prefix,
                            "via",
                            &gw.to_string(),
                            "dev",
                            &phys.name,
                        ])
                        .await?;
                    }
                } else {
                    ip_checked(&["-6", "route", "replace", &prefix, "dev", &phys.name]).await?;
                }
            }
        }
        }

        // 2. Bypass routes pinned to the physical interface.
        for net in cfg.bypass_nets().map_err(anyhow::Error::msg)? {
            // Never create a physical route for loopback or multicast.
            if net.addr().is_loopback() || net.addr().is_multicast() {
                continue;
            }
            add_net(&net.to_string(), &phys.name).await;
        }

        // 3. TUN subnet and sub-default halves. These must succeed: a
        //    silently missing /1 route leaves traffic untunneled.
        add_net_checked(&format!("{}/{}", cfg.tun_ipv4, cfg.tun_prefix), tun_name).await?;
        add_net_checked("fd00:255::/64", tun_name).await?;
        for net in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
            add_net_checked(net, tun_name).await?;
        }

        // 4. Policy routing for SO_MARK-tagged sockets. This table contains
        //    only the physical default route, so marked relay sockets can
        //    never be captured by the /1 routes in the main table.
        if let IpAddr::V4(gw) = phys.gateway_ip {
            ip_tolerant(&[
                "route",
                "replace",
                "table",
                &POLICY_TABLE.to_string(),
                "default",
                "via",
                &gw.to_string(),
                "dev",
                &phys.name,
            ])
            .await;
            ip_tolerant(&[
                "rule",
                "add",
                "fwmark",
                &format!("{SOCKET_MARK:#x}/0xffffffff"),
                "lookup",
                &POLICY_TABLE.to_string(),
                "priority",
                "100",
            ])
            .await;
        }
        Ok(())
    }

    async fn apply_dns(&self, tun_name: &str, dns_ip: Ipv4Addr) -> anyhow::Result<()> {
        if systemd_resolved_active().await {
            let dns = dns_ip.to_string();
            run_command("resolvectl", &["dns", tun_name, &dns])
                .await
                .context("resolvectl dns failed")?;
            run_command("resolvectl", &["domain", tun_name, "~."])
                .await
                .context("resolvectl domain failed")?;
            run_command("resolvectl", &["default-route", tun_name, "yes"])
                .await
                .context("resolvectl default-route failed")?;
            flush_dns_cache().await;
            return Ok(());
        }

        // Fallback: back up and atomically replace /etc/resolv.conf.
        let original = tokio::fs::read(RESOLV_CONF).await.unwrap_or_default();
        let backup_dir = Path::new(RESOLV_BACKUP).parent().unwrap_or(Path::new("/var/run"));
        tokio::fs::create_dir_all(backup_dir).await.ok();
        tokio::fs::write(RESOLV_BACKUP, &original)
            .await
            .context("failed to back up /etc/resolv.conf")?;
        write_resolv_conf(&format!("nameserver {dns_ip}\noptions edns0 trust-ad\n"))
            .await
            .context("failed to write /etc/resolv.conf")?;
        flush_dns_cache().await;
        Ok(())
    }

    async fn restore_all(&self, journal: &RollbackJournal) -> anyhow::Result<()> {
        // DNS first: get the resolver working again before routes disappear.
        if journal.dns_mode.as_deref() == Some("systemd-resolved") {
            run_command_tolerant("resolvectl", &["revert", &journal.tun_interface]).await;
            flush_dns_cache().await;
        } else if tokio::fs::metadata(RESOLV_BACKUP).await.is_ok() {
            match tokio::fs::read(RESOLV_BACKUP).await {
                Ok(original) => {
                    if let Err(e) = write_resolv_conf_raw(&original).await {
                        tracing::warn!(error = %e, "failed to restore /etc/resolv.conf");
                    } else {
                        let _ = tokio::fs::remove_file(RESOLV_BACKUP).await;
                    }
                }
                Err(e) => tracing::warn!(error = %e, "failed to read resolv.conf backup"),
            }
            flush_dns_cache().await;
        }

        // Remove the policy rule and table.
        ip_tolerant(&[
            "rule",
            "del",
            "fwmark",
            &format!("{SOCKET_MARK:#x}/0xffffffff"),
            "lookup",
            &POLICY_TABLE.to_string(),
            "priority",
            "100",
        ])
        .await;
        ip_tolerant(&["route", "flush", "table", &POLICY_TABLE.to_string()]).await;

        // Remove the relay host route.
        if let Ok(relay) = journal.upstream_relay_ip.parse::<IpAddr>() {
            let (family, prefix) = match relay {
                IpAddr::V4(_) => (None, format!("{relay}/32")),
                IpAddr::V6(_) => (Some("-6"), format!("{relay}/128")),
            };
            let mut args: Vec<&str> = Vec::new();
            if let Some(f) = family {
                args.push(f);
            }
            args.extend_from_slice(&["route", "del", &prefix]);
            ip_tolerant(&args).await;
        }

        // Remove exactly the routes recorded in the journal.
        for cidr in &journal.routes_added {
            let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
                continue;
            };
            let cidr = net.to_string();
            let args: Vec<&str> = if net.addr().is_ipv6() {
                vec!["-6", "route", "del", &cidr]
            } else {
                vec!["route", "del", &cidr]
            };
            ip_tolerant(&args).await;
        }
        Ok(())
    }

    async fn snapshot_dns(
        &self,
        _phys: &PhysicalInterfaceInfo,
        journal: &mut RollbackJournal,
    ) -> anyhow::Result<()> {
        if systemd_resolved_active().await {
            journal.dns_mode = Some("systemd-resolved".into());
            if let Ok(out) = run_command("resolvectl", &["dns"]).await {
                let mut servers = Vec::new();
                for token in out.split_whitespace() {
                    if token.parse::<IpAddr>().is_ok() && !servers.contains(&token.to_string()) {
                        servers.push(token.to_string());
                    }
                }
                journal.original_dns_servers = servers;
            }
        } else {
            journal.dns_mode = Some("resolv.conf".into());
            journal.linux_resolv_backup_path = Some(RESOLV_BACKUP.into());
            journal.original_dns_servers = read_resolv_servers().await;
        }
        Ok(())
    }

    async fn repin_relay_route(
        &self,
        relay: IpAddr,
        phys: &PhysicalInterfaceInfo,
    ) -> anyhow::Result<()> {
        if relay.is_loopback() {
            return Ok(());
        }
        match relay {
            IpAddr::V4(ip) => {
                let prefix = format!("{ip}/32");
                let gw = phys.gateway_ip.to_string();
                let args = [
                    "route", "replace", &prefix, "via", &gw, "dev", &phys.name,
                ];
                if let Err(e) = run_command("ip", &args).await {
                    anyhow::bail!("ip route replace failed: {e}");
                }
            }
            IpAddr::V6(ip) => {
                let prefix = format!("{ip}/128");
                let owned: Vec<String> = if let IpAddr::V6(gw) = phys.gateway_ip {
                    vec![
                        "-6".into(),
                        "route".into(),
                        "replace".into(),
                        prefix,
                        "via".into(),
                        gw.to_string(),
                        "dev".into(),
                        phys.name.clone(),
                    ]
                } else {
                    vec![
                        "-6".into(),
                        "route".into(),
                        "replace".into(),
                        prefix,
                        "dev".into(),
                        phys.name.clone(),
                    ]
                };
                let args: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
                if let Err(e) = run_command("ip", &args).await {
                    anyhow::bail!("ip -6 route replace failed: {e}");
                }
            }
        }
        Ok(())
    }

    async fn remove_relay_route(&self, relay: IpAddr, _phys: &PhysicalInterfaceInfo) {
        if relay.is_loopback() {
            return;
        }
        match relay {
            IpAddr::V4(ip) => {
                ip_tolerant(&["route", "del", &format!("{ip}/32")]).await;
            }
            IpAddr::V6(ip) => {
                ip_tolerant(&["-6", "route", "del", &format!("{ip}/128")]).await;
            }
        }
    }

    fn platform_name(&self) -> &'static str {
        "linux"
    }
}

async fn detect_default(args: &[&str], ipv6: bool) -> anyhow::Result<Option<PhysicalInterfaceInfo>> {
    let out = match run_command("ip", args).await {
        Ok(out) => out,
        Err(_) => return Ok(None),
    };
    let mut best: Option<(u32, PhysicalInterfaceInfo)> = None;
    for line in out.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if !line.starts_with("default") {
            continue;
        }
        let mut gateway: Option<IpAddr> = None;
        let mut dev: Option<&str> = None;
        let mut metric: u32 = 0;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "via" if i + 1 < tokens.len() => {
                    gateway = tokens[i + 1].parse().ok();
                    i += 2;
                }
                "dev" if i + 1 < tokens.len() => {
                    dev = Some(tokens[i + 1]);
                    i += 2;
                }
                "metric" if i + 1 < tokens.len() => {
                    metric = tokens[i + 1].parse().unwrap_or(0);
                    i += 2;
                }
                _ => i += 1,
            }
        }
        let Some(dev) = dev else { continue };
        let gateway_ip = gateway.unwrap_or_else(|| {
            if ipv6 {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        });
        let index = if_nametoindex(dev).unwrap_or(0);
        let info = PhysicalInterfaceInfo {
            name: dev.to_string(),
            index,
            gateway_ip,
        };
        if best.as_ref().map(|(m, _)| metric < *m).unwrap_or(true) {
            best = Some((metric, info));
        }
    }
    Ok(best.map(|(_, info)| info))
}

async fn add_net(cidr: &str, dev: &str) {
    let args: Vec<&str> = if cidr.contains(':') {
        vec!["-6", "route", "replace", cidr, "dev", dev]
    } else {
        vec!["route", "replace", cidr, "dev", dev]
    };
    ip_tolerant(&args).await;
}

async fn add_net_checked(cidr: &str, dev: &str) -> anyhow::Result<()> {
    let args: Vec<&str> = if cidr.contains(':') {
        vec!["-6", "route", "replace", cidr, "dev", dev]
    } else {
        vec!["route", "replace", cidr, "dev", dev]
    };
    ip_checked(&args).await
}

/// Route operations that are required for tunnel correctness. Only the
/// idempotent "File exists" result is treated as success.
async fn ip_checked(args: &[&str]) -> anyhow::Result<()> {
    match run_command("ip", args).await {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("File exists") => Ok(()),
        Err(e) => Err(e),
    }
}

async fn ip_tolerant(args: &[&str]) {
    // `ip` reports "RTNETLINK answers: File exists" for idempotent re-adds.
    // All callers are applying our own deterministic route set, so treating
    // that as success is correct; genuine failures are logged.
    match run_command("ip", args).await {
        Ok(_) => {}
        Err(e) => {
            let text = e.to_string();
            if text.contains("File exists") || text.contains("No such process") {
                tracing::debug!(?args, "ip: already in desired state");
            } else {
                tracing::warn!(?args, error = %text, "ip command failed");
            }
        }
    }
}

async fn systemd_resolved_active() -> bool {
    if Path::new("/run/systemd/resolve/stub-resolv.conf").exists() {
        return true;
    }
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            Command::new("resolvectl")
                .arg("status")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        )
        .await,
        Ok(Ok(status)) if status.success()
    )
}

async fn read_resolv_servers() -> Vec<String> {
    let Ok(content) = tokio::fs::read_to_string(RESOLV_CONF).await else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("nameserver")?;
            let server = rest.trim().split_whitespace().next()?;
            server.parse::<IpAddr>().ok().map(|_| server.to_string())
        })
        .collect()
}

async fn write_resolv_conf(content: &str) -> std::io::Result<()> {
    write_resolv_conf_raw(content.as_bytes()).await
}

async fn write_resolv_conf_raw(content: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let tmp = format!("/etc/.proxybase-resolv.{}", std::process::id());
    {
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(content).await?;
        file.sync_all().await?;
    }
    tokio::fs::rename(&tmp, RESOLV_CONF).await?;
    if let Ok(dir) = std::fs::File::open("/etc") {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(unix)]
fn if_nametoindex(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}
