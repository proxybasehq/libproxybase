//! macOS route + DNS management.
//!
//! Routes are added with `/sbin/route` using argument arrays (never a shell).
//! DNS is written into the `SCDynamicStore` with `scutil` because
//! `networksetup -setdnsservers` targets one service and is silently reverted
//! by DHCP renewals on Ethernet/Thunderbolt/USB-tethering interfaces.

use super::{flush_dns_cache, parse_ip_after, run_command, run_command_tolerant};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::journal::RollbackJournal;
use crate::tunnel::socket_bypass::PhysicalInterfaceInfo;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use tokio::process::Command;

pub const PROXYBASE_DNS_SERVICE_KEY: &str = "State:/Network/Service/proxybase-tunnel/DNS";
pub const PROXYBASE_DNS_GLOBAL_KEY: &str = "State:/Network/Global/DNS";

#[derive(Default)]
pub struct MacOsRouteManager;

impl MacOsRouteManager {
    fn route_program() -> &'static str {
        "/sbin/route"
    }
}

#[async_trait]
impl super::PlatformRouteManager for MacOsRouteManager {
    async fn detect_physical_route(&self) -> anyhow::Result<PhysicalInterfaceInfo> {
        if let Some(info) = detect_default(false).await? {
            return Ok(info);
        }
        if let Some(info) = detect_default(true).await? {
            return Ok(info);
        }
        Err(anyhow!("no IPv4 or IPv6 default route found"))
    }

    async fn apply_routes(
        &self,
        tun_name: &str,
        phys: &PhysicalInterfaceInfo,
        cfg: &TunnelConfig,
    ) -> anyhow::Result<()> {
        // 1. Pin the relay host route to the physical gateway. This has a
        //    longer prefix than the /1 routes added below and therefore always
        //    wins. A loopback relay never leaves the machine and must not be
        //    pinned to a physical gateway.
        if !cfg.upstream_relay_ip.is_loopback() {
        match cfg.upstream_relay_ip {
            IpAddr::V4(ip) => {
                add_route(&["-n", "add", "-host", &ip.to_string(), &phys.gateway_ip.to_string()])
                    .await?;
            }
            IpAddr::V6(ip) => {
                let gw = match phys.gateway_ip {
                    IpAddr::V6(v6) if v6.is_unicast_link_local() => {
                        // Link-local gateways require an interface scope on
                        // macOS.
                        format!("{v6}%{}", phys.name)
                    }
                    IpAddr::V6(v6) => v6.to_string(),
                    _ => String::new(),
                };
                if gw.is_empty() {
                    add_route(&[
                        "-n", "add", "-inet6", "-host", &ip.to_string(), "-interface", &phys.name,
                    ])
                    .await?;
                } else {
                    add_route(&[
                        "-n", "add", "-inet6", "-host", &ip.to_string(), &gw,
                    ])
                    .await?;
                }
            }
        }
        }

        // 2. Private/local subnets pinned to the physical interface. The
        //    kernel's longest-prefix match keeps the TUN subnet below on the
        //    tunnel because it is more specific than 10.0.0.0/8.
        for net in cfg.bypass_nets().map_err(anyhow::Error::msg)? {
            // Loopback stays on lo0. Re-pointing 127/8 at the physical NIC
            // would break localhost services (and 127.0.0.2+ entirely).
            if net.addr().is_loopback() || net.addr().is_multicast() {
                continue;
            }
            // Bypass routes are best-effort: the kernel usually already has
            // more specific LAN routes, and failing the entire tunnel because
            // of an exotic prefix would be worse.
            if let Err(e) = add_net_route(&net, &phys.name).await {
                tracing::warn!(cidr = %net, error = %e, "could not install bypass route");
            }
        }

        // 3. The virtual TUN subnet itself, then the two sub-default halves.
        let tun_cidr = format!("{}/{}", cfg.tun_ipv4, cfg.tun_prefix);
        add_net_route(&tun_cidr.parse()?, tun_name).await?;
        add_net_route(&"fd00:255::/64".parse()?, tun_name).await?;
        for net in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
            add_net_route(&net.parse()?, tun_name).await?;
        }
        Ok(())
    }

    async fn apply_dns(&self, _tun_name: &str, dns_ip: Ipv4Addr) -> anyhow::Result<()> {
        let script = format!(
            "open\nd.init\nd.add ServerAddresses * {dns_ip}\nd.add SupplementalMatchDomains * \"\"\nset {PROXYBASE_DNS_SERVICE_KEY}\nset {PROXYBASE_DNS_GLOBAL_KEY}\nquit\n"
        );
        run_scutil(&script)
            .await
            .context("failed to install DNS overrides via scutil")?;
        flush_dns_cache().await;
        Ok(())
    }

    async fn restore_all(&self, journal: &RollbackJournal) -> anyhow::Result<()> {
        // SCDynamicStore is runtime state and does not survive a reboot. If
        // the journal is stale, the machine is on a different network now and
        // re-installing the previous network's resolvers would break DNS. Just
        // drop our keys and let configd repopulate from the current service.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let stale = now.saturating_sub(journal.created_at_unix) > 900;
        let script = if stale {
            format!("open\nremove {PROXYBASE_DNS_SERVICE_KEY}\nquit\n")
        } else {
            let servers: Vec<String> = journal
                .original_dns_servers
                .iter()
                .filter(|s| s.parse::<IpAddr>().is_ok())
                .cloned()
                .collect();
            let restore_servers = if servers.is_empty() {
                format!("remove {PROXYBASE_DNS_GLOBAL_KEY}\n")
            } else {
                format!(
                    "d.init\nd.add ServerAddresses * {}\nset {PROXYBASE_DNS_GLOBAL_KEY}\n",
                    servers.join(" ")
                )
            };
            format!(
                "open\nremove {PROXYBASE_DNS_SERVICE_KEY}\n{restore_servers}quit\n"
            )
        };
        if let Err(e) = run_scutil(&script).await {
            tracing::warn!(error = %e, "failed to restore scutil DNS state");
        }

        // Delete exactly the routes we recorded.
        if let Ok(relay) = journal.upstream_relay_ip.parse::<IpAddr>() {
            match relay {
                IpAddr::V4(ip) => {
                    run_command_tolerant(
                        Self::route_program(),
                        &["-n", "delete", "-host", &ip.to_string()],
                    )
                    .await;
                }
                IpAddr::V6(ip) => {
                    run_command_tolerant(
                        Self::route_program(),
                        &["-n", "delete", "-inet6", "-host", &ip.to_string()],
                    )
                    .await;
                }
            }
        }
        for cidr in &journal.routes_added {
            let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
                continue;
            };
            let cidr = net.to_string();
            let mut args = vec!["-n", "delete"];
            if net.addr().is_ipv6() {
                args.push("-inet6");
            }
            args.extend_from_slice(&["-net", &cidr]);
            run_command_tolerant(Self::route_program(), &args).await;
        }

        flush_dns_cache().await;
        Ok(())
    }

    async fn snapshot_dns(
        &self,
        _phys: &PhysicalInterfaceInfo,
        journal: &mut RollbackJournal,
    ) -> anyhow::Result<()> {
        journal.dns_mode = Some("scutil".into());
        if let Ok(out) = run_command("/usr/sbin/scutil", &["--dns"]).await {
            let mut servers: Vec<String> = Vec::new();
            for line in out.lines() {
                let line = line.trim();
                if let Some(pos) = line.find("nameserver[") {
                    if let Some((_, value)) = line[pos..].split_once(':') {
                        let value = value.trim().to_string();
                        if value.parse::<IpAddr>().is_ok() && !servers.contains(&value) {
                            servers.push(value);
                        }
                    }
                }
            }
            journal.original_dns_servers = servers;
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
                let gw = phys.gateway_ip.to_string();
                let ip = ip.to_string();
                if run_command(
                    Self::route_program(),
                    &["-n", "change", "-host", &ip, &gw],
                )
                .await
                .is_err()
                {
                    add_route(&["-n", "add", "-host", &ip, &gw]).await?;
                }
            }
            IpAddr::V6(ip) => {
                let ip = ip.to_string();
                let changed = if let IpAddr::V6(gw) = phys.gateway_ip {
                    let gw = if gw.is_unicast_link_local() {
                        format!("{gw}%{}", phys.name)
                    } else {
                        gw.to_string()
                    };
                    run_command(
                        Self::route_program(),
                        &["-n", "change", "-inet6", "-host", &ip, &gw],
                    )
                    .await
                    .is_ok()
                } else {
                    false
                };
                if !changed {
                    add_route(&[
                        "-n", "add", "-inet6", "-host", &ip, "-interface", &phys.name,
                    ])
                    .await?;
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
                run_command_tolerant(
                    Self::route_program(),
                    &["-n", "delete", "-host", &ip.to_string()],
                )
                .await;
            }
            IpAddr::V6(ip) => {
                run_command_tolerant(
                    Self::route_program(),
                    &["-n", "delete", "-inet6", "-host", &ip.to_string()],
                )
                .await;
            }
        }
    }

    fn platform_name(&self) -> &'static str {
        "macos"
    }
}

async fn detect_default(ipv6: bool) -> anyhow::Result<Option<PhysicalInterfaceInfo>> {
    let args: &[&str] = if ipv6 {
        &["-n", "get", "-inet6", "default"]
    } else {
        &["-n", "get", "default"]
    };
    let out = match run_command(MacOsRouteManager::route_program(), args).await {
        Ok(out) => out,
        Err(_) => return Ok(None),
    };
    let mut gateway: Option<IpAddr> = None;
    let mut interface: Option<String> = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(v) = parse_ip_after(line, "gateway:") {
            // Link-local IPv6 gateways are scoped (`fe80::1%en0`).
            let v = v.split('%').next().unwrap_or(v);
            gateway = v.parse().ok().or(gateway);
        } else if let Some(rest) = line.strip_prefix("interface:") {
            interface = Some(rest.trim().to_string());
        }
    }
    let Some(interface) = interface else {
        return Ok(None);
    };
    let Some(gateway) = gateway else {
        return Ok(None);
    };
    let index = if_nametoindex(&interface)?;
    Ok(Some(PhysicalInterfaceInfo {
        name: interface,
        index,
        gateway_ip: gateway,
    }))
}

async fn add_route(args: &[&str]) -> anyhow::Result<()> {
    match run_command(MacOsRouteManager::route_program(), args).await {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.to_string().contains("File exists") {
                // A stale route (possibly pointing at an old TUN or another
                // VPN) already owns this prefix. Change it to our target so a
                // conflicting /1 route cannot silently leak traffic.
                let mut change: Vec<String> =
                    args.iter().map(|s| (*s).to_string()).collect();
                if let Some(pos) = change.iter().position(|s| s == "add") {
                    change[pos] = "change".into();
                }
                let refs: Vec<&str> = change.iter().map(|s| s.as_str()).collect();
                run_command(MacOsRouteManager::route_program(), &refs).await?;
                return Ok(());
            }
            Err(e)
        }
    }
}

async fn add_net_route(net: &ipnet::IpNet, interface: &str) -> anyhow::Result<()> {
    let cidr = net.to_string();
    let args: Vec<&str> = if net.addr().is_ipv6() {
        vec!["-n", "add", "-inet6", "-net", &cidr, "-interface", interface]
    } else {
        vec!["-n", "add", "-net", &cidr, "-interface", interface]
    };
    add_route(&args).await
}

async fn run_scutil(script: &str) -> anyhow::Result<()> {
    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn scutil")?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("scutil stdin unavailable"))?
        .write_all(script.as_bytes())
        .await?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .map_err(|_| anyhow!("scutil timed out"))??;
    if !output.status.success() {
        anyhow::bail!(
            "scutil failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn if_nametoindex(name: &str) -> anyhow::Result<u32> {
    let c = std::ffi::CString::new(name).map_err(|_| anyhow!("interface name contains NUL"))?;
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if index == 0 {
        anyhow::bail!(
            "if_nametoindex({name}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(index)
}
