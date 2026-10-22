//! Windows route, DNS and DNS-leak management.
//!
//! Routes use the typed IP Helper API (`GetIpForwardTable2` /
//! `CreateIpForwardEntry2` / `SetIpForwardEntry2`). DNS is installed on the
//! Wintun interface with `SetInterfaceDnsSettings`. Because Windows sends DNS
//! queries in parallel across every adapter (Smart Multi-Homed Name
//! Resolution), a dynamic WFP session additionally blocks outbound UDP/TCP:53
//! on every physical interface; the kernel removes those filters automatically
//! if this process exits or crashes.

use super::{default_route_detail, unspecified_like, PlatformRouteManager, RouteSpec, VpnConflict};
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::journal::RollbackJournal;
use crate::tunnel::socket_bypass::PhysicalInterfaceInfo;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid,
    ConvertInterfaceLuidToIndex, ConvertInterfaceLuidToNameW, ConvertInterfaceNameToLuidW,
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetAdaptersAddresses,
    GetBestRoute2, GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, SetInterfaceDnsSettings, SetIpForwardEntry2,
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
    GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_PPP,
    IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FWPM_ACTION0,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWP_ACTION_BLOCK, FWP_CONDITION_VALUE0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_MATCH_NOT_EQUAL,
    FWP_UINT16, FWP_UINT64, FWP_UINT8, FWP_VALUE0,
};
use windows_sys::Win32::Networking::WinSock::{
    NlroManual, AF_INET, AF_INET6, AF_UNSPEC, IPPROTO_TCP, IPPROTO_UDP, MIB_IPPROTO_NETMGMT,
    SOCKADDR, SOCKADDR_IN, SOCKADDR_INET,
};

const RPC_C_AUTHN_WINNT: u32 = 10;

// A stable private GUID for our WFP sublayer: {9a6b1d20-4c51-4b7e-9d3d-5042c0de0001}
const PROXYBASE_SUBLAYER_GUID: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0x9a6b1d20_4c51_4b7e_9d3d_5042c0de0001);

pub struct WindowsRouteManager {
    wfp: Mutex<Option<WfpSession>>,
    /// LUID of the active Wintun adapter, remembered so WFP filters can be
    /// rebuilt when the physical network changes.
    tun_luid: Mutex<Option<u64>>,
}

impl Default for WindowsRouteManager {
    fn default() -> Self {
        Self {
            wfp: Mutex::new(None),
            tun_luid: Mutex::new(None),
        }
    }
}

struct WfpSession {
    engine: HANDLE,
}

// WFP engine handles are process-wide kernel handles; the daemon serialises
// access through the Mutex.
unsafe impl Send for WfpSession {}
unsafe impl Sync for WfpSession {}

impl Drop for WfpSession {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.engine);
        }
    }
}

#[async_trait]
impl PlatformRouteManager for WindowsRouteManager {
    async fn detect_physical_route(&self) -> anyhow::Result<PhysicalInterfaceInfo> {
        // When the tunnel is already up, its sub-default routes can win the
        // route lookup; never mistake our own TUN for the physical uplink.
        let own_tun = self.tun_luid.lock().ok().and_then(|guard| *guard);
        detect_default_route(own_tun)
    }

    async fn detect_conflicting_vpn(&self) -> anyhow::Result<Option<VpnConflict>> {
        let adapters = enumerate_vpn_adapters();
        if adapters.is_empty() {
            return Ok(None);
        }
        let own_tun = self.tun_luid.lock().ok().and_then(|guard| *guard);
        Ok(conflicting_vpn_from_routes(&adapters, own_tun))
    }

    async fn apply_routes(
        &self,
        tun_name: &str,
        phys: &PhysicalInterfaceInfo,
        cfg: &TunnelConfig,
    ) -> anyhow::Result<()> {
        let phys_luid = luid_from_name(&phys.name)?;
        let tun_luid = luid_from_name(tun_name)?;

        // Wintun registers the adapter asynchronously. Adding routes to an
        // interface the IP Helper provider has not published yet fails with
        // ERROR_INVALID_PARAMETER (87) or ERROR_NOT_FOUND (1168); give it a
        // bounded moment to settle instead of failing the whole tunnel.
        if !wait_for_interface(&tun_luid, Duration::from_secs(3)).await {
            tracing::warn!(
                interface = %tun_name,
                "TUN interface did not report as connected before route setup"
            );
        }

        // 1. Relay host route pinned off the tunnel. Ask Windows which route
        //    it would actually use for the relay instead of assuming the
        //    default gateway: this keeps the interface, address family and
        //    next hop consistent on multi-homed hosts, VPNs, and IPv6 relays.
        //    Loopback relays stay on the machine and are never routed.
        if !cfg.upstream_relay_ip.is_loopback() {
            let relay = cfg.upstream_relay_ip;
            let prefix_len = if relay.is_ipv4() { 32 } else { 128 };
            let best = best_route_for(relay)
                .filter(|route| luid_value(&route.luid) != luid_value(&tun_luid));
            let (relay_luid, relay_next_hop) = match best {
                Some(route) => (route.luid, route.next_hop),
                None => {
                    // Fall back to the detected default route, but only if the
                    // address families agree (an IPv4 gateway can never route
                    // an IPv6 relay; Windows answers that with error 87).
                    let next = if phys.gateway_ip.is_ipv4() == relay.is_ipv4() {
                        phys.gateway_ip
                    } else {
                        unspecified_like(relay)
                    };
                    (phys_luid, next)
                }
            };
            add_or_replace_route(
                &relay_luid,
                relay,
                prefix_len,
                if relay_next_hop.is_unspecified() {
                    None
                } else {
                    Some(relay_next_hop)
                },
                1,
            )
            .await
            .context("failed to pin the upstream relay route off the tunnel")?;
            tracing::info!(
                relay = %relay,
                interface = %interface_label(&relay_luid),
                next_hop = %relay_next_hop,
                "pinned upstream relay route"
            );
        }

        // 2. Bypass routes. Loopback, broadcast and multicast are deliberately
        //    not re-added on Windows: the OS already has more-specific routes
        //    for them, and re-pointing 127/8 at the NIC would break localhost.
        for net in cfg.bypass_nets().map_err(anyhow::Error::msg)? {
            let skip = match net.addr() {
                IpAddr::V4(v4) => v4.is_loopback() || v4.is_broadcast() || v4.is_multicast(),
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast(),
            };
            if skip {
                continue;
            }
            // Link-local destinations are reachable only on the local link;
            // sending them through the gateway would blackhole them.
            let next_hop = match net.addr() {
                IpAddr::V4(v4) if v4.is_link_local() => None,
                IpAddr::V4(_) => Some(phys.gateway_ip),
                IpAddr::V6(_) => None,
            };
            if let Err(e) =
                add_or_replace_route(&phys_luid, net.addr(), net.prefix_len(), next_hop, 1).await
            {
                tracing::warn!(cidr = %net, error = %e, "could not install bypass route");
            }
        }

        // 3. TUN subnet, ULA, then the sub-default halves (never the real
        //    default route). Windows creates the on-link subnet route when the
        //    address is assigned; adding it again is an idempotent no-op.
        let tun_cidr: ipnet::IpNet = format!("{}/{}", cfg.tun_ipv4, cfg.tun_prefix).parse()?;
        add_or_replace_route(
            &tun_luid,
            tun_cidr.trunc().addr(),
            tun_cidr.prefix_len(),
            None,
            1,
        )
        .await
        .context("failed to install the TUN subnet route")?;
        if let Err(e) =
            add_or_replace_route(&tun_luid, "fd00:255::".parse().unwrap(), 64, None, 1).await
        {
            tracing::warn!(error = %e, "could not install IPv6 ULA route; continuing");
        }
        for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
            let net: ipnet::IpNet = cidr.parse().unwrap();
            add_or_replace_route(&tun_luid, net.addr(), net.prefix_len(), None, 1).await?;
        }
        for cidr in ["::/1", "8000::/1"] {
            let net: ipnet::IpNet = cidr.parse().unwrap();
            if let Err(e) =
                add_or_replace_route(&tun_luid, net.addr(), net.prefix_len(), None, 1).await
            {
                tracing::warn!(
                    cidr = %cidr,
                    error = %e,
                    "could not install IPv6 sub-default route; IPv6 traffic may bypass the tunnel"
                );
            }
        }

        // 4. Windows DNS leak blocker (dynamic WFP session).
        self.install_wfp_dns_blocker(&tun_luid)?;
        Ok(())
    }

    async fn apply_dns(&self, tun_name: &str, dns_ip: Ipv4Addr) -> anyhow::Result<()> {
        let luid = luid_from_name(tun_name)?;
        let mut guid = windows_sys::core::GUID::from_u128(0);
        let status = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
        if status != 0 {
            return Err(anyhow!("ConvertInterfaceLuidToGuid failed: {status}"));
        }
        let mut name_server: Vec<u16> = dns_ip
            .to_string()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: name_server.as_mut_ptr(),
            ..Default::default()
        };
        let status = unsafe { SetInterfaceDnsSettings(guid, &settings) };
        if status != 0 {
            return Err(anyhow!("SetInterfaceDnsSettings failed: {status}"));
        }
        flush_dns_cache();
        Ok(())
    }

    async fn restore_all(&self, journal: &RollbackJournal) -> anyhow::Result<()> {
        // Closing the dynamic WFP engine handle removes every DNS-block filter
        // immediately, even if individual filter deletes fail.
        if let Ok(mut guard) = self.wfp.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.tun_luid.lock() {
            *guard = None;
        }

        // The relay pin may live on a different interface than the one
        // detected at startup (multi-homed hosts, VPNs), so delete it by
        // destination across every interface.
        if let Ok(relay) = journal.upstream_relay_ip.parse::<IpAddr>() {
            delete_route_everywhere(relay, if relay.is_ipv4() { 32 } else { 128 });
        }
        let phys_luid = luid_from_name(&journal.physical_interface).ok();

        for cidr in &journal.routes_added {
            let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
                continue;
            };
            // Try the TUN LUID, then the physical LUID; whichever owns the
            // route will succeed. Routes on a removed TUN adapter disappear
            // automatically.
            let tun_luid = luid_from_name(&journal.tun_interface).ok();
            if let Some(luid) = tun_luid {
                let _ = delete_route(&luid, net.addr(), net.prefix_len());
            }
            if let Some(luid) = phys_luid {
                let _ = delete_route(&luid, net.addr(), net.prefix_len());
            }
        }

        flush_dns_cache();
        Ok(())
    }

    async fn refresh_dns_guard(&self, tun_name: &str, dns_ip: Ipv4Addr) -> anyhow::Result<()> {
        self.apply_dns(tun_name, dns_ip).await?;
        self.rebuild_wfp()
    }

    async fn snapshot_dns(
        &self,
        phys: &PhysicalInterfaceInfo,
        journal: &mut RollbackJournal,
    ) -> anyhow::Result<()> {
        journal.dns_mode = Some("windows".into());
        journal.original_dns_servers = original_dns_servers(phys.index).unwrap_or_default();
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
        let prefix_len = if relay.is_ipv4() { 32 } else { 128 };
        let next_hop = if phys.gateway_ip.is_ipv4() == relay.is_ipv4() {
            let next = phys.gateway_ip;
            if next.is_unspecified() {
                None
            } else {
                Some(next)
            }
        } else {
            // The detected interface carries a gateway of the other family.
            // Drop the stale pin first so GetBestRoute2 sees the new uplink,
            // then ask Windows for a valid same-family next hop.
            delete_route_everywhere(relay, prefix_len);
            best_route_for(relay)
                .map(|route| route.next_hop)
                .filter(|ip| !ip.is_unspecified())
        };
        let luid = luid_from_name(&phys.name)?;
        add_or_replace_route(&luid, relay, prefix_len, next_hop, 1).await
    }

    async fn remove_relay_route(&self, relay: IpAddr, _phys: &PhysicalInterfaceInfo) {
        if relay.is_loopback() {
            return;
        }
        delete_route_everywhere(relay, if relay.is_ipv4() { 32 } else { 128 });
    }

    fn platform_name(&self) -> &'static str {
        "windows"
    }
}

impl WindowsRouteManager {
    fn install_wfp_dns_blocker(&self, tun_luid: &NET_LUID_LH) -> anyhow::Result<()> {
        let tun_value = unsafe { tun_luid.Value };
        if let Ok(mut luid) = self.tun_luid.lock() {
            *luid = Some(tun_value);
        }
        let mut guard = self.wfp.lock().map_err(|_| anyhow!("WFP mutex poisoned"))?;
        if guard.is_some() {
            return Ok(());
        }
        let session = build_wfp_session(tun_value)?;
        *guard = Some(session);
        Ok(())
    }

    fn rebuild_wfp(&self) -> anyhow::Result<()> {
        let tun_value = *self
            .tun_luid
            .lock()
            .map_err(|_| anyhow!("WFP luid mutex poisoned"))?
            .as_ref()
            .ok_or_else(|| anyhow!("TUN LUID is not recorded"))?;
        let mut guard = self.wfp.lock().map_err(|_| anyhow!("WFP mutex poisoned"))?;
        // Dropping the session removes every old filter immediately.
        *guard = None;
        let session = build_wfp_session(tun_value)?;
        *guard = Some(session);
        Ok(())
    }
}

fn build_wfp_session(tun_value: u64) -> anyhow::Result<WfpSession> {
    let engine = WfpEngine::open()?;
    engine.add_sublayer()?;
    engine.add_dns_block_filters(&FWPM_LAYER_ALE_AUTH_CONNECT_V4, tun_value)?;
    engine.add_dns_block_filters(&FWPM_LAYER_ALE_AUTH_CONNECT_V6, tun_value)?;
    Ok(WfpSession {
        engine: engine.into_handle(),
    })
}

struct WfpEngine(HANDLE);

impl Drop for WfpEngine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

impl WfpEngine {
    fn into_handle(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }

    fn open() -> anyhow::Result<Self> {
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        };
        if status != 0 {
            return Err(anyhow!("FwpmEngineOpen0 failed: {status}"));
        }
        Ok(Self(engine))
    }

    fn add_sublayer(&self) -> anyhow::Result<()> {
        let mut name = wide("ProxyBase DNS Leak Blocker");
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = PROXYBASE_SUBLAYER_GUID;
        sublayer.displayData = FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: std::ptr::null_mut(),
        };
        sublayer.weight = 0x8000;
        let status = unsafe { FwpmSubLayerAdd0(self.0, &sublayer, std::ptr::null_mut()) };
        const FWP_E_ALREADY_EXISTS: u32 = 0x8032000C;
        if status != 0 && status != FWP_E_ALREADY_EXISTS {
            return Err(anyhow!("FwpmSubLayerAdd0 failed: {status:#x}"));
        }
        Ok(())
    }

    /// Block outbound DNS on every interface *except* the Wintun adapter.
    ///
    /// A single `local interface != TUN` condition covers interfaces that
    /// appear after the tunnel starts (Wi-Fi/Ethernet changes, USB tethering),
    /// so Smart Multi-Homed Name Resolution can never leak around our DNS
    /// proxy. WFP supports `FWP_MATCH_NOT_EQUAL` for LUID conditions.
    fn add_dns_block_filters(
        &self,
        layer: &windows_sys::core::GUID,
        tun_luid_value: u64,
    ) -> anyhow::Result<()> {
        for protocol in [IPPROTO_UDP as u8, IPPROTO_TCP as u8] {
            self.add_filter(layer, tun_luid_value, protocol)?;
        }
        Ok(())
    }

    fn add_filter(
        &self,
        layer: &windows_sys::core::GUID,
        luid_value: u64,
        protocol: u8,
    ) -> anyhow::Result<()> {
        let mut luid_value = luid_value;
        let mut conditions = vec![
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        uint8: protocol,
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        uint16: 53,
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType: FWP_MATCH_NOT_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        uint64: &mut luid_value,
                    },
                },
            },
        ];

        let mut name = wide("ProxyBase: block DNS on physical interfaces");
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData = FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: std::ptr::null_mut(),
        };
        filter.layerKey = *layer;
        filter.subLayerKey = PROXYBASE_SUBLAYER_GUID;
        filter.weight = FWP_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: unsafe { std::mem::zeroed() },
        };
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action = FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: unsafe { std::mem::zeroed() },
        };
        let mut id = 0u64;
        let status = unsafe { FwpmFilterAdd0(self.0, &filter, std::ptr::null_mut(), &mut id) };
        if status != 0 {
            return Err(anyhow!("FwpmFilterAdd0 failed: {status}"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Route helpers
// ---------------------------------------------------------------------------

fn detect_default_route(own_tun: Option<u64>) -> anyhow::Result<PhysicalInterfaceInfo> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if status != 0 {
        return Err(anyhow!("GetIpForwardTable2 failed: {status}"));
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut best_connected: Option<(u32, NET_LUID_LH, Ipv4Addr, u32)> = None;
    let mut best_any: Option<(u32, NET_LUID_LH, Ipv4Addr, u32)> = None;
    for row in rows {
        if row.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let prefix_ip = unsafe { sockaddr_ip(&row.DestinationPrefix.Prefix) };
        if prefix_ip != Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
            continue;
        }
        // Never select our own tunnel as the "physical" uplink. Its 0/1 and
        // 128/1 routes contain every IPv4 destination; picking it would pin
        // the relay route back into the tunnel.
        if own_tun == Some(luid_value(&row.InterfaceLuid)) {
            continue;
        }
        let Ok(name) = name_from_luid(&row.InterfaceLuid) else {
            continue;
        };
        if is_own_tun_name(&name)
            || interface_alias(&row.InterfaceLuid).is_some_and(|a| is_own_tun_name(&a))
        {
            continue;
        }
        let next_hop = unsafe { sockaddr_ip(&row.NextHop) }
            .and_then(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        if next_hop == Ipv4Addr::UNSPECIFIED {
            continue;
        }
        let if_row = interface_row(&row.InterfaceLuid);
        let if_metric = if_row.map(|if_row| if_row.Metric).unwrap_or(0);
        let effective_metric = row.Metric.saturating_add(if_metric);
        let candidate = (
            effective_metric,
            row.InterfaceLuid,
            next_hop,
            row.InterfaceIndex,
        );
        let is_better = |best: &Option<(u32, NET_LUID_LH, Ipv4Addr, u32)>| {
            best.as_ref()
                .map(|(metric, _, _, _)| effective_metric < *metric)
                .unwrap_or(true)
        };
        if is_better(&best_any) {
            best_any = Some(candidate);
        }
        let connected = if_row.map(|if_row| if_row.Connected).unwrap_or(true);
        if connected && is_better(&best_connected) {
            best_connected = Some(candidate);
        }
    }
    unsafe { FreeMibTable(table as *const _) };
    let (_, luid, gateway, index) = best_connected
        .or(best_any)
        .ok_or_else(|| anyhow!("no IPv4 default route found"))?;
    let name = name_from_luid(&luid)?;
    Ok(PhysicalInterfaceInfo {
        name,
        index,
        gateway_ip: IpAddr::V4(gateway),
    })
}

struct VpnAdapter {
    luid: u64,
    name: String,
}

/// Enumerate up, non-ProxyBase adapters that look like a VPN client.
///
/// WireGuard/Tailscale use Wintun (IF_TYPE_TUNNEL, matching "wintun"),
/// OpenVPN uses a TAP-Windows Ethernet adapter, and IKEv2/PPP VPNs use
/// IF_TYPE_PPP. The route-table scan in [`conflicting_vpn_from_routes`] is
/// what decides whether they actually own a default route.
fn enumerate_vpn_adapters() -> Vec<VpnAdapter> {
    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 0;
    let first = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if first != 0 && size == 0 {
        return Vec::new();
    }
    let mut storage = vec![0u64; (size as usize + 7) / 8];
    let adapters = storage.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null(),
            adapters,
            &mut size,
        )
    };
    if status != 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut current = adapters;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let name = pwstr_to_string(adapter.FriendlyName);
        let description = pwstr_to_string(adapter.Description);
        let own = is_own_tun_name(&name) || is_own_tun_name(&description);
        let up = adapter.OperStatus == IfOperStatusUp;
        let tunnel_type = adapter.IfType == IF_TYPE_TUNNEL || adapter.IfType == IF_TYPE_PPP;
        if up && !own && (tunnel_type || vpn_name_matches(&name) || vpn_name_matches(&description))
        {
            out.push(VpnAdapter {
                luid: luid_value(&adapter.Luid),
                name: if name.is_empty() { description } else { name },
            });
        }
        current = adapter.Next;
    }
    out
}

fn conflicting_vpn_from_routes(
    adapters: &[VpnAdapter],
    own_tun: Option<u64>,
) -> Option<VpnConflict> {
    // IPv4 only: that is the family ProxyBase itself needs, and it avoids
    // flagging IPv6-only system tunnels (Teredo/ISATAP are IF_TYPE_TUNNEL).
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != 0 || table.is_null() {
        return None;
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut found = None;
    for row in rows {
        let luid = luid_value(&row.InterfaceLuid);
        if Some(luid) == own_tun {
            continue;
        }
        let Some(adapter) = adapters.iter().find(|adapter| adapter.luid == luid) else {
            continue;
        };
        let Some(prefix) = (unsafe { sockaddr_ip(&row.DestinationPrefix.Prefix) }) else {
            continue;
        };
        // Full-tunnel VPNs take `default` or the two longest-prefix /1
        // halves; split-tunnel routes use longer prefixes.
        let destination = match row.DestinationPrefix.PrefixLength {
            0 => "default".to_string(),
            1 => format!("{prefix}/1"),
            _ => continue,
        };
        if let Some(detail) = default_route_detail(&destination) {
            found = Some(VpnConflict {
                interface: adapter.name.clone(),
                detail: detail.to_string(),
            });
            break;
        }
    }
    unsafe { FreeMibTable(table as *const _) };
    found
}

fn pwstr_to_string(ptr: windows_sys::core::PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn vpn_name_matches(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const KEYWORDS: &[&str] = &[
        "wireguard",
        "wintun",
        "tap-windows",
        "openvpn",
        "tailscale",
        "nordlynx",
        "proton",
        "mullvad",
        "cloudflare warp",
        "vpn",
    ];
    KEYWORDS.iter().any(|keyword| lower.contains(keyword))
}

/// Ask Windows which route it would use for `destination`.
///
/// Copying the interface and next hop from the OS's own best-route lookup
/// keeps the pin valid on multi-homed machines, VPNs and for IPv6 relays,
/// where assuming the IPv4 default gateway would produce a mismatched row
/// that `CreateIpForwardEntry2` rejects with `ERROR_INVALID_PARAMETER` (87).
struct BestRoute {
    luid: NET_LUID_LH,
    next_hop: IpAddr,
    #[allow(dead_code)]
    index: u32,
}

fn best_route_for(destination: IpAddr) -> Option<BestRoute> {
    let dest = make_sockaddr(destination);
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &dest,
            0,
            &mut row,
            &mut source,
        )
    };
    if status != 0 {
        return None;
    }
    let next_hop = unsafe { sockaddr_ip(&row.NextHop) }
        .filter(|ip| ip.is_ipv4() == destination.is_ipv4())
        .unwrap_or_else(|| unspecified_like(destination));
    Some(BestRoute {
        luid: row.InterfaceLuid,
        next_hop,
        index: row.InterfaceIndex,
    })
}

fn build_route_row(spec: &RouteSpec, luid: &NET_LUID_LH) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = *luid;
    if let Some(index) = luid_index(luid) {
        row.InterfaceIndex = index;
    }
    row.DestinationPrefix.Prefix = make_sockaddr(spec.destination);
    row.DestinationPrefix.PrefixLength = spec.prefix_len;
    row.NextHop = make_sockaddr(spec.next_hop);
    // InitializeIpForwardEntry intentionally leaves SitePrefixLength, Metric
    // and Protocol at illegal sentinel values and sets the boolean flags to
    // TRUE. Fill every field explicitly so no undocumented default can make
    // CreateIpForwardEntry2 reject the row with error 87.
    row.SitePrefixLength = 0;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = spec.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = true;
    row.Age = 0;
    row.Origin = NlroManual;
    row
}

async fn add_or_replace_route(
    luid: &NET_LUID_LH,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> anyhow::Result<()> {
    let spec = RouteSpec::new(destination, prefix_len, next_hop, metric)?;
    let row = build_route_row(&spec, luid);
    let mut replaced = false;

    for attempt in 0..6u32 {
        let status = unsafe { CreateIpForwardEntry2(&row) };
        if status == 0 {
            tracing::debug!(
                route = %route_label(&spec),
                interface = %interface_label(luid),
                "route installed"
            );
            return Ok(());
        }
        if status == ERROR_OBJECT_ALREADY_EXISTS {
            // Already exactly the route we want (e.g. the on-link subnet
            // route Windows created together with the interface address).
            if !matching_routes(luid, &spec, true).is_empty() {
                return Ok(());
            }
            // A conflicting route owns this prefix on this interface.
            // SetIpForwardEntry2 only matches when NextHop is identical, so
            // try it and then fall back to delete-and-recreate.
            let set_status = unsafe { SetIpForwardEntry2(&row) };
            if set_status == 0 {
                return Ok(());
            }
            if replaced {
                return Err(route_error("CreateIpForwardEntry2", &spec, luid, status));
            }
            let removed = delete_matching_routes(luid, &spec);
            tracing::debug!(
                route = %route_label(&spec),
                interface = %interface_label(luid),
                removed,
                set_error = set_status,
                "replacing conflicting route"
            );
            replaced = true;
            tokio::time::sleep(Duration::from_millis(25)).await;
            continue;
        }
        if (status == 87 || status == ERROR_NOT_FOUND) && attempt < 5 {
            // A freshly created Wintun adapter can be visible to the adapter
            // API before the IP Helper route provider has published it.
            tokio::time::sleep(Duration::from_millis(100 * (u64::from(attempt) + 1))).await;
            continue;
        }
        return Err(route_error("CreateIpForwardEntry2", &spec, luid, status));
    }

    Err(anyhow!(
        "route installation did not converge for {} on {}",
        route_label(&spec),
        interface_label(luid)
    ))
}

fn delete_route(luid: &NET_LUID_LH, destination: IpAddr, prefix_len: u8) -> WIN32_ERROR {
    let Ok(spec) = RouteSpec::new(destination, prefix_len, None, 0) else {
        return 87;
    };
    // Only remove static routes we installed. Connected and DHCP-owned routes
    // existed before the tunnel and must survive disconnect (otherwise, for
    // example, deleting a /8 bypass route could take the LAN with it).
    let rows = routes_matching(&spec, Some(luid_value(luid)), false, true);
    if !rows.is_empty() {
        let mut last_error = 0;
        for row in &rows {
            let err = unsafe { DeleteIpForwardEntry2(row) };
            if err != 0 {
                last_error = err;
            }
        }
        if last_error == 0 {
            return 0;
        }
    }

    let row = build_route_row(&spec, luid);
    unsafe { DeleteIpForwardEntry2(&row) }
}

/// Delete every static route to `destination/prefix_len`, regardless of
/// interface.
///
/// Used for the relay pin, whose interface can change across networks or be
/// different from the detected default route on multi-homed hosts.
fn delete_route_everywhere(destination: IpAddr, prefix_len: u8) -> usize {
    let Ok(spec) = RouteSpec::new(destination, prefix_len, None, 0) else {
        return 0;
    };
    let rows = routes_matching(&spec, None, false, true);
    let mut removed = 0;
    for row in &rows {
        if unsafe { DeleteIpForwardEntry2(row) } == 0 {
            removed += 1;
        }
    }
    removed
}

fn matching_routes(
    luid: &NET_LUID_LH,
    spec: &RouteSpec,
    same_next_hop: bool,
) -> Vec<MIB_IPFORWARD_ROW2> {
    routes_matching(spec, Some(luid_value(luid)), same_next_hop, false)
}

fn delete_matching_routes(luid: &NET_LUID_LH, spec: &RouteSpec) -> usize {
    let rows = matching_routes(luid, spec, false);
    let mut removed = 0;
    for row in &rows {
        if unsafe { DeleteIpForwardEntry2(row) } == 0 {
            removed += 1;
        }
    }
    removed
}

fn routes_matching(
    spec: &RouteSpec,
    luid: Option<u64>,
    same_next_hop: bool,
    only_netmgmt: bool,
) -> Vec<MIB_IPFORWARD_ROW2> {
    let family = if spec.destination.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    };
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(family, &mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut out = Vec::new();
    for row in rows {
        if let Some(luid) = luid {
            if luid_value(&row.InterfaceLuid) != luid {
                continue;
            }
        }
        if row.DestinationPrefix.PrefixLength != spec.prefix_len {
            continue;
        }
        if only_netmgmt && row.Protocol != MIB_IPPROTO_NETMGMT {
            continue;
        }
        if unsafe { sockaddr_ip(&row.DestinationPrefix.Prefix) } != Some(spec.destination) {
            continue;
        }
        if same_next_hop && unsafe { sockaddr_ip(&row.NextHop) } != Some(spec.next_hop) {
            continue;
        }
        out.push(*row);
    }
    unsafe { FreeMibTable(table as *const _) };
    out
}

fn luid_value(luid: &NET_LUID_LH) -> u64 {
    unsafe { luid.Value }
}

fn luid_index(luid: &NET_LUID_LH) -> Option<u32> {
    let mut index = 0u32;
    if unsafe { ConvertInterfaceLuidToIndex(luid, &mut index) } == 0 {
        Some(index)
    } else {
        None
    }
}

fn interface_row(luid: &NET_LUID_LH) -> Option<MIB_IPINTERFACE_ROW> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = *luid;
    if unsafe { GetIpInterfaceEntry(&mut row) } == 0 {
        Some(row)
    } else {
        None
    }
}

async fn wait_for_interface(luid: &NET_LUID_LH, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // `GetIpInterfaceEntry` succeeding means the IP Helper route provider
        // has published the interface; that is what CreateIpForwardEntry2
        // needs. Media state can lag behind and is not required for routes.
        if luid_index(luid).is_some() && interface_row(luid).is_some() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn is_own_tun_name(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("proxybase")
}

fn interface_alias(luid: &NET_LUID_LH) -> Option<String> {
    let mut buf = vec![0u16; 257];
    let status = unsafe { ConvertInterfaceLuidToAlias(luid, buf.as_mut_ptr(), buf.len()) };
    if status != 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

fn interface_label(luid: &NET_LUID_LH) -> String {
    match interface_alias(luid) {
        Some(alias) => format!("{alias} [LUID {:#x}]", luid_value(luid)),
        None => format!("LUID {:#x}", luid_value(luid)),
    }
}

fn route_label(spec: &RouteSpec) -> String {
    format!(
        "{}/{} via {}",
        spec.destination, spec.prefix_len, spec.next_hop
    )
}

fn route_error(
    op: &str,
    spec: &RouteSpec,
    luid: &NET_LUID_LH,
    status: WIN32_ERROR,
) -> anyhow::Error {
    anyhow!(
        "{op} failed for {} on {}: {} [Windows error {status}]",
        route_label(spec),
        interface_label(luid),
        route_status_text(status)
    )
}

fn route_status_text(status: WIN32_ERROR) -> &'static str {
    match status {
        5 => "access denied — the tunnel service must run with administrator rights",
        50 => "the interface does not support routes",
        87 => "invalid route parameters (destination prefix, next hop, or interface rejected)",
        1168 => "the interface was not found",
        5010 => "a matching route already exists",
        _ => "unexpected Windows routing error",
    }
}

fn make_sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    sa
}

unsafe fn sockaddr_ip(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    let family = unsafe { sa.si_family };
    if family == AF_INET {
        let v4 = unsafe { sa.Ipv4 };
        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(unsafe {
            v4.sin_addr.S_un.S_addr
        }))))
    } else if family == AF_INET6 {
        let v6 = unsafe { sa.Ipv6 };
        Some(IpAddr::V6(Ipv6Addr::from(unsafe { v6.sin6_addr.u.Byte })))
    } else {
        None
    }
}

fn luid_from_name(name: &str) -> anyhow::Result<NET_LUID_LH> {
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // Try resolving as an interface alias first (e.g. "ProxyBase", "Ethernet", "Wi-Fi"),
    // which is what tun-rs and the Windows UI present.
    let status_alias = unsafe { ConvertInterfaceAliasToLuid(wide_name.as_ptr(), &mut luid) };
    if status_alias == 0 {
        return Ok(luid);
    }
    // Fall back to NDIS interface name (e.g. "ethernet_32768", "wintun_0").
    let status_name = unsafe { ConvertInterfaceNameToLuidW(wide_name.as_ptr(), &mut luid) };
    if status_name == 0 {
        return Ok(luid);
    }
    Err(anyhow!(
        "could not resolve interface '{name}' to LUID (alias error: {status_alias}, name error: {status_name})"
    ))
}

fn name_from_luid(luid: &NET_LUID_LH) -> anyhow::Result<String> {
    let mut buf = vec![0u16; 256];
    let status = unsafe { ConvertInterfaceLuidToNameW(luid, buf.as_mut_ptr(), buf.len()) };
    if status != 0 {
        return Err(anyhow!("ConvertInterfaceLuidToNameW failed: {status}"));
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(String::from_utf16_lossy(&buf[..len]))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn original_dns_servers(if_index: u32) -> anyhow::Result<Vec<String>> {
    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 0;
    let first = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    // ERROR_BUFFER_OVERFLOW is expected; `size` now holds the required size.
    if first != 0 && size == 0 {
        return Err(anyhow!("GetAdaptersAddresses sizing failed: {first}"));
    }
    let mut storage = vec![0u64; (size as usize + 7) / 8];
    let adapters = storage.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null(),
            adapters,
            &mut size,
        )
    };
    if status != 0 {
        return Err(anyhow!("GetAdaptersAddresses failed: {status}"));
    }

    let mut current = adapters;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        if index == if_index {
            let mut servers = Vec::new();
            let mut dns = adapter.FirstDnsServerAddress;
            while !dns.is_null() {
                let entry = unsafe { &*dns };
                if let Some(ip) = unsafe { socket_address_ip(&entry.Address) } {
                    servers.push(ip.to_string());
                }
                dns = entry.Next;
            }
            return Ok(servers);
        }
        current = adapter.Next;
    }
    Ok(Vec::new())
}

unsafe fn socket_address_ip(
    address: &windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() {
        return None;
    }
    let sa = unsafe { &*(address.lpSockaddr as *const SOCKADDR) };
    match sa.sa_family {
        AF_INET => {
            let v4 = unsafe { &*(address.lpSockaddr as *const SOCKADDR_IN) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(unsafe {
                v4.sin_addr.S_un.S_addr
            }))))
        }
        AF_INET6 => {
            let v6 = unsafe {
                &*(address.lpSockaddr
                    as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6)
            };
            Some(IpAddr::V6(Ipv6Addr::from(unsafe { v6.sin6_addr.u.Byte })))
        }
        _ => None,
    }
}

/// Flush the Windows resolver cache via the documented API.
pub fn flush_dns_cache() {
    #[link(name = "dnsapi")]
    extern "system" {
        fn DnsFlushResolverCache() -> i32;
    }
    unsafe {
        DnsFlushResolverCache();
    }
}
