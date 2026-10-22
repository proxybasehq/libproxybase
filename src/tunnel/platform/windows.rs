//! Windows route, DNS and DNS-leak management.
//!
//! Routes use the typed IP Helper API (`GetIpForwardTable2` /
//! `CreateIpForwardEntry2` / `SetIpForwardEntry2`). DNS is installed on the
//! Wintun interface with `SetInterfaceDnsSettings`. Because Windows sends DNS
//! queries in parallel across every adapter (Smart Multi-Homed Name
//! Resolution), a dynamic WFP session additionally blocks outbound UDP/TCP:53
//! on every physical interface; the kernel removes those filters automatically
//! if this process exits or crashes.

use super::PlatformRouteManager;
use crate::tunnel::config::TunnelConfig;
use crate::tunnel::journal::RollbackJournal;
use crate::tunnel::socket_bypass::PhysicalInterfaceInfo;
use anyhow::anyhow;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToNameW,
    ConvertInterfaceNameToLuidW, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
    GetAdaptersAddresses, GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, SetInterfaceDnsSettings, SetIpForwardEntry2, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FWPM_ACTION0,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_CONDITION_VALUE0, FWP_EMPTY,
    FWP_MATCH_EQUAL, FWP_MATCH_NOT_EQUAL, FWP_UINT16, FWP_UINT64, FWP_UINT8, FWP_VALUE0,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IPPROTO_TCP, IPPROTO_UDP, SOCKADDR, SOCKADDR_IN, SOCKADDR_INET,
};
use windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;

const RPC_C_AUTHN_WINNT: u32 = 10;
const LOOPBACK_INTERFACE_INDEX: u32 = 1;

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
        detect_default_route()
    }

    async fn apply_routes(
        &self,
        tun_name: &str,
        phys: &PhysicalInterfaceInfo,
        cfg: &TunnelConfig,
    ) -> anyhow::Result<()> {
        let phys_luid = luid_from_name(&phys.name)?;
        let tun_luid = luid_from_name(tun_name)?;

        // 1. Relay host route pinned to the physical interface. Loopback
        //    relays stay on the machine and are never routed.
        if !cfg.upstream_relay_ip.is_loopback() {
            add_or_replace_route(
                &phys_luid,
                cfg.upstream_relay_ip,
                if cfg.upstream_relay_ip.is_ipv4() { 32 } else { 128 },
                Some(phys.gateway_ip),
                1,
            )?;
        }

        // 2. Bypass routes. Loopback, link-local, multicast and broadcast are
        //    deliberately not re-added on Windows: the OS already has
        //    more-specific routes for them, and re-pointing 127/8 at the NIC
        //    would break localhost.
        for net in cfg.bypass_nets().map_err(anyhow::Error::msg)? {
            // Add every configured bypass except loopback, broadcast and
            // multicast. Unlike the Unix path, Windows has no per-interface
            // local table for 127/8, so writing such a route would break
            // localhost.
            let skip = match net.addr() {
                IpAddr::V4(v4) => v4.is_loopback() || v4.is_broadcast() || v4.is_multicast(),
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast(),
            };
            if skip {
                continue;
            }
            let next_hop = match net.addr() {
                IpAddr::V4(_) => Some(phys.gateway_ip),
                IpAddr::V6(_) => None,
            };
            if let Err(e) =
                add_or_replace_route(&phys_luid, net.addr(), net.prefix_len(), next_hop, 1)
            {
                tracing::warn!(cidr = %net, error = %e, "could not install bypass route");
            }
        }

        // 3. TUN subnet, ULA, then the sub-default halves (never the real
        //    default route).
        let tun_cidr: ipnet::IpNet = format!("{}/{}", cfg.tun_ipv4, cfg.tun_prefix).parse()?;
        add_or_replace_route(
            &tun_luid,
            tun_cidr.trunc().addr(),
            tun_cidr.prefix_len(),
            None,
            1,
        )?;
        if let Err(e) = add_or_replace_route(
            &tun_luid,
            "fd00:255::".parse().unwrap(),
            64,
            None,
            1,
        ) {
            tracing::warn!(error = %e, "could not install IPv6 ULA route; continuing");
        }
        for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
            let net: ipnet::IpNet = cidr.parse().unwrap();
            add_or_replace_route(&tun_luid, net.addr(), net.prefix_len(), None, 1)?;
        }
        for cidr in ["::/1", "8000::/1"] {
            let net: ipnet::IpNet = cidr.parse().unwrap();
            if let Err(e) = add_or_replace_route(&tun_luid, net.addr(), net.prefix_len(), None, 1) {
                tracing::warn!(cidr = %cidr, error = %e, "could not install IPv6 sub-default route; continuing with IPv4 tunnel");
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

        let phys_luid = luid_from_name(&journal.physical_interface).ok();
        if let Some(luid) = phys_luid {
            if let Ok(relay) = journal.upstream_relay_ip.parse::<IpAddr>() {
                let _ = delete_route(
                    &luid,
                    relay,
                    if relay.is_ipv4() { 32 } else { 128 },
                );
            }
        }

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

    async fn refresh_dns_guard(
        &self,
        tun_name: &str,
        dns_ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
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
        let luid = luid_from_name(&phys.name)?;
        add_or_replace_route(
            &luid,
            relay,
            if relay.is_ipv4() { 32 } else { 128 },
            Some(phys.gateway_ip),
            1,
        )
    }

    async fn remove_relay_route(&self, relay: IpAddr, phys: &PhysicalInterfaceInfo) {
        if relay.is_loopback() {
            return;
        }
        if let Ok(luid) = luid_from_name(&phys.name) {
            let _ = delete_route(&luid, relay, if relay.is_ipv4() { 32 } else { 128 });
        }
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

fn detect_default_route() -> anyhow::Result<PhysicalInterfaceInfo> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if status != 0 {
        return Err(anyhow!("GetIpForwardTable2 failed: {status}"));
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut best: Option<(u32, NET_LUID_LH, Ipv4Addr, u32)> = None;
    for row in rows {
        if row.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let prefix_ip = unsafe { sockaddr_ip(&row.DestinationPrefix.Prefix) };
        if prefix_ip != Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
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
        let mut if_row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut if_row) };
        if_row.Family = AF_INET;
        if_row.InterfaceLuid = row.InterfaceLuid;
        let if_metric = if unsafe { GetIpInterfaceEntry(&mut if_row) } == 0 {
            if_row.Metric
        } else {
            0
        };
        let effective_metric = row.Metric.saturating_add(if_metric);
        let candidate = (effective_metric, row.InterfaceLuid, next_hop, row.InterfaceIndex);
        if best
            .as_ref()
            .map(|(metric, _, _, _)| effective_metric < *metric)
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
    }
    unsafe { FreeMibTable(table as *const _) };
    let (_, luid, gateway, index) =
        best.ok_or_else(|| anyhow!("no IPv4 default route found"))?;
    let name = name_from_luid(&luid)?;
    Ok(PhysicalInterfaceInfo {
        name,
        index,
        gateway_ip: IpAddr::V4(gateway),
    })
}

fn add_or_replace_route(
    luid: &NET_LUID_LH,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> anyhow::Result<()> {
    // Windows rejects routes with non-zero host bits outside prefix_len
    // with ERROR_INVALID_PARAMETER (87). Truncate to network address.
    let clean_dest = ipnet::IpNet::new(destination, prefix_len)
        .map(|net| net.trunc().addr())
        .unwrap_or(destination);

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.DestinationPrefix.Prefix = make_sockaddr(clean_dest);
    row.NextHop = make_sockaddr(next_hop.unwrap_or_else(|| unspecified_like(clean_dest)));
    // InitializeIpForwardEntry sets SitePrefixLength to 255 (illegal).
    // If SitePrefixLength > DestinationPrefix.PrefixLength, CreateIpForwardEntry2
    // fails with ERROR_INVALID_PARAMETER (87). It must be explicitly set to 0.
    row.SitePrefixLength = 0;
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Immortal = true;
    row.Loopback = false;

    let status = unsafe { CreateIpForwardEntry2(&row) };
    if status == ERROR_OBJECT_ALREADY_EXISTS {
        let status = unsafe { SetIpForwardEntry2(&row) };
        if status != 0 && status != ERROR_NOT_FOUND {
            return Err(anyhow!("SetIpForwardEntry2 failed: {status}"));
        }
        return Ok(());
    }
    if status != 0 {
        return Err(anyhow!("CreateIpForwardEntry2 failed: {status}"));
    }
    Ok(())
}

fn delete_route(luid: &NET_LUID_LH, destination: IpAddr, prefix_len: u8) -> WIN32_ERROR {
    let clean_dest = ipnet::IpNet::new(destination, prefix_len)
        .map(|net| net.trunc().addr())
        .unwrap_or(destination);
    let family = match destination {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(family, &mut table) };
    if status == 0 && !table.is_null() {
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        let mut last_error = 0;
        let mut deleted = false;
        for row in rows {
            if unsafe { row.InterfaceLuid.Value == luid.Value }
                && row.DestinationPrefix.PrefixLength == prefix_len
                && unsafe { sockaddr_ip(&row.DestinationPrefix.Prefix) } == Some(clean_dest)
            {
                let err = unsafe { DeleteIpForwardEntry2(row) };
                if err != 0 {
                    last_error = err;
                } else {
                    deleted = true;
                }
            }
        }
        unsafe { FreeMibTable(table as *const _) };
        if deleted || last_error == 0 {
            return 0;
        }
    }

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.DestinationPrefix.Prefix = make_sockaddr(clean_dest);
    row.NextHop = make_sockaddr(unspecified_like(clean_dest));
    row.SitePrefixLength = 0;
    unsafe { DeleteIpForwardEntry2(&row) }
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

fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
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
    let status =
        unsafe { ConvertInterfaceLuidToNameW(luid, buf.as_mut_ptr(), buf.len()) };
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
    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 0;
    let first = unsafe {
        GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), std::ptr::null_mut(), &mut size)
    };
    // ERROR_BUFFER_OVERFLOW is expected; `size` now holds the required size.
    if first != 0 && size == 0 {
        return Err(anyhow!("GetAdaptersAddresses sizing failed: {first}"));
    }
    let mut storage = vec![0u64; (size as usize + 7) / 8];
    let adapters = storage.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let status = unsafe {
        GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), adapters, &mut size)
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
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                unsafe { v4.sin_addr.S_un.S_addr },
            ))))
        }
        AF_INET6 => {
            let v6 = unsafe {
                &*(address.lpSockaddr
                    as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6)
            };
            Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                v6.sin6_addr.u.Byte
            })))
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

