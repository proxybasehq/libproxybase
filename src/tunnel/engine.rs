//! Shared TUN -> userspace TCP/IP -> SOCKS5 packet engine.
//!
//! The engine is platform-neutral: desktop passes an `AsyncDevice` created by
//! `tun-rs`, Android passes one adopted from `VpnService.detachFd()`. Route and
//! DNS setup is delegated to [`PlatformRouteManager`].

use crate::tunnel::config::{
    TunnelConfig, TunnelErrorCode, TunnelMode, TunnelState,
};
use crate::tunnel::fake_dns::FakeDns;
use crate::tunnel::health::{verify_exit_node, HealthError};
use crate::tunnel::journal::{self, RollbackJournal};
use crate::tunnel::packet::{parse, build_udp_response, PacketDecision, PacketFilter};
use crate::tunnel::platform::{self, PlatformRouteManager};
use crate::tunnel::socks5::{
    connect_via_socks, decode_udp_datagram, encode_udp_datagram, udp_associate, Socks5Endpoint,
    TargetAddr,
};
use crate::tunnel::socket_bypass::{PhysicalInterfaceInfo, SocketBypass};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream, TcpConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{broadcast, mpsc, watch, Mutex, RwLock};
use tokio::task::JoinHandle;

pub const DNS_OVER_TCP_SERVER: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
pub const TUN_IPV6_ADDRESS: &str = "fd00:255::2";
pub const TUN_IPV6_CIDR: &str = "fd00:255::/64";

/// Live traffic counters pushed to the GUI every second.
#[derive(Debug, Clone, Copy, Default)]
pub struct Telemetry {
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub active_flows: u32,
}

#[derive(Debug, Clone)]
pub struct TunnelError {
    pub code: TunnelErrorCode,
    pub message: String,
}

impl TunnelError {
    fn new(code: TunnelErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for TunnelError {}

/// Cancellation primitive (watch-based so it is cancel-safe and cheap).
#[derive(Clone)]
struct Cancel {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl Cancel {
    fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self { tx, rx }
    }

    fn cancel(&self) {
        let _ = self.tx.send(true);
    }

    async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        if *rx.borrow() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }
}

#[derive(Default)]
struct Stats {
    rx: AtomicU64,
    tx: AtomicU64,
    flows: AtomicU32,
    /// Set when the upstream rejects CONNECT in a way that indicates an
    /// exhausted quota or revoked lease.
    quota_exhausted: AtomicBool,
    /// Set when the TUN device disappears or returns a fatal read error.
    tun_failed: AtomicBool,
}

impl Stats {
    fn telemetry(&self, last: &mut (u64, u64), instant: &mut Instant) -> Telemetry {
        let rx = self.rx.load(Ordering::Relaxed);
        let tx = self.tx.load(Ordering::Relaxed);
        let elapsed = instant.elapsed().as_secs_f64().max(0.001);
        let rx_bps = (((rx.saturating_sub(last.0)) as f64) / elapsed) as u64;
        let tx_bps = (((tx.saturating_sub(last.1)) as f64) / elapsed) as u64;
        *last = (rx, tx);
        *instant = Instant::now();
        Telemetry {
            rx_bytes_total: rx,
            tx_bytes_total: tx,
            rx_bps,
            tx_bps,
            active_flows: self.flows.load(Ordering::Relaxed),
        }
    }
}

/// Counts bytes as they are read from a stream. Wrapping each half of a
/// bidirectional copy gives live telemetry even for long-lived keep-alive
/// connections (the totals returned by `copy_bidirectional` only arrive at
/// close time).
struct ReadCounter<S> {
    inner: S,
    stats: Arc<Stats>,
    /// true = application -> upstream (TX), false = upstream -> app (RX).
    tx: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadCounter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len().saturating_sub(before);
            if n > 0 {
                if self.tx {
                    self.stats.tx.fetch_add(n as u64, Ordering::Relaxed);
                } else {
                    self.stats.rx.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReadCounter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
struct EngineContext {
    fake_dns: Arc<FakeDns>,
    endpoint: Arc<RwLock<Socks5Endpoint>>,
    bypass: Arc<RwLock<Option<Arc<SocketBypass>>>>,
    stats: Arc<Stats>,
    cancel: Cancel,
}

impl EngineContext {
    async fn endpoint(&self) -> Socks5Endpoint {
        self.endpoint.read().await.clone()
    }

    async fn bypass_snapshot(&self) -> Option<Arc<SocketBypass>> {
        self.bypass.read().await.clone()
    }
}

/// A `tun-rs` device adapter that preserves packet boundaries. `ipstack`
/// expects one `read()` to return exactly one IP packet; a byte-stream duplex
/// would coalesce packets and corrupt parsing.
struct PacketDevice {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for PacketDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                if packet.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "packet of {} bytes exceeds stack buffer of {}",
                            packet.len(),
                            buf.remaining()
                        ),
                    )));
                }
                buf.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tunnel writer closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct PacketLoop {
    cancel: Cancel,
    handles: Vec<JoinHandle<()>>,
    endpoint: Arc<RwLock<Socks5Endpoint>>,
    bypass: Arc<RwLock<Option<Arc<SocketBypass>>>>,
    stats: Arc<Stats>,
}

struct ActiveTunnel {
    cancel: Cancel,
    handles: Vec<JoinHandle<()>>,
    journal: Arc<Mutex<RollbackJournal>>,
    journal_path: std::path::PathBuf,
    manager: Arc<dyn PlatformRouteManager>,
    config: Arc<RwLock<TunnelConfig>>,
    phys: Arc<RwLock<PhysicalInterfaceInfo>>,
    endpoint: Arc<RwLock<Socks5Endpoint>>,
    tun_name: String,
    telemetry: broadcast::Sender<Telemetry>,
}

/// The public state machine used by the daemon and the Android shell.
pub struct SystemTunnelEngine {
    state: Arc<RwLock<TunnelState>>,
    state_tx: broadcast::Sender<TunnelState>,
    telemetry_tx: broadcast::Sender<Telemetry>,
    fake_dns: Arc<FakeDns>,
    stats: Arc<Stats>,
    active: Mutex<Option<ActiveTunnel>>,
}

impl Default for SystemTunnelEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemTunnelEngine {
    pub fn new() -> Self {
        let (state_tx, _) = broadcast::channel(64);
        let (telemetry_tx, _) = broadcast::channel(64);
        let engine = Self {
            state: Arc::new(RwLock::new(TunnelState::Disconnected)),
            state_tx,
            telemetry_tx,
            fake_dns: Arc::new(FakeDns::new()),
            stats: Arc::new(Stats::default()),
            active: Mutex::new(None),
        };
        let _ = engine.state_tx.send(TunnelState::Disconnected);
        engine
    }

    pub fn subscribe_state(&self) -> broadcast::Receiver<TunnelState> {
        self.state_tx.subscribe()
    }

    pub fn subscribe_telemetry(&self) -> broadcast::Receiver<Telemetry> {
        self.telemetry_tx.subscribe()
    }

    pub async fn state(&self) -> TunnelState {
        self.state.read().await.clone()
    }

    pub async fn telemetry(&self) -> Telemetry {
        let mut last = (0, 0);
        let mut instant = Instant::now();
        self.stats.telemetry(&mut last, &mut instant)
    }

    pub fn fake_dns(&self) -> Arc<FakeDns> {
        self.fake_dns.clone()
    }

    async fn publish(&self, state: TunnelState) {
        *self.state.write().await = state.clone();
        let _ = self.state_tx.send(state);
    }

    async fn publish_error(&self, code: TunnelErrorCode, message: impl Into<String>) {
        self.publish(TunnelState::Error {
            code,
            message: message.into(),
        })
        .await;
    }

    /// Start the tunnel on a desktop platform. Creates the TUN device, records
    /// a rollback journal, installs routes/DNS, verifies the exit node, and
    /// only then reports `Connected`.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    pub async fn start(self: &Arc<Self>, config: TunnelConfig) -> Result<(), TunnelError> {
        let mut slot = self.active.lock().await;
        if slot.is_some() {
            return Err(TunnelError::new(
                TunnelErrorCode::InternalError,
                "a tunnel is already active",
            ));
        }
        if let Err(e) = config.validate() {
            self.publish_error(TunnelErrorCode::InternalError, e.clone()).await;
            return Err(TunnelError::new(TunnelErrorCode::InternalError, e));
        }

        self.fake_dns.clear();
        self.publish(TunnelState::ConfiguringRoutes {
            proxy_id: config.proxy_id.clone(),
        })
        .await;

        let manager: Arc<dyn PlatformRouteManager> = Arc::from(platform::current());
        let phys = match manager.detect_physical_route().await {
            Ok(p) => p,
            Err(e) => {
                self.publish_error(TunnelErrorCode::RoutingConfigurationFailed, e.to_string())
                    .await;
                return Err(TunnelError::new(
                    TunnelErrorCode::RoutingConfigurationFailed,
                    e.to_string(),
                ));
            }
        };

        let device = match create_desktop_device(&config) {
            Ok(d) => d,
            Err(e) => {
                self.publish_error(TunnelErrorCode::TunDeviceCreationFailed, e.to_string())
                    .await;
                return Err(TunnelError::new(
                    TunnelErrorCode::TunDeviceCreationFailed,
                    format!("failed to create TUN device: {e}"),
                ));
            }
        };
        let tun_name = device.name().unwrap_or_else(|_| "tun".to_string());

        // Build and persist the rollback journal *before* mutating anything.
        let mut journal = RollbackJournal::new(
            format!(
                "{}-{}",
                config.proxy_id,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
            &tun_name,
            &phys.name,
            phys.index,
            phys.gateway_ip.to_string(),
            config.upstream_relay_ip.to_string(),
            Vec::new(),
        );
        journal.tun_ipv4_cidr = Some(format!("{}/{}", config.tun_ipv4, config.tun_prefix));
        #[cfg(target_os = "linux")]
        {
            if manager.platform_name() == "linux" {
                journal.linux_route_table = Some(platform::linux::POLICY_TABLE);
            }
        }
        if let Err(e) = manager.snapshot_dns(&phys, &mut journal).await {
            tracing::warn!(error = %e, "could not snapshot the original DNS configuration");
        }
        let mut route_nets = config.bypass_nets().map_err(|e| {
            TunnelError::new(TunnelErrorCode::InternalError, e)
        })?;
        route_nets.push(
            journal
                .tun_ipv4_cidr
                .as_deref()
                .unwrap_or("10.255.0.0/30")
                .parse()
                .expect("validated TUN CIDR"),
        );
        journal.routes_added = route_list(&route_nets);

        let journal_path = journal::default_journal_path();
        if let Err(e) = journal::write(&journal_path, &journal) {
            self.publish_error(
                TunnelErrorCode::InternalError,
                format!("failed to write the rollback journal: {e}"),
            )
            .await;
            return Err(TunnelError::new(
                TunnelErrorCode::InternalError,
                format!("failed to write the rollback journal: {e}"),
            ));
        }

        let endpoint = Arc::new(RwLock::new(Socks5Endpoint {
            bridge: config.socks5_bridge_addr,
            username: config.socks5_username.clone(),
            password: config.socks5_password.clone(),
        }));
        let bypass = Arc::new(RwLock::new(Some(Arc::new(SocketBypass::new(phys.clone())))));

        let PacketLoop {
            cancel,
            handles: mut loop_handles,
            endpoint: endpoint_arc,
            bypass: bypass_arc,
            stats,
        } = self.spawn_packet_loop(&config, device, endpoint.clone(), bypass.clone());

        // Routes and DNS. Any failure rolls the whole thing back.
        if let Err(e) = manager.apply_routes(&tun_name, &phys, &config).await {
            cancel.cancel();
            for h in loop_handles.drain(..) {
                h.abort();
            }
            let _ = manager.restore_all(&journal).await;
            let _ = journal::mark_inactive(&journal_path);
            self.publish_error(TunnelErrorCode::RoutingConfigurationFailed, e.to_string())
                .await;
            return Err(TunnelError::new(
                TunnelErrorCode::RoutingConfigurationFailed,
                e.to_string(),
            ));
        }
        if let Err(e) = manager
            .apply_dns(&tun_name, config.tun_gateway_ipv4)
            .await
        {
            cancel.cancel();
            for h in loop_handles.drain(..) {
                h.abort();
            }
            let _ = manager.restore_all(&journal).await;
            let _ = journal::mark_inactive(&journal_path);
            self.publish_error(TunnelErrorCode::DnsConfigurationFailed, e.to_string())
                .await;
            return Err(TunnelError::new(
                TunnelErrorCode::DnsConfigurationFailed,
                e.to_string(),
            ));
        }

        self.publish(TunnelState::VerifyingExitNode {
            proxy_id: config.proxy_id.clone(),
        })
        .await;

        let exit = match verify_exit_node(
            &endpoint.read().await.clone(),
            None,
            Duration::from_secs(6),
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                cancel.cancel();
                for h in loop_handles.drain(..) {
                    h.abort();
                }
                let _ = manager.restore_all(&journal).await;
                let _ = journal::mark_inactive(&journal_path);
                let code = match e {
                    HealthError::Upstream(_) | HealthError::UpstreamRejected(_) => {
                        TunnelErrorCode::UpstreamProxyUnreachable
                    }
                    HealthError::Verification(_) => TunnelErrorCode::ExitVerificationFailed,
                };
                self.publish_error(code, e.to_string()).await;
                return Err(TunnelError::new(code, e.to_string()));
            }
        };

        let journal = Arc::new(Mutex::new(journal));
        let connected_since_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let state = TunnelState::Connected {
            proxy_id: config.proxy_id.clone(),
            exit_ip: exit.exit_ip.clone(),
            country_code: None,
            isp: None,
            latency_ms: exit.latency_ms,
            connected_since_unix,
            mode: TunnelMode::Layer3Tun,
        };

        // Health + network-change monitor.
        let phys = Arc::new(RwLock::new(phys));
        let shared_config = Arc::new(RwLock::new(config.clone()));
        let monitor = self.spawn_monitor(MonitorContext {
            config: shared_config.clone(),
            manager: manager.clone(),
            journal: journal.clone(),
            journal_path: journal_path.clone(),
            endpoint: endpoint_arc,
            bypass: bypass_arc,
            phys: phys.clone(),
            stats: stats.clone(),
            connected_since_unix,
        });
        loop_handles.push(monitor);

        *slot = Some(ActiveTunnel {
            cancel,
            handles: loop_handles,
            journal,
            journal_path,
            manager,
            config: shared_config,
            phys,
            endpoint: endpoint.clone(),
            tun_name,
            telemetry: self.telemetry_tx.clone(),
        });
        self.publish(state).await;
        Ok(())
    }

    /// Android path: the VpnService has already created and configured the TUN
    /// device; VpnService.Builder owns routes and DNS.
    pub async fn start_with_device(
        self: &Arc<Self>,
        config: TunnelConfig,
        device: tun_rs::AsyncDevice,
    ) -> Result<(), TunnelError> {
        let mut slot = self.active.lock().await;
        if slot.is_some() {
            return Err(TunnelError::new(
                TunnelErrorCode::InternalError,
                "a tunnel is already active",
            ));
        }
        if let Err(e) = config.validate() {
            self.publish_error(TunnelErrorCode::InternalError, e.clone()).await;
            return Err(TunnelError::new(TunnelErrorCode::InternalError, e));
        }
        self.fake_dns.clear();
        self.publish(TunnelState::ConfiguringRoutes {
            proxy_id: config.proxy_id.clone(),
        })
        .await;

        let endpoint = Arc::new(RwLock::new(Socks5Endpoint {
            bridge: config.socks5_bridge_addr,
            username: config.socks5_username.clone(),
            password: config.socks5_password.clone(),
        }));
        let bypass = Arc::new(RwLock::new(None));

        let PacketLoop {
            cancel,
            handles: mut loop_handles,
            endpoint: endpoint_arc,
            bypass: bypass_arc,
            stats,
        } = self.spawn_packet_loop(&config, device, endpoint.clone(), bypass.clone());

        self.publish(TunnelState::VerifyingExitNode {
            proxy_id: config.proxy_id.clone(),
        })
        .await;
        let exit = match verify_exit_node(
            &endpoint.read().await.clone(),
            None,
            Duration::from_secs(6),
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                cancel.cancel();
                for h in loop_handles.drain(..) {
                    h.abort();
                }
                let code = match e {
                    HealthError::Upstream(_) | HealthError::UpstreamRejected(_) => {
                        TunnelErrorCode::UpstreamProxyUnreachable
                    }
                    HealthError::Verification(_) => TunnelErrorCode::ExitVerificationFailed,
                };
                self.publish_error(code, e.to_string()).await;
                return Err(TunnelError::new(code, e.to_string()));
            }
        };

        let journal = Arc::new(Mutex::new(RollbackJournal::new(
            config.proxy_id.clone(),
            "android",
            "android",
            0,
            "",
            config.upstream_relay_ip.to_string(),
            Vec::new(),
        )));
        let journal_path = std::path::PathBuf::from("/dev/null");
        let manager: Arc<dyn PlatformRouteManager> = Arc::from(platform::current());
        let connected_since_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let state = TunnelState::Connected {
            proxy_id: config.proxy_id.clone(),
            exit_ip: exit.exit_ip.clone(),
            country_code: None,
            isp: None,
            latency_ms: exit.latency_ms,
            connected_since_unix,
            mode: TunnelMode::Layer3Tun,
        };
        let android_phys = Arc::new(RwLock::new(PhysicalInterfaceInfo {
            name: "android".into(),
            index: 0,
            gateway_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }));
        let shared_config = Arc::new(RwLock::new(config.clone()));
        loop_handles.push(self.spawn_monitor(MonitorContext {
            config: shared_config.clone(),
            manager: manager.clone(),
            journal: journal.clone(),
            journal_path: journal_path.clone(),
            endpoint: endpoint_arc,
            bypass: bypass_arc,
            phys: android_phys.clone(),
            stats: stats.clone(),
            connected_since_unix,
        }));

        *slot = Some(ActiveTunnel {
            cancel,
            handles: loop_handles,
            journal,
            journal_path,
            manager,
            config: shared_config,
            phys: android_phys,
            endpoint: endpoint.clone(),
            tun_name: "android".into(),
            telemetry: self.telemetry_tx.clone(),
        });
        self.publish(state).await;
        Ok(())
    }

    /// Zero-downtime proxy switch. The TUN adapter and packet loop are never
    /// recreated; only the `Arc<RwLock<Socks5Endpoint>>` target is swapped.
    pub async fn hot_swap(&self, config: TunnelConfig) -> Result<(), TunnelError> {
        let mut slot = self.active.lock().await;
        let active = slot.as_mut().ok_or_else(|| {
            TunnelError::new(TunnelErrorCode::InternalError, "no active tunnel to swap")
        })?;
        if let Err(e) = config.validate() {
            return Err(TunnelError::new(TunnelErrorCode::InternalError, e));
        }
        let proxy_id = config.proxy_id.clone();
        let old_endpoint = active.endpoint.read().await.clone();
        let old_relay = active.config.read().await.upstream_relay_ip;
        let new_endpoint = Socks5Endpoint {
            bridge: config.socks5_bridge_addr,
            username: config.socks5_username.clone(),
            password: config.socks5_password.clone(),
        };

        let phys = active.phys.read().await.clone();
        if old_relay != config.upstream_relay_ip {
            // Pin the new relay host route before dropping the old one.
            if let Err(e) = active
                .manager
                .repin_relay_route(config.upstream_relay_ip, &phys)
                .await
            {
                return Err(TunnelError::new(
                    TunnelErrorCode::RoutingConfigurationFailed,
                    e.to_string(),
                ));
            }
        }

        *active.endpoint.write().await = new_endpoint.clone();
        *active.config.write().await = config.clone();
        {
            let mut journal = active.journal.lock().await;
            journal.upstream_relay_ip = config.upstream_relay_ip.to_string();
            let _ = journal::write(&active.journal_path, &journal);
        }

        let exit = match verify_exit_node(&new_endpoint, None, Duration::from_secs(6)).await {
            Ok(info) => info,
            Err(e) => {
                // Revert atomically; existing flows on the new proxy are
                // already dead, but new flows go back to the working proxy.
                *active.endpoint.write().await = old_endpoint;
                active.config.write().await.upstream_relay_ip = old_relay;
                return Err(TunnelError::new(
                    TunnelErrorCode::ExitVerificationFailed,
                    format!("hot swap verification failed: {e}"),
                ));
            }
        };

        if old_relay != config.upstream_relay_ip {
            active
                .manager
                .remove_relay_route(old_relay, &phys)
                .await;
            let mut journal = active.journal.lock().await;
            journal.upstream_relay_ip = config.upstream_relay_ip.to_string();
            let _ = journal::write(&active.journal_path, &journal);
        }

        let state = TunnelState::Connected {
            proxy_id,
            exit_ip: exit.exit_ip,
            country_code: None,
            isp: None,
            latency_ms: exit.latency_ms,
            connected_since_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            mode: TunnelMode::Layer3Tun,
        };
        self.publish(state).await;
        Ok(())
    }

    /// Tear down the tunnel and restore every route/DNS change.
    pub async fn stop(&self) -> Result<(), TunnelError> {
        let mut slot = self.active.lock().await;
        let Some(active) = slot.take() else {
            self.publish(TunnelState::Disconnected).await;
            return Ok(());
        };
        self.publish(TunnelState::Disconnecting).await;

        active.cancel.cancel();
        for handle in active.handles {
            handle.abort();
            // Wait for cancellation to drop the TUN descriptor before routes
            // are removed; this avoids transient "interface busy" errors.
            let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        }

        let journal = active.journal.lock().await.clone();
        let restore = active.manager.restore_all(&journal).await;
        if active.tun_name != "android" {
            let _ = journal::mark_inactive(&active.journal_path);
        }
        platform::flush_dns_cache().await;

        self.fake_dns.clear();
        let _ = active.telemetry.send(Telemetry::default());
        self.publish(TunnelState::Disconnected).await;
        if let Err(e) = restore {
            tracing::warn!(error = %e, "route/DNS restore reported an error");
        }
        Ok(())
    }

    fn spawn_packet_loop(
        self: &Arc<Self>,
        config: &TunnelConfig,
        device: tun_rs::AsyncDevice,
        endpoint: Arc<RwLock<Socks5Endpoint>>,
        bypass: Arc<RwLock<Option<Arc<SocketBypass>>>>,
    ) -> PacketLoop {
        let cancel = Cancel::new();
        let stats = self.stats.clone();
        let filter = Arc::new(PacketFilter::new(
            config.disable_quic_udp_443,
            config.block_webrtc_stun,
            config.mtu.saturating_sub(40),
            self.fake_dns.clone(),
        ));
        let ctx = EngineContext {
            fake_dns: self.fake_dns.clone(),
            endpoint: endpoint.clone(),
            bypass: bypass.clone(),
            stats: stats.clone(),
            cancel: cancel.clone(),
        };

        let (to_stack_tx, to_stack_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (from_stack_tx, mut from_stack_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (to_tun_tx, to_tun_rx) = mpsc::channel::<Vec<u8>>(1024);

        let mut ipstack_cfg = IpStackConfig::default();
        ipstack_cfg
            .mtu(config.mtu)
            .expect("validated MTU is >= 1280");
        let mut tcp_cfg = TcpConfig::default();
        tcp_cfg.timeout = Duration::from_secs(600);
        tcp_cfg.options = Some(vec![ipstack::TcpOptions::MaximumSegmentSize(
            config.mtu.saturating_sub(40),
        )]);
        ipstack_cfg.with_tcp_config(tcp_cfg);
        ipstack_cfg.udp_timeout(Duration::from_secs(10));
        let mut ip_stack = IpStack::new(
            ipstack_cfg,
            PacketDevice {
                rx: to_stack_rx,
                tx: from_stack_tx,
            },
        );

        let mut handles = Vec::new();

        // Single task owns the TUN device: `tun-rs` exposes packet-oriented
        // `recv`/`send` rather than `AsyncRead`/`AsyncWrite`, so reads,
        // synthetic replies and ipstack output are multiplexed here. This also
        // guarantees only one writer ever touches the descriptor.
        {
            let filter = filter.clone();
            let cancel = cancel.clone();
            let ctx = ctx.clone();
            let stats = stats.clone();
            let to_stack_tx = to_stack_tx.clone();
            let to_tun_tx_inner = to_tun_tx.clone();
            let mut to_tun_rx = to_tun_rx;
            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        result = device.recv(&mut buf) => {
                            match result {
                                Ok(0) => {
                                    stats.tun_failed.store(true, Ordering::SeqCst);
                                    cancel.cancel();
                                    break;
                                }
                                Ok(n) => {
                                    let packet = &buf[..n];
                                    match filter.inspect_outbound(packet) {
                                        PacketDecision::Forward(out) => {
                                            if to_stack_tx.send(out).await.is_err() { break; }
                                        }
                                        PacketDecision::Reply(out) => {
                                            if device.send(&out).await.is_err() { break; }
                                        }
                                        PacketDecision::Drop => {}
                                        PacketDecision::ForwardDns { query, original } => {
                                            let ctx = ctx.clone();
                                            let to_tun_tx = to_tun_tx_inner.clone();
                                            tokio::spawn(async move {
                                                resolve_dns_over_tcp(&ctx, &query, &original, to_tun_tx).await;
                                            });
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "TUN device read failed");
                                    stats.tun_failed.store(true, Ordering::SeqCst);
                                    cancel.cancel();
                                    break;
                                }
                            }
                        }
                        packet = to_tun_rx.recv() => {
                            match packet {
                                Some(packet) => {
                                    if device.send(&packet).await.is_err() { break; }
                                }
                                None => break,
                            }
                        }
                    }
                }
            }));
        }

        // ipstack -> inbound MSS clamp -> TUN task.
        {
            let filter = filter.clone();
            let cancel = cancel.clone();
            let to_tun_tx = to_tun_tx.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        packet = from_stack_rx.recv() => {
                            match packet {
                                Some(packet) => {
                                    let out = filter.inspect_inbound(&packet);
                                    if to_tun_tx.send(out).await.is_err() { break; }
                                }
                                None => break,
                            }
                        }
                    }
                }
            }));
        }

        // Accept loop: one task per TCP/UDP flow.
        {
            let cancel = cancel.clone();
            let ctx = ctx.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        stream = ip_stack.accept() => {
                            match stream {
                                Ok(IpStackStream::Tcp(tcp)) => {
                                    let ctx = ctx.clone();
                                    tokio::spawn(async move { handle_tcp(tcp, ctx).await });
                                }
                                Ok(IpStackStream::Udp(udp)) => {
                                    let ctx = ctx.clone();
                                    tokio::spawn(async move { handle_udp(udp, ctx).await });
                                }
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    }
                }
            }));
        }

        PacketLoop {
            cancel,
            handles,
            endpoint,
            bypass,
            stats,
        }
    }

    fn spawn_monitor(self: &Arc<Self>, mon: MonitorContext) -> JoinHandle<()> {
        let state = self.state.clone();
        let state_tx = self.state_tx.clone();
        let telemetry_tx = self.telemetry_tx.clone();
        let stats = mon.stats.clone();
        tokio::spawn(async move {
            run_monitor(mon, state, stats, state_tx, telemetry_tx).await;
        })
    }
}

/// Borrowed monitor configuration.
struct MonitorContext {
    config: Arc<RwLock<TunnelConfig>>,
    manager: Arc<dyn PlatformRouteManager>,
    journal: Arc<Mutex<RollbackJournal>>,
    journal_path: std::path::PathBuf,
    endpoint: Arc<RwLock<Socks5Endpoint>>,
    bypass: Arc<RwLock<Option<Arc<SocketBypass>>>>,
    phys: Arc<RwLock<PhysicalInterfaceInfo>>,
    stats: Arc<Stats>,
    connected_since_unix: u64,
}

async fn run_monitor(
    mon: MonitorContext,
    state: Arc<RwLock<TunnelState>>,
    stats: Arc<Stats>,
    state_tx: broadcast::Sender<TunnelState>,
    telemetry_tx: broadcast::Sender<Telemetry>,
) {
    let mut last_telemetry = (0u64, 0u64);
    let mut telemetry_instant = Instant::now();
    let mut last_wall = SystemTime::now();
    let mut last_network_check = Instant::now();
    let mut last_health = Instant::now();
    let mut failures = 0u32;
    let mut phys = mon.phys.read().await.clone();
    let mut force_health = false;
    let mut tun_dead = false;
    let mut torn_down = false;

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // A hot swap replaces the configuration; always read the current one.
        let current = mon.config.read().await.clone();

        let telemetry = stats.telemetry(&mut last_telemetry, &mut telemetry_instant);
        let _ = telemetry_tx.send(telemetry);

        if stats.tun_failed.swap(false, Ordering::SeqCst) {
            publish(
                &state,
                &state_tx,
                TunnelState::Error {
                    code: TunnelErrorCode::InternalError,
                    message: "The tunnel interface was closed by the operating system".into(),
                },
            )
            .await;
            if !current.kill_switch {
                let journal = mon.journal.lock().await.clone();
                let _ = mon.manager.restore_all(&journal).await;
                let _ = journal::mark_inactive(&mon.journal_path);
                torn_down = true;
            }
            tun_dead = true;
            continue;
        }

        if tun_dead || torn_down {
            continue;
        }

        if stats.quota_exhausted.swap(false, Ordering::SeqCst) {
            publish(
                &state,
                &state_tx,
                TunnelState::Error {
                    code: TunnelErrorCode::QuotaExhausted,
                    message: "Proxy session ended: bandwidth quota or lease exhausted".into(),
                },
            )
            .await;
            if !current.kill_switch {
                let journal = mon.journal.lock().await.clone();
                let _ = mon.manager.restore_all(&journal).await;
                let _ = journal::mark_inactive(&mon.journal_path);
                torn_down = true;
            }
            continue;
        }

        // Sleep / hibernate detection: wall clock jumps while the monotonic
        // timer only advanced by ~1s.
        let now_wall = SystemTime::now();
        let wall_delta = now_wall
            .duration_since(last_wall)
            .unwrap_or(Duration::ZERO);
        last_wall = now_wall;
        if wall_delta > Duration::from_secs(15) {
            let proxy_id = match &*state.read().await {
                TunnelState::Connected { proxy_id, .. } => proxy_id.clone(),
                _ => current.proxy_id.clone(),
            };
            publish(
                &state,
                &state_tx,
                TunnelState::Reconnecting {
                    proxy_id,
                    attempt: 1,
                    last_error: "system resumed from sleep".into(),
                },
            )
            .await;
            force_health = true;
        }

        if last_network_check.elapsed() >= Duration::from_secs(10)
            && mon.manager.platform_name() != "android"
        {
            last_network_check = Instant::now();
            if let Ok(new_phys) = mon.manager.detect_physical_route().await {
                if new_phys != phys {
                    tracing::info!(
                        old = %phys.name,
                        new = %new_phys.name,
                        "physical network changed; re-pinning relay route"
                    );
                    if let Err(e) = mon
                        .manager
                        .repin_relay_route(current.upstream_relay_ip, &new_phys)
                        .await
                    {
                        tracing::warn!(error = %e, "failed to re-pin relay route");
                    } else {
                        *mon.bypass.write().await = Some(Arc::new(SocketBypass::new(new_phys.clone())));
                        {
                            let mut journal = mon.journal.lock().await;
                            journal.physical_interface = new_phys.name.clone();
                            journal.physical_interface_index = new_phys.index;
                            journal.original_gateway = new_phys.gateway_ip.to_string();
                            let _ = journal::write(&mon.journal_path, &journal);
                        }
                        *mon.phys.write().await = new_phys.clone();
                        phys = new_phys.clone();
                        let tun_interface = mon.journal.lock().await.tun_interface.clone();
                        if let Err(e) = mon
                            .manager
                            .refresh_dns_guard(&tun_interface, current.tun_gateway_ipv4)
                            .await
                        {
                            tracing::warn!(error = %e, "failed to re-assert DNS guard after network change");
                        }
                        publish(
                            &state,
                            &state_tx,
                            TunnelState::Reconnecting {
                                proxy_id: current.proxy_id.clone(),
                                attempt: 1,
                                last_error: "network interface changed".into(),
                            },
                        )
                        .await;
                        force_health = true;
                    }
                }
            }
        }

        if force_health || last_health.elapsed() >= Duration::from_secs(30) {
            force_health = false;
            last_health = Instant::now();
            let endpoint = mon.endpoint.read().await.clone();
            match verify_exit_node(&endpoint, None, Duration::from_secs(6)).await {
                Ok(info) => {
                    failures = 0;
                    publish(
                        &state,
                        &state_tx,
                        TunnelState::Connected {
                            proxy_id: current.proxy_id.clone(),
                            exit_ip: info.exit_ip,
                            country_code: None,
                            isp: None,
                            latency_ms: info.latency_ms,
                            connected_since_unix: mon.connected_since_unix,
                            mode: TunnelMode::Layer3Tun,
                        },
                    )
                    .await;
                }
                Err(HealthError::UpstreamRejected(code)) if code == 0x02 => {
                    publish(
                        &state,
                        &state_tx,
                        TunnelState::Error {
                            code: TunnelErrorCode::QuotaExhausted,
                            message: "Proxy session ended: bandwidth quota or lease exhausted"
                                .into(),
                        },
                    )
                    .await;
                    if !current.kill_switch {
                        let journal = mon.journal.lock().await.clone();
                        let _ = mon.manager.restore_all(&journal).await;
                        let _ = journal::mark_inactive(&mon.journal_path);
                    }
                }
                Err(e) => {
                    failures += 1;
                    if failures >= 3 {
                        publish(
                            &state,
                            &state_tx,
                            TunnelState::Error {
                                code: TunnelErrorCode::ExitVerificationFailed,
                                message: format!(
                                    "upstream proxy is unreachable (quota may be exhausted): {e}"
                                ),
                            },
                        )
                        .await;
                        if !current.kill_switch {
                            let journal = mon.journal.lock().await.clone();
                            let _ = mon.manager.restore_all(&journal).await;
                            let _ = journal::mark_inactive(&mon.journal_path);
                            torn_down = true;
                        }
                        // Keep monitoring so a network change can recover.
                        failures = 0;
                        last_health = Instant::now();
                    } else {
                        publish(
                            &state,
                            &state_tx,
                            TunnelState::Reconnecting {
                                proxy_id: current.proxy_id.clone(),
                                attempt: failures,
                                last_error: e.to_string(),
                            },
                        )
                        .await;
                    }
                }
            }
        }
    }
}

async fn publish(
    state: &Arc<RwLock<TunnelState>>,
    tx: &broadcast::Sender<TunnelState>,
    next: TunnelState,
) {
    *state.write().await = next.clone();
    let _ = tx.send(next);
}

async fn handle_tcp(mut tcp: IpStackTcpStream, ctx: EngineContext) {
    let peer = tcp.peer_addr();
    let target = match target_for(&ctx.fake_dns, peer) {
        Some(t) => t,
        None => {
            tracing::warn!(dst = %peer, "fake-IP destination has no mapping; resetting");
            let _ = tcp.shutdown().await;
            return;
        }
    };
    let endpoint = ctx.endpoint().await;
    let bypass = ctx.bypass_snapshot().await;
    let upstream = tokio::select! {
        _ = ctx.cancel.cancelled() => return,
        res = connect_via_socks(&endpoint, &target, bypass.as_deref(), Duration::from_secs(10)) => res,
    };
    let upstream = match upstream {
        Ok(s) => s,
        Err(e) => {
            if let crate::tunnel::socks5::Socks5Error::ConnectFailed(code) = &e {
                // 0x02 = connection not allowed by ruleset. The bridge uses
                // this for a rejected session credential. 0x05 is a normal
                // target refusal and must not be mistaken for quota loss.
                if *code == 0x02 {
                    ctx.stats.quota_exhausted.store(true, Ordering::SeqCst);
                }
            }
            tracing::debug!(dst = %peer, target = %target.host_string(), error = %e, "SOCKS5 connect failed");
            let _ = tcp.shutdown().await;
            return;
        }
    };

    ctx.stats.flows.fetch_add(1, Ordering::Relaxed);
    let mut app = ReadCounter {
        inner: tcp,
        stats: ctx.stats.clone(),
        tx: true,
    };
    let mut remote = ReadCounter {
        inner: upstream,
        stats: ctx.stats.clone(),
        tx: false,
    };
    let _ = tokio::select! {
        _ = ctx.cancel.cancelled() => None,
        res = tokio::time::timeout(
            Duration::from_secs(600),
            tokio::io::copy_bidirectional(&mut app, &mut remote),
        ) => res.ok(),
    };
    ctx.stats.flows.fetch_sub(1, Ordering::Relaxed);
}

async fn handle_udp(mut udp: IpStackUdpStream, ctx: EngineContext) {
    let peer = udp.peer_addr();
    let target = match target_for(&ctx.fake_dns, peer) {
        Some(t) => t,
        None => return,
    };
    let endpoint = ctx.endpoint().await;
    // The local bridge currently implements CONNECT only; a failure here is
    // expected and the datagram is dropped.
    let (control, relay) = match udp_associate(&endpoint, Duration::from_secs(5)).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(dst = %peer, error = %e, "UDP ASSOCIATE unavailable; dropping flow");
            return;
        }
    };
    let bind: SocketAddr = if relay.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if socket.connect(relay).await.is_err() {
        return;
    }
    ctx.stats.flows.fetch_add(1, Ordering::Relaxed);
    let mut up_buf = vec![0u8; 65_535];
    let mut down_buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            res = udp.read(&mut up_buf) => {
                let n = match res { Ok(n) if n > 0 => n, _ => break };
                let Ok(packet) = encode_udp_datagram(&target, &up_buf[..n]) else { break };
                let _ = socket.send(&packet).await;
                ctx.stats.tx.fetch_add(n as u64, Ordering::Relaxed);
            }
            res = socket.recv(&mut down_buf) => {
                let n = match res { Ok(n) if n > 0 => n, _ => break };
                let Ok(payload) = decode_udp_datagram(&down_buf[..n]) else { continue };
                ctx.stats.rx.fetch_add(payload.len() as u64, Ordering::Relaxed);
                if udp.write_all(&payload).await.is_err() { break; }
            }
        }
    }
    ctx.stats.flows.fetch_sub(1, Ordering::Relaxed);
    drop(control);
}

fn target_for(fake_dns: &FakeDns, peer: SocketAddr) -> Option<TargetAddr> {
    match peer.ip() {
        IpAddr::V4(v4) if fake_dns.is_fake_ip(v4) => fake_dns
            .reverse_lookup(v4)
            .map(|name| TargetAddr::domain(name, peer.port())),
        ip => Some(TargetAddr::ip(ip, peer.port())),
    }
}

async fn resolve_dns_over_tcp(
    ctx: &EngineContext,
    query: &[u8],
    original: &[u8],
    to_tun: mpsc::Sender<Vec<u8>>,
) {
    let endpoint = ctx.endpoint().await;
    let bypass = ctx.bypass_snapshot().await;
    let result = tokio::time::timeout(Duration::from_secs(6), async {
        let mut stream = connect_via_socks(
            &endpoint,
            &TargetAddr::ip(DNS_OVER_TCP_SERVER.ip(), DNS_OVER_TCP_SERVER.port()),
            bypass.as_deref(),
            Duration::from_secs(5),
        )
        .await
        .ok()?;
        if query.len() > u16::MAX as usize {
            return None;
        }
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await.ok()?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.ok()?;
        let mut response = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut response).await.ok()?;
        Some(response)
    })
    .await
    .ok()
    .flatten();

    let Some(response) = result else {
        tracing::debug!("DNS-over-TCP forwarding failed");
        return;
    };
    let Some(info) = parse(original) else {
        return;
    };
    if let Some(reply) = build_udp_response(original, &info, &response) {
        let _ = to_tun.send(reply).await;
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn route_list(nets: &[ipnet::IpNet]) -> Vec<String> {
    let mut out: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
    out.push(TUN_IPV6_CIDR.to_string());
    for net in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
        out.push(net.to_string());
    }
    out
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn create_desktop_device(cfg: &TunnelConfig) -> std::io::Result<tun_rs::AsyncDevice> {
    #[cfg(target_os = "macos")]
    let builder = tun_rs::DeviceBuilder::new().with(|opt| {
        // Route setup is ours; tun-rs must not install its own default route.
        opt.associate_route(false);
    });
    #[cfg(target_os = "linux")]
    let builder = tun_rs::DeviceBuilder::new().name("proxybase0");
    #[cfg(target_os = "windows")]
    let builder = {
        let mut b = tun_rs::DeviceBuilder::new();
        b.name("ProxyBase");
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let wintun_path = dir.join("wintun.dll");
                if wintun_path.exists() {
                    b.wintun_file(wintun_path.to_string_lossy().to_string());
                }
            }
        }
        b
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let builder = tun_rs::DeviceBuilder::new();

    builder
        .ipv4(cfg.tun_ipv4, cfg.tun_prefix, None)
        .ipv6(TUN_IPV6_ADDRESS, 64)
        .mtu(cfg.mtu)
        .enable(true)
        .build_async()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::fake_dns::FakeDns;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn mock_socks_server(tag: u8) -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 2];
            socket.read_exact(&mut greet).await.unwrap();
            let mut methods = vec![0u8; greet[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            socket.read_exact(&mut head).await.unwrap();
            let host = match head[3] {
                0x03 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    let mut name = vec![0u8; len[0] as usize];
                    socket.read_exact(&mut name).await.unwrap();
                    String::from_utf8(name).unwrap()
                }
                0x01 => {
                    let mut b = [0u8; 4];
                    socket.read_exact(&mut b).await.unwrap();
                    Ipv4Addr::from(b).to_string()
                }
                _ => unreachable!(),
            };
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).await.unwrap();
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let _ = tx.send(format!("{tag}:{host}:{}", u16::from_be_bytes(port)));
            let mut buf = [0u8; 16];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let _ = socket.write_all(&buf[..n]).await;
            let _ = tag;
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn test_zero_downtime_proxy_hot_swap() {
        let (server_a, target_a) = mock_socks_server(1).await;
        let (server_b, target_b) = mock_socks_server(2).await;
        let endpoint = Arc::new(RwLock::new(Socks5Endpoint::new(server_a)));
        let dns = Arc::new(FakeDns::new());
        let fake = dns.allocate("switch.example.com");

        let first = {
            let ep = endpoint.read().await.clone();
            connect_via_socks(
                &ep,
                &TargetAddr::domain(dns.reverse_lookup(fake).unwrap(), 443),
                None,
                Duration::from_secs(3),
            )
            .await
            .unwrap()
        };
        assert!(target_a.await.unwrap().starts_with("1:"));

        *endpoint.write().await = Socks5Endpoint::new(server_b);
        let second = {
            let ep = endpoint.read().await.clone();
            connect_via_socks(
                &ep,
                &TargetAddr::domain(dns.reverse_lookup(fake).unwrap(), 443),
                None,
                Duration::from_secs(3),
            )
            .await
            .unwrap()
        };
        assert!(target_b.await.unwrap().starts_with("2:"));
        drop(first);
        drop(second);
    }
}
