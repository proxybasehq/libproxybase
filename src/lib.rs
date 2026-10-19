pub mod config;
pub mod governor;
pub mod market;
pub mod network;
pub mod proxy;
pub mod shutdown;
pub mod telemetry;
pub mod tunnel;
pub mod updater;
pub mod wallet;

use anyhow::Result;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::watch;

pub use config::Config;
pub use wallet::WalletManager;

/// Top-level engine composing all modules.
pub struct Engine {
    pub config: Config,
    pub wallet: WalletManager,
    pub market: market::MarketClient,
    pub network: network::NetworkEngine,
    pub proxy: proxy::ProxyServer,
    pub governor: governor::ResourceGovernor,
    pub telemetry: telemetry::TelemetryWorker,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl Engine {
    /// Create a new Engine with the given configuration.
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize tracing
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| {
                        tracing_subscriber::EnvFilter::new(&config.engine.log_level)
                    }),
            )
            .init();

        let wallet = WalletManager::new(config.wallet.data_dir.clone())?;
        let market_client = market::MarketClient::new(&config.market.backend_url);
        let network = network::NetworkEngine::new();
        let proxy = proxy::ProxyServer::new();
        let governor = governor::ResourceGovernor::new(
            config.limits.max_bandwidth_bytes_per_day,
            config.limits.max_speed_bytes_per_sec,
            config.limits.max_concurrent_streams,
        );
        let telemetry = telemetry::TelemetryWorker::new();
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        Ok(Self {
            config,
            wallet,
            market: market_client,
            network,
            proxy,
            governor,
            telemetry,
            shutdown_tx,
        })
    }

    /// Run the engine — connect to the market, authenticate, and start all subsystems.
    pub async fn run_until_shutdown(mut self) -> Result<()> {
        // Start shutdown signal listener
        let shutdown_signal = crate::shutdown::listen_for_shutdown();
        let tx = self.shutdown_tx.clone();

        tokio::spawn(async move {
            shutdown_signal.await;
            tracing::info!("Shutdown signal received");
            let _ = tx.send(true);
        });

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        // Try to authenticate if wallet is loaded
        if self.wallet.is_loaded() {
            let addr = self.wallet.address().unwrap_or("unknown");
            tracing::info!("Wallet loaded: {}", addr);

            match self.market.request_challenge(addr).await {
                Ok(challenge) => {
                    let message = format!(
                        "{}:{}:{}",
                        addr, challenge.nonce, challenge.timestamp
                    );
                    match self.wallet.sign(message.as_bytes()) {
                        Ok(sig) => {
                            let sig_hex = hex::encode(&sig);
                            let pk_hex = addr.trim_start_matches("0x");

                            match self
                                .market
                                .verify_challenge(pk_hex, &challenge.nonce, &challenge.timestamp, &sig_hex)
                                .await
                            {
                                Ok(auth) => {
                                    tracing::info!(
                                        "Authenticated as {} (role: {}, spendable: {})",
                                        auth.wallet_address,
                                        auth.role,
                                        auth.spendable_balance
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!("Authentication failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to sign challenge: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to request challenge (backend unreachable?): {}", e);
                }
            }
        }

        // Start SOCKS5 local proxy for buyer role (deferred until backend WS session is active)
        let proxy_port: Option<u16> = None;
        if self.config.market.role == "buyer" || self.config.market.role == "dual" {
            tracing::info!(
                "Buyer role active. Use the backend session to open a proxy session, then connect your browser to the local SOCKS5 port."
            );
        }

        // Start telemetry keepalive + heartbeat
        let keepalive_handle = tokio::spawn(async move {
            crate::telemetry::keepalive::run_keepalive(move || true).await;
        });

        if let Some(port) = proxy_port {
            tracing::info!("ProxyBase engine running. SOCKS5 proxy: 127.0.0.1:{}", port);
        } else {
            tracing::info!("ProxyBase engine running (no local proxy).");
        }

        // Main event loop — wait for shutdown signal
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Shutting down...");
                        break;
                    }
                }
            }
        }

        keepalive_handle.abort();
        self.proxy.stop();
        Ok(())
    }

    /// Get the shutdown sender for programmatic shutdown.
    pub fn shutdown_handle(&self) -> tokio::sync::watch::Sender<bool> {
        self.shutdown_tx.clone()
    }
}
