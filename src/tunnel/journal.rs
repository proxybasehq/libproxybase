//! Crash-recovery journal.
//!
//! Before the daemon touches a route or a DNS setting it records enough state
//! to undo every change. The file is written atomically (`write temp -> fsync
//! -> rename`) so a power loss can never leave a half-written journal.
//!
//! On the next start — including after `kill -9`, a kernel panic, or a reboot —
//! `recover_if_dirty()` restores the original state before serving IPC.

use crate::tunnel::platform::PlatformRouteManager;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk rollback state. The first block of fields is the documented
/// schema; the extra fields make restores exact on platforms that need more
/// context (WFP session, policy-routing table, ...).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackJournal {
    pub active: bool,
    pub session_id: String,
    pub tun_interface: String,
    pub physical_interface: String,
    pub physical_interface_index: u32,
    pub original_gateway: String,
    pub upstream_relay_ip: String,
    pub original_dns_servers: Vec<String>,
    pub linux_resolv_backup_path: Option<String>,
    pub created_at_unix: u64,

    /// CIDRs/routes added while bringing the tunnel up.
    #[serde(default)]
    pub routes_added: Vec<String>,
    /// `systemd-resolved`, `resolv.conf`, `scutil`, `windows`, `android`.
    #[serde(default)]
    pub dns_mode: Option<String>,
    /// Linux policy-routing table used for firewalled/`SO_MARK`ed sockets.
    #[serde(default)]
    pub linux_route_table: Option<u32>,
    /// Whether a dynamic WFP session is blocking DNS on physical adapters.
    #[serde(default)]
    pub windows_wfp_active: bool,
    /// The TUN subnet, recorded so recovery can remove its routes precisely.
    #[serde(default)]
    pub tun_ipv4_cidr: Option<String>,
}

impl RollbackJournal {
    pub fn new(
        session_id: impl Into<String>,
        tun_interface: impl Into<String>,
        physical_interface: impl Into<String>,
        physical_interface_index: u32,
        original_gateway: impl Into<String>,
        upstream_relay_ip: impl Into<String>,
        original_dns_servers: Vec<String>,
    ) -> Self {
        Self {
            active: true,
            session_id: session_id.into(),
            tun_interface: tun_interface.into(),
            physical_interface: physical_interface.into(),
            physical_interface_index,
            original_gateway: original_gateway.into(),
            upstream_relay_ip: upstream_relay_ip.into(),
            original_dns_servers,
            linux_resolv_backup_path: None,
            created_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            routes_added: Vec::new(),
            dns_mode: None,
            linux_route_table: None,
            windows_wfp_active: false,
            tun_ipv4_cidr: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("journal rollback failed: {0}")]
    Restore(String),
    #[error("journal path has no parent directory: {0}")]
    NoParent(String),
}

/// Platform journal path.
pub fn default_journal_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("ProxyBase").join("tunnel_journal.json")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/lib/proxybase/tunnel_journal.json")
    }
}

/// Atomically persist `journal`.
pub fn write(path: &Path, journal: &RollbackJournal) -> Result<(), JournalError> {
    let parent = path
        .parent()
        .ok_or_else(|| JournalError::NoParent(path.display().to_string()))?;
    std::fs::create_dir_all(parent)?;
    let json = serde_json::to_vec_pretty(journal)?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("tunnel_journal"),
        std::process::id()
    ));

    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Persist the rename itself (directory fsync). Unix only.
    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Read a journal if it exists.
pub fn read(path: &Path) -> Result<Option<RollbackJournal>, JournalError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Restore a dirty journal through the supplied platform manager, then mark it
/// inactive. Safe to call when there is nothing to do.
pub async fn recover_if_dirty_with(
    manager: &dyn PlatformRouteManager,
    path: &Path,
) -> Result<bool, JournalError> {
    let Some(mut journal) = read(path)? else {
        return Ok(false);
    };
    if !journal.active {
        return Ok(false);
    }
    tracing::warn!(
        session = %journal.session_id,
        tun = %journal.tun_interface,
        "recovering dirty tunnel journal from a previous crash"
    );
    if let Err(e) = manager.restore_all(&journal).await {
        // Keep `active: true` so a later attempt (or a fixed build) retries.
        return Err(JournalError::Restore(e.to_string()));
    }
    journal.active = false;
    write(path, &journal)?;
    Ok(true)
}

/// Restore using the current platform's manager.
pub async fn recover_if_dirty() -> Result<bool, JournalError> {
    let manager = crate::tunnel::platform::current();
    let path = default_journal_path();
    recover_if_dirty_with(manager.as_ref(), &path).await
}

/// Mark the persistent journal inactive after a clean teardown.
pub fn mark_inactive(path: &Path) -> Result<(), JournalError> {
    if let Some(mut journal) = read(path)? {
        journal.active = false;
        write(path, &journal)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::platform::PlatformRouteManager;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct MockManager {
        restores: Arc<AtomicUsize>,
        fail: bool,
    }

    #[async_trait]
    impl PlatformRouteManager for MockManager {
        async fn detect_physical_route(
            &self,
        ) -> anyhow::Result<crate::tunnel::socket_bypass::PhysicalInterfaceInfo> {
            unreachable!()
        }
        async fn apply_routes(
            &self,
            _tun_name: &str,
            _phys: &crate::tunnel::socket_bypass::PhysicalInterfaceInfo,
            _cfg: &crate::tunnel::config::TunnelConfig,
        ) -> anyhow::Result<()> {
            unreachable!()
        }
        async fn apply_dns(
            &self,
            _tun_name: &str,
            _dns_ip: std::net::Ipv4Addr,
        ) -> anyhow::Result<()> {
            unreachable!()
        }
        async fn restore_all(&self, _journal: &RollbackJournal) -> anyhow::Result<()> {
            self.restores.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("simulated restore failure");
            }
            Ok(())
        }
        fn platform_name(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_rollback_journal_crash_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tunnel_journal.json");
        let mut journal = RollbackJournal::new(
            "session-1",
            "utun7",
            "en0",
            6,
            "192.168.1.1",
            "149.28.45.112",
            vec!["192.168.1.1".into(), "1.1.1.1".into()],
        );
        journal.linux_resolv_backup_path = None;
        write(&path, &journal).unwrap();

        let restores = Arc::new(AtomicUsize::new(0));
        let manager = MockManager {
            restores: restores.clone(),
            fail: false,
        };
        assert!(recover_if_dirty_with(&manager, &path).await.unwrap());
        assert_eq!(restores.load(Ordering::SeqCst), 1);

        let after = read(&path).unwrap().unwrap();
        assert!(!after.active);
        assert_eq!(after.session_id, "session-1");

        // Second run is a no-op.
        assert!(!recover_if_dirty_with(&manager, &path).await.unwrap());
        assert_eq!(restores.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_restore_keeps_journal_dirty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tunnel_journal.json");
        let journal =
            RollbackJournal::new("s", "utun1", "en0", 4, "10.0.0.1", "1.2.3.4", vec![]);
        write(&path, &journal).unwrap();
        let manager = MockManager {
            restores: Arc::new(AtomicUsize::new(0)),
            fail: true,
        };
        assert!(recover_if_dirty_with(&manager, &path).await.is_err());
        assert!(read(&path).unwrap().unwrap().active);
    }

    #[test]
    fn write_is_atomic_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.json");
        let journal =
            RollbackJournal::new("s", "utun1", "en0", 4, "10.0.0.1", "1.2.3.4", vec![]);
        write(&path, &journal).unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("j.json")]);
        assert_eq!(read(&path).unwrap().unwrap(), journal);
    }
}
