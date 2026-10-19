//! Loop-prevention layer 1: bind outbound relay sockets to the physical NIC
//! (or, on Android, hand the descriptor to `VpnService.protect`) *before*
//! `connect()`.
//!
//! When `0.0.0.0/1` and `128.0.0.0/1` are routed into the TUN device, a relay
//! socket that is not bound to the physical interface would itself be routed
//! back into the TUN, producing an infinite loop. Route pinning (layer 2) is
//! the primary defence; this is defence in depth, and the only defence on
//! Android where the OS selects the interface.

use socket2::Socket;
use std::io;
use std::net::IpAddr;

/// Information about the physical interface currently carrying the default
/// route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalInterfaceInfo {
    pub name: String,
    pub index: u32,
    pub gateway_ip: IpAddr,
}

/// Trait used on Android to invoke `VpnService.protect(fd)` via JNI. On
/// desktop the engine passes [`NoopSocketProtector`].
pub trait AndroidSocketProtector: Send + Sync {
    fn protect_fd(&self, fd: i32) -> bool;
}

/// Desktop / non-Android placeholder.
pub struct NoopSocketProtector;

impl AndroidSocketProtector for NoopSocketProtector {
    fn protect_fd(&self, _fd: i32) -> bool {
        true
    }
}

/// Bind `socket` to the physical interface described by `phys`.
///
/// The socket must be created but not yet connected. On Linux the interface
/// name is applied with `SO_BINDTODEVICE` and `SO_MARK = 0x5042` is set as a
/// policy-routing backup. On macOS `IP_BOUND_IF`/`IPV6_BOUND_IF` are applied.
/// On Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF` are used (network byte order).
pub fn bind_socket_to_physical_interface(
    socket: &Socket,
    phys: &PhysicalInterfaceInfo,
    protector: &dyn AndroidSocketProtector,
) -> io::Result<()> {
    #[cfg(not(target_os = "android"))]
    let _ = protector;
    #[cfg(target_os = "android")]
    let _ = phys;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        socket.bind_device(Some(phys.name.as_bytes()))?;

        // SO_MARK requires CAP_NET_ADMIN. It is a backup for policy routing,
        // so a failure here must not abort an otherwise healthy tunnel.
        let mark: u32 = 0x5042;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            tracing::debug!(
                interface = %phys.name,
                error = %io::Error::last_os_error(),
                "SO_MARK could not be set (policy-routing backup unavailable)"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;

        let idx = phys.index as libc::c_uint;
        let v4_ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                &idx as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        };
        if v4_ret == 0 {
            return Ok(());
        }
        let v4_err = io::Error::last_os_error();

        // IPV6_BOUND_IF is not exposed by every libc version.
        #[cfg(target_os = "macos")]
        const IPV6_BOUND_IF: libc::c_int = 125;
        let v6_ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_BOUND_IF,
                &idx as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        };
        if v6_ret == 0 {
            return Ok(());
        }
        Err(v4_err)
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, IPV6_UNICAST_IF,
        };

        // Windows requires the interface index in network byte order for both
        // IPv4 and IPv6 IP_*_UNICAST_IF options.
        let if_index_be = phys.index.to_be();
        let raw = socket.as_raw_socket() as usize;
        let v4_ret = unsafe {
            setsockopt(
                raw as _,
                IPPROTO_IP as i32,
                IP_UNICAST_IF as i32,
                &if_index_be as *const _ as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if v4_ret == 0 {
            return Ok(());
        }
        let v4_err = io::Error::last_os_error();
        let v6_ret = unsafe {
            setsockopt(
                raw as _,
                IPPROTO_IPV6 as i32,
                IPV6_UNICAST_IF as i32,
                &if_index_be as *const _ as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if v6_ret == 0 {
            return Ok(());
        }
        Err(v4_err)
    }

    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        if !protector.protect_fd(socket.as_raw_fd()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android VpnService.protect(fd) returned false",
            ));
        }
        Ok(())
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    )))]
    {
        let _ = (socket, phys, protector);
        Ok(())
    }
}

static GLOBAL_ANDROID_PROTECTOR: std::sync::RwLock<
    Option<std::sync::Arc<dyn AndroidSocketProtector>>,
> = std::sync::RwLock::new(None);

/// Install (or replace) the process-wide JNI `VpnService.protect` hook
/// (Android only). Replacement matters when the VpnService is destroyed and
/// recreated: the new instance must be used for the next tunnel session.
pub fn install_global_android_protector(protector: std::sync::Arc<dyn AndroidSocketProtector>) {
    if let Ok(mut guard) = GLOBAL_ANDROID_PROTECTOR.write() {
        *guard = Some(protector);
    }
}

pub fn global_android_protector() -> Option<std::sync::Arc<dyn AndroidSocketProtector>> {
    GLOBAL_ANDROID_PROTECTOR
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Convenience wrapper used by the engine for every outbound relay socket.
pub struct SocketBypass {
    pub phys: PhysicalInterfaceInfo,
    pub protector: std::sync::Arc<dyn AndroidSocketProtector>,
}

impl SocketBypass {
    pub fn new(phys: PhysicalInterfaceInfo) -> Self {
        Self {
            phys,
            protector: global_android_protector()
                .unwrap_or_else(|| std::sync::Arc::new(NoopSocketProtector)),
        }
    }

    pub fn with_protector(
        phys: PhysicalInterfaceInfo,
        protector: std::sync::Arc<dyn AndroidSocketProtector>,
    ) -> Self {
        Self { phys, protector }
    }

    pub fn bind(&self, socket: &Socket) -> io::Result<()> {
        bind_socket_to_physical_interface(socket, &self.phys, self.protector.as_ref())
    }
}
