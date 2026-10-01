//! Source-IP transparency: making the protected service see the real client.
//!
//! The NFQUEUE engine gets this for free — it never terminates anything, so the
//! service sees the original packets. A proxy has to work for it, and if it does not,
//! every service that logs, rate-limits or bans by client address quietly starts
//! seeing one address for the whole internet. That is a correctness regression the
//! operator would never notice, so the capability is checked at startup and the
//! per-connection fallback is counted and logged rather than silent.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

// Not in libc: netfilter's own option numbers.
const SO_ORIGINAL_DST: libc::c_int = 80;
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
const IP_TRANSPARENT: libc::c_int = 19;
const IPV6_TRANSPARENT: libc::c_int = 75;

/// Stamped on every connection the engine opens itself.
///
/// Without it an intercept rule cannot tell the engine's own dial apart from the
/// traffic it is supposed to intercept, and on a path where both ends are local —
/// nginx's clear leg in the TLS module is exactly that — the engine redirects itself
/// in a loop. Deliberately not the mark policy routing keys off: that one means
/// "deliver this here", and stamping it on an outbound connection would strand it.
pub const SELF_MARK: u32 = 0x133A;

fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Allow the socket to bind and receive on addresses that are not ours.
///
/// Needs `CAP_NET_ADMIN`; without it this fails with `EPERM` and the caller has to
/// decide whether that is fatal.
pub fn set_transparent(fd: RawFd, ipv6: bool) -> io::Result<()> {
    if ipv6 {
        setsockopt_int(fd, libc::IPPROTO_IPV6, IPV6_TRANSPARENT, 1)
    } else {
        setsockopt_int(fd, libc::IPPROTO_IP, IP_TRANSPARENT, 1)
    }
}

/// Turn a v4-mapped IPv6 address back into the IPv4 address it is.
///
/// A service answering on both stacks is served by one dual-stack listener, so an IPv4
/// connection arrives on it wearing a `::ffff:a.b.c.d` costume. Everything downstream —
/// the conntrack lookup, the source-preserving dial, the metadata a filter reads —
/// wants the address the packet actually had, and a mapped address matches none of the
/// v4 machinery it needs to reach.
pub fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// Where the client was actually trying to reach.
///
/// Always from conntrack: the destination was rewritten before we saw it, and
/// conntrack is what still remembers the original. There used to be a second way
/// (tproxy, which preserves the addresses in place), but it forced the operator to
/// understand the difference and could not reach a service on this host at all. The
/// proxy should look like it is not there, and that is not a setting.
pub fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    original_dst_from_conntrack(stream)
}

fn original_dst_from_conntrack(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    // Unmapped first: on a dual-stack listener an IPv4 connection reports a v6 local
    // address, and asking IPv6 conntrack about an IPv4 flow simply fails.
    match unmap(stream.local_addr()?) {
        SocketAddr::V4(_) => {
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    SO_ORIGINAL_DST,
                    &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr))),
                u16::from_be(addr.sin_port),
            ))
        }
        SocketAddr::V6(_) => {
            let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    IP6T_SO_ORIGINAL_DST,
                    &mut addr as *mut libc::sockaddr_in6 as *mut libc::c_void,
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                u16::from_be(addr.sin6_port),
            ))
        }
    }
}

pub fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv6() {
        let sock = TcpSocket::new_v6()?;
        let _ = setsockopt_int(sock.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0);
        sock
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// Dial the service as the client: same source address, kernel-chosen source port.
///
/// The reply comes back to an address that is not ours, so it only reaches this
/// socket if the ruleset diverts it — the `socket transparent` match in prerouting
/// plus a local route for marked packets. Without that the connection simply hangs,
/// which is why the integration test asserts a full round trip and not just the
/// address the service reports.
pub async fn connect_as(
    client: IpAddr,
    upstream: SocketAddr,
    self_mark: Option<u32>,
) -> io::Result<TcpStream> {
    if client.is_ipv6() != upstream.is_ipv6() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot spoof an IPv4 client towards an IPv6 service, or the reverse",
        ));
    }
    let socket = if upstream.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    set_transparent(socket.as_raw_fd(), upstream.is_ipv6())?;
    if let Some(mark) = self_mark {
        set_self_mark(socket.as_raw_fd(), mark)?;
    }
    socket.set_reuseaddr(true)?;
    socket.bind(SocketAddr::new(client, 0))?;
    socket.connect(upstream).await
}

/// Dial without impersonating anyone, but still marked as ours.
pub async fn connect_plain(upstream: SocketAddr, self_mark: Option<u32>) -> io::Result<TcpStream> {
    let socket = if upstream.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    if let Some(mark) = self_mark {
        set_self_mark(socket.as_raw_fd(), mark)?;
    }
    socket.connect(upstream).await
}

/// A UDP socket wearing the client's address, with nothing dialled yet.
///
/// Split out from [`connect_as_udp`] for QUIC: quinn owns its socket and sends to an
/// address per packet, which a *connected* socket refuses (`EISCONN`). Everything that
/// makes the address someone else's — `IP_TRANSPARENT`, the mark the intercept rules
/// skip, and the bind to a foreign address — happens here; who it then talks to is the
/// caller's business.
pub fn bind_as_udp(
    client: IpAddr,
    upstream: SocketAddr,
    self_mark: Option<u32>,
) -> io::Result<std::net::UdpSocket> {
    if client.is_ipv6() != upstream.is_ipv6() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot spoof an IPv4 client towards an IPv6 service, or the reverse",
        ));
    }
    let domain = if upstream.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    set_transparent(socket.as_raw_fd(), upstream.is_ipv6())?;
    if let Some(mark) = self_mark {
        set_self_mark(socket.as_raw_fd(), mark)?;
    }
    socket.set_reuse_address(true)?;
    let bind_addr: socket2::SockAddr = SocketAddr::new(client, 0).into();
    socket.bind(&bind_addr)?;
    Ok(socket.into())
}

/// Dial the service as the client over UDP: same source address, kernel-chosen source port.
pub async fn connect_as_udp(
    client: IpAddr,
    upstream: SocketAddr,
    self_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let std_sock = bind_as_udp(client, upstream, self_mark)?;
    let tokio_sock = UdpSocket::from_std(std_sock)?;
    tokio_sock.connect(upstream).await?;
    Ok(tokio_sock)
}

/// Dial UDP without impersonating anyone, but still marked as ours.
pub async fn connect_plain_udp(
    upstream: SocketAddr,
    self_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if upstream.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).await?;
    if let Some(mark) = self_mark {
        set_self_mark(socket.as_raw_fd(), mark)?;
    }
    socket.connect(upstream).await?;
    Ok(socket)
}

/// Mark a socket as ours, so the intercept rules can skip it.
pub fn set_self_mark(fd: RawFd, mark: u32) -> io::Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)
}

/// Check at startup that we can actually do this, so a missing `CAP_NET_ADMIN` is a
/// loud failure instead of a silent loss of the client's identity.
pub fn probe_capability(ipv6: bool) -> io::Result<()> {
    let socket = if ipv6 {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    set_transparent(socket.as_raw_fd(), ipv6)
}
