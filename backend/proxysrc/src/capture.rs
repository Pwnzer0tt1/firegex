//! The decrypted stream, written out as the packets it never was.
//!
//! TLS is terminated in this process, which is what lets a protected service occupy no
//! port beyond the one it already answered on — and it means the plaintext is never a
//! packet on any interface, so there is nothing for a capture tool to see. Everything an
//! operator wants to do with the decrypted traffic (read it in Wireshark, keep a pcap of
//! a round, grep a flow after the fact) would have gone with the ports.
//!
//! So the engine writes it out itself. Each connection's plaintext is framed as the TCP
//! stream it was before encryption and sent to a dummy interface, where tcpdump and
//! Wireshark read it like anything else. One interface for the whole instance: every TLS
//! service's plaintext arrives there and nothing else does.
//!
//! **These are reconstructed packets.** The bytes are real — they are exactly what the
//! filters saw and exactly what was forwarded — but the framing around them is made up
//! here, because the framing that actually crossed the wire was encrypted. Sequence
//! numbers start at zero, there are no retransmissions, and the segmentation is this
//! engine's read sizes rather than the peer's. What that buys is a stream Wireshark can
//! follow; what it costs is that this is not evidence of what was on the wire, and the
//! documentation says so.
//!
//! **A QUIC stream is reconstructed the same way, one TCP stream each.** A QUIC stream
//! is ordered, reliable and starts at zero, which is precisely what a [`Tap`] rebuilds —
//! but every stream of one connection shares the connection's four-tuple, so writing
//! them out as they are would interleave a hundred of them into a single conversation
//! that no tool could take apart. So each is given a **synthetic client port** by
//! [`Tap::open_stream`], and that is one more piece of invented framing on top of the
//! invented framing this whole file is: the port identifies a stream and was never a
//! port anybody bound. It has to be said wherever a capture from here is offered, next
//! to the sentence about sequence numbers, because an operator reading a port back out
//! of Wireshark will otherwise go looking for a socket that does not exist.
//!
//! Failure is always silent and always local. If the interface is not there, or the
//! socket cannot be opened, or a send fails, the traffic goes on exactly as it would
//! have: a capture aid must never be able to interrupt a service it is only watching.

use std::ffi::CString;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;

/// The interface the decrypted traffic is written to. A fixed name on purpose: it is
/// something an operator types into a capture tool.
pub const DEVICE: &str = "firegex0";

/// How much payload goes in one segment. Under the dummy device's 1500-byte MTU with
/// room for the largest headers this writes (Ethernet + IPv6 + TCP).
const SEGMENT: usize = 1400;

const ETH_HEADER: usize = 14;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_HEADER: usize = 20;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// A raw socket bound to the capture interface, shared by every connection.
pub struct Capture {
    fd: libc::c_int,
    ifindex: libc::c_int,
}

// The fd is used only for `sendto`, which is thread-safe on a packet socket.
unsafe impl Send for Capture {}
unsafe impl Sync for Capture {}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Capture {
    /// Open the capture interface, or `None` if there is nothing to write to.
    ///
    /// `None` is the ordinary case, not an error: the interface exists only while some
    /// TLS service is running, and a host that cannot have one still runs services.
    pub fn open() -> Option<Arc<Capture>> {
        let name = CString::new(DEVICE).ok()?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return None;
        }
        // `ETH_P_ALL` in the socket's protocol would also make it *receive* every frame
        // on every interface, which is a firehose nobody reads. Zero sends only.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return None;
        }
        Some(Arc::new(Capture { fd, ifindex: ifindex as libc::c_int }))
    }

    fn send(&self, frame: &[u8]) {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        unsafe {
            // The return value is deliberately ignored: a capture that cannot keep up,
            // or an interface that went away, must not become an error on the path of
            // the traffic it is watching.
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                libc::MSG_DONTWAIT,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
        }
    }
}

/// One connection's reconstruction: the two ends, and where each direction has got to.
pub struct Tap {
    capture: Arc<Capture>,
    client: SocketAddr,
    server: SocketAddr,
    /// Next sequence number for client → service.
    up: AtomicU32,
    /// Next sequence number for service → client.
    down: AtomicU32,
    /// Whether the end of the stream has been written.
    ended: AtomicBool,
}

/// A reconstruction always gets an end, whichever way its owner left.
///
/// The TCP path closes its tap where the connection is torn down, and could; the paths
/// that carry one stream of many have a dozen ways out — a refused request returns before
/// anything is joined — and a stream left without a FIN is one Wireshark holds open
/// waiting for bytes that are never coming. So the last holder emits it, and
/// [`Tap::closed`] stays callable where the end is known and worth saying explicitly.
impl Drop for Tap {
    fn drop(&mut self) {
        self.closed();
    }
}

/// Hands out the ports that tell one multiplexed stream from another.
///
/// A counter and not a hash of the stream id: ids restart at zero on every QUIC
/// connection, so deriving the port from one would drop two clients' first streams into
/// the same conversation. Cycling the ephemeral range instead gives the same answer a
/// NAT gives, and reuse only becomes possible after 16384 live streams — at which point
/// a new SYN is what separates them, exactly as it does for a real port that came round
/// again.
static NEXT_STREAM_PORT: AtomicU16 = AtomicU16::new(0);

const EPHEMERAL_BASE: u16 = 49152;
const EPHEMERAL_SPAN: u16 = 65535 - EPHEMERAL_BASE + 1;

fn stream_port() -> u16 {
    EPHEMERAL_BASE + NEXT_STREAM_PORT.fetch_add(1, Ordering::Relaxed) % EPHEMERAL_SPAN
}

impl Tap {
    /// Start a reconstruction for one stream of a multiplexed connection.
    ///
    /// The client's address keeps its IP and loses its port, because the port is the only
    /// field left that can tell two streams of one connection apart: the service's end is
    /// the service's and changing it would misattribute the traffic, and the client's IP
    /// is what an operator filters on. What comes back is therefore a conversation
    /// between a real host and a real service on a port that never existed.
    pub fn open_stream(
        capture: Option<Arc<Capture>>,
        client: SocketAddr,
        server: SocketAddr,
    ) -> Option<Arc<Tap>> {
        let mut client = client;
        client.set_port(stream_port());
        Tap::open(capture, client, server)
    }

    /// Start a reconstruction, and emit the handshake that opens it.
    ///
    /// The handshake is not decoration: without a SYN, Wireshark has no beginning for
    /// the stream and cannot reassemble it, so the payloads show up as unrelated
    /// segments of a conversation it never saw start.
    pub fn open(capture: Option<Arc<Capture>>, client: SocketAddr, server: SocketAddr) -> Option<Arc<Tap>> {
        // Mixed families would need a translation nobody asked for; in practice both
        // ends of a connection the engine terminates are the same family.
        if (client.is_ipv4()) != (server.is_ipv4()) {
            return None;
        }
        let tap = Arc::new(Tap {
            capture: capture?,
            client,
            server,
            up: AtomicU32::new(0),
            down: AtomicU32::new(0),
            ended: AtomicBool::new(false),
        });
        // Interleaved with the increments, not emitted and then counted: each of these
        // reads the two counters as they stand, so a SYN-ACK sent before the client's
        // SYN has been counted acknowledges nothing and reads as a broken handshake in
        // any tool that checks. SYN consumes a sequence number; so does SYN-ACK.
        tap.emit(true, SYN, &[]);
        tap.up.fetch_add(1, Ordering::Relaxed);
        tap.emit(false, SYN | ACK, &[]);
        tap.down.fetch_add(1, Ordering::Relaxed);
        tap.emit(true, ACK, &[]);
        Some(tap)
    }

    /// One chunk of plaintext, in the direction it was forwarded.
    ///
    /// What is written here is what was *forwarded*, after any rewriting: a capture that
    /// showed the bytes a filter replaced would disagree with what the two ends actually
    /// received, which is the one thing it is for.
    pub fn wrote(&self, from_client: bool, data: &[u8]) {
        for chunk in data.chunks(SEGMENT) {
            self.emit(from_client, PSH | ACK, chunk);
            let counter = if from_client { &self.up } else { &self.down };
            counter.fetch_add(chunk.len() as u32, Ordering::Relaxed);
        }
    }

    /// Close the reconstruction, so the stream has an end as well as a beginning.
    ///
    /// Idempotent: [`Drop`] calls it too, and a stream that ended twice would read as one
    /// that was closed and then closed again.
    pub fn closed(&self) {
        if self.ended.swap(true, Ordering::Relaxed) {
            return;
        }
        self.emit(true, FIN | ACK, &[]);
        self.emit(false, FIN | ACK, &[]);
    }

    fn emit(&self, from_client: bool, flags: u8, payload: &[u8]) {
        let (src, dst) = if from_client {
            (self.client, self.server)
        } else {
            (self.server, self.client)
        };
        let (seq, ack) = if from_client {
            (self.up.load(Ordering::Relaxed), self.down.load(Ordering::Relaxed))
        } else {
            (self.down.load(Ordering::Relaxed), self.up.load(Ordering::Relaxed))
        };
        let frame = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                build_v4(s, d, src.port(), dst.port(), seq, ack, flags, payload)
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                build_v6(s, d, src.port(), dst.port(), seq, ack, flags, payload)
            }
            _ => return,
        };
        self.capture.send(&frame);
    }
}

/// Ethernet header. The addresses are locally administered and made up: a dummy device
/// has no peer to address, and a capture tool only needs the ethertype to know what
/// follows.
fn ethernet(out: &mut Vec<u8>, ethertype: u16) {
    out.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // destination
    out.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // source
    out.extend_from_slice(&ethertype.to_be_bytes());
}

fn ones_complement(sum: u32) -> u16 {
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn sum_bytes(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    sum
}

#[allow(clippy::too_many_arguments)]
fn tcp_header(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    pseudo: u32,
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(TCP_HEADER);
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4); // data offset: five 32-bit words, no options
    tcp.push(flags);
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0, 0]); // checksum, filled in below
    tcp.extend_from_slice(&[0, 0]); // urgent pointer
    let checksum = ones_complement(pseudo + sum_bytes(&tcp) + sum_bytes(payload));
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    tcp
}

#[allow(clippy::too_many_arguments)]
fn build_v4(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = TCP_HEADER + payload.len();
    let pseudo = sum_bytes(&src.octets())
        + sum_bytes(&dst.octets())
        + libc::IPPROTO_TCP as u32
        + tcp_len as u32;
    let tcp = tcp_header(src_port, dst_port, seq, ack, flags, payload, pseudo);

    let mut out = Vec::with_capacity(ETH_HEADER + IPV4_HEADER + tcp_len);
    ethernet(&mut out, 0x0800);
    let start = out.len();
    out.push(0x45); // version 4, five-word header
    out.push(0); // dscp/ecn
    out.extend_from_slice(&((IPV4_HEADER + tcp_len) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]); // identification
    out.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    out.push(64); // ttl
    out.push(libc::IPPROTO_TCP as u8);
    out.extend_from_slice(&[0, 0]); // checksum, filled in below
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    let checksum = ones_complement(sum_bytes(&out[start..]));
    out[start + 10..start + 12].copy_from_slice(&checksum.to_be_bytes());

    out.extend_from_slice(&tcp);
    out.extend_from_slice(payload);
    out
}

#[allow(clippy::too_many_arguments)]
fn build_v6(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = TCP_HEADER + payload.len();
    let pseudo = sum_bytes(&src.octets())
        + sum_bytes(&dst.octets())
        + libc::IPPROTO_TCP as u32
        + tcp_len as u32;
    let tcp = tcp_header(src_port, dst_port, seq, ack, flags, payload, pseudo);

    let mut out = Vec::with_capacity(ETH_HEADER + IPV6_HEADER + tcp_len);
    ethernet(&mut out, 0x86DD);
    out.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6, no traffic class
    out.extend_from_slice(&(tcp_len as u16).to_be_bytes()); // payload length
    out.push(libc::IPPROTO_TCP as u8); // next header
    out.push(64); // hop limit
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&tcp);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one property that makes multiplexed streams separable in a capture.
    ///
    /// Two streams of one connection differ in nothing a capture tool looks at — same
    /// addresses, same service port — so if this stopped handing out distinct ports they
    /// would arrive as one interleaved conversation, which is worse than not capturing
    /// them at all: it reads as a single stream whose bytes make no sense.
    #[test]
    fn every_stream_gets_a_port_of_its_own() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..EPHEMERAL_SPAN as usize {
            let port = stream_port();
            assert!(port >= EPHEMERAL_BASE, "{port} is not an ephemeral port");
            assert!(seen.insert(port), "{port} came round before the range was spent");
        }
        // And then it does come round, rather than running out: a long-lived engine has
        // more streams than there are ports, and a new SYN is what separates the reuse —
        // exactly as it does for a real port the kernel hands out again.
        assert!(!seen.insert(stream_port()));
    }
}
