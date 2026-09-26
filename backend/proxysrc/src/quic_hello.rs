//! What a QUIC client offers, read off its first packets before anybody answers them.
//!
//! The TLS path mirrors ALPN by holding the ClientHello open, asking the service with the
//! client's own list and telling the client what came back. QUIC was thought to leave
//! nothing to hold: the ClientHello travels inside an Initial packet, encrypted. But the
//! Initial keys are derived from the Destination Connection ID the client put in the
//! clear (RFC 9001 §5.2) — deliberately, so a middlebox can read exactly this — and so
//! the list can be read before the handshake is answered. That is what this does.
//!
//! What it replaced was a list of candidates the operator had to write down per service,
//! `h3` unless told otherwise: a QUIC service speaking anything else was unreachable
//! through firegex until somebody found the setting. With the client's own list the
//! service chooses from what the client actually offered, exactly as over TLS, and there
//! is nothing to configure.
//!
//! It reads; it never answers. The socket the endpoint owns is wrapped
//! ([`SniffingSocket`]) so every datagram quinn is about to process passes by here first,
//! and only long-header Initial packets are looked at — one comparison for everything
//! else. A ClientHello too large for one packet (post-quantum key shares make that
//! ordinary) is reassembled from its CRYPTO frames across datagrams, in whatever order
//! they arrive.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rustls::quic::{Suite, Version};
use rustls::Side;

/// How many clients' hellos may be in progress at once. Past it new ones are not read —
/// their connections fall back rather than this growing without end under a flood of
/// forged Initials, which cost the sender nothing: the keys are public, so a valid one can
/// be made from any address. With `MAX_HELLO` this bounds what a flood can make this
/// process hold to 16 MiB.
const MAX_PENDING: usize = 1024;

/// How long an unfinished or unclaimed hello is kept.
const KEPT_FOR: Duration = Duration::from_secs(10);

/// Most CRYPTO bytes kept for one hello. A ClientHello is one or two kilobytes, a few with
/// post-quantum key shares and a resumption ticket; this is a cap on what a peer can make
/// this process hold, not a size anybody meets.
const MAX_HELLO: usize = 16 * 1024;

/// One client's hello as it arrives.
struct Pending {
    /// The connection ID its Initials were protected with. A new one means a new attempt —
    /// a Retry answered, or another connection from the same port.
    dcid: Vec<u8>,
    fragments: Vec<(u64, Vec<u8>)>,
    held: usize,
    alpn: Option<Vec<Vec<u8>>>,
    since: Instant,
}

/// The hellos being read, by the address they came from.
pub struct Hellos {
    pending: Mutex<HashMap<SocketAddr, Pending>>,
    arrived: tokio::sync::Notify,
    suite: Suite,
}

impl fmt::Debug for Hellos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hellos").finish_non_exhaustive()
    }
}

impl Default for Hellos {
    fn default() -> Self {
        Self::new()
    }
}

impl Hellos {
    pub fn new() -> Self {
        // Every version's Initial packets are protected with this suite, whatever the
        // handshake goes on to choose: RFC 9001 §5.2.
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .and_then(|s| s.quic_suite())
            .expect("TLS13_AES_128_GCM_SHA256 carries QUIC");
        Self {
            pending: Mutex::new(HashMap::new()),
            arrived: tokio::sync::Notify::new(),
            suite,
        }
    }

    /// Look at one datagram received from `from`. Cheap for anything but an Initial.
    pub fn observe(&self, from: SocketAddr, datagram: &[u8]) {
        let mut rest = datagram;
        // An Initial can have other packets coalesced behind it in one datagram; only
        // the Initials matter, and they come first.
        while let Some(packet) = decrypt_initial(&self.suite, rest) {
            rest = &rest[packet.length..];
            self.absorb(from, packet);
        }
    }

    fn absorb(&self, from: SocketAddr, packet: Initial) {
        let Ok(mut pending) = self.pending.lock() else { return };
        let now = Instant::now();
        if pending.len() >= MAX_PENDING {
            pending.retain(|_, p| now.duration_since(p.since) < KEPT_FOR);
            if pending.len() >= MAX_PENDING && !pending.contains_key(&from) {
                return;
            }
        }
        let entry = pending.entry(from).or_insert_with(|| Pending {
            dcid: packet.dcid.clone(),
            fragments: Vec::new(),
            held: 0,
            alpn: None,
            since: now,
        });
        if entry.dcid != packet.dcid {
            *entry = Pending {
                dcid: packet.dcid.clone(),
                fragments: Vec::new(),
                held: 0,
                alpn: None,
                since: now,
            };
        }
        if entry.alpn.is_some() {
            return;
        }
        for (offset, data) in packet.crypto {
            if entry.held + data.len() > MAX_HELLO {
                return;
            }
            entry.held += data.len();
            entry.fragments.push((offset, data));
        }
        if let Some(alpn) = client_hello_alpn(&entry.fragments) {
            entry.alpn = Some(alpn);
            entry.fragments.clear();
            self.arrived.notify_waiters();
        }
    }

    fn take(&self, from: SocketAddr) -> Option<Vec<Vec<u8>>> {
        let mut pending = self.pending.lock().ok()?;
        if pending.get(&from)?.alpn.is_some() {
            return pending.remove(&from).and_then(|p| p.alpn);
        }
        None
    }

    /// The protocols the client at `from` offered, waiting up to `wait` for the rest of a
    /// hello split across datagrams. `None` when it could not be read.
    pub async fn offered(&self, from: SocketAddr, wait: Duration) -> Option<Vec<Vec<u8>>> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            // Registered before looking, so a hello completed in between is not missed.
            let notified = self.arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(alpn) = self.take(from) {
                return Some(alpn);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.take(from);
            }
        }
    }
}

/// The socket a relay's endpoint receives through, reading hellos on the way past.
#[derive(Debug)]
pub struct SniffingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    hellos: Arc<Hellos>,
}

impl SniffingSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, hellos: Arc<Hellos>) -> Self {
        Self { inner, hellos }
    }
}

impl AsyncUdpSocket for SniffingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let polled = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = &polled {
            for (buf, meta) in bufs.iter().zip(meta.iter()).take(*count) {
                let received = &buf[..meta.len.min(buf.len())];
                // Several datagrams of `stride` bytes each where the kernel coalesced them.
                let stride = if meta.stride == 0 { received.len() } else { meta.stride };
                for datagram in received.chunks(stride.max(1)) {
                    if is_long_header(datagram) {
                        self.hellos.observe(meta.addr, datagram);
                    }
                }
            }
        }
        polled
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn is_long_header(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|b| b & 0x80 != 0)
}

/// One Initial packet, decrypted: what it was protected with, and its CRYPTO frames.
struct Initial {
    /// How many bytes of the datagram it took, so a packet coalesced behind it is found.
    length: usize,
    dcid: Vec<u8>,
    crypto: Vec<(u64, Vec<u8>)>,
}

fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(*pos..*pos + len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *pos += len;
    Some(value)
}

/// Decrypt the Initial packet at the start of `packet`, if that is what it is.
fn decrypt_initial(suite: &Suite, packet: &[u8]) -> Option<Initial> {
    let first = *packet.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
    let (version, initial_type) = match version {
        0x0000_0001 => (Version::V1, 0),
        0x6b33_43cf => (Version::V2, 1),
        0xff00_001d..=0xff00_0020 => (Version::V1Draft, 0),
        _ => return None,
    };
    if (first >> 4) & 0x03 != initial_type {
        return None;
    }
    let mut pos = 5;
    let dcid_len = usize::from(*packet.get(pos)?);
    let dcid = packet.get(pos + 1..pos + 1 + dcid_len)?.to_vec();
    pos += 1 + dcid_len;
    let scid_len = usize::from(*packet.get(pos)?);
    pos += 1 + scid_len;
    let token_len = usize::try_from(varint(packet, &mut pos)?).ok()?;
    pos = pos.checked_add(token_len)?;
    let length = usize::try_from(varint(packet, &mut pos)?).ok()?;
    let pn_offset = pos;
    let end = pn_offset.checked_add(length)?;
    if end > packet.len() {
        return None;
    }

    let keys = suite.keys(&dcid, Side::Server, version);
    let sample_len = keys.remote.header.sample_len();
    let sample = packet.get(pn_offset + 4..pn_offset + 4 + sample_len)?.to_vec();
    let mut buf = packet[..end].to_vec();
    let (head, tail) = buf.split_at_mut(1);
    let pn_field = tail.get_mut(pn_offset - 1..pn_offset + 3)?;
    keys.remote
        .header
        .decrypt_in_place(&sample, &mut head[0], pn_field)
        .ok()?;
    let pn_len = usize::from(buf[0] & 0x03) + 1;
    let mut number = 0u64;
    for byte in &buf[pn_offset..pn_offset + pn_len] {
        number = (number << 8) | u64::from(*byte);
    }
    let (header, payload) = buf.split_at_mut(pn_offset + pn_len);
    let plain = keys
        .remote
        .packet
        .decrypt_in_place(number, header, payload)
        .ok()?;

    Some(Initial {
        length: end,
        dcid,
        crypto: crypto_frames(plain)?,
    })
}

/// The CRYPTO frames of a decrypted Initial payload. `None` for a frame an Initial cannot
/// carry, which means this was not what it looked like.
fn crypto_frames(payload: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        match varint(payload, &mut pos)? {
            0x00 | 0x01 => {} // PADDING, PING
            kind @ (0x02 | 0x03) => {
                // ACK: largest, delay, range count, first range, the ranges, and ECN.
                varint(payload, &mut pos)?;
                varint(payload, &mut pos)?;
                let ranges = varint(payload, &mut pos)?;
                varint(payload, &mut pos)?;
                for _ in 0..ranges {
                    varint(payload, &mut pos)?;
                    varint(payload, &mut pos)?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        varint(payload, &mut pos)?;
                    }
                }
            }
            0x06 => {
                let offset = varint(payload, &mut pos)?;
                let len = usize::try_from(varint(payload, &mut pos)?).ok()?;
                let data = payload.get(pos..pos.checked_add(len)?)?;
                frames.push((offset, data.to_vec()));
                pos += len;
            }
            // CONNECTION_CLOSE ends what there is to read.
            0x1c => break,
            _ => return None,
        }
    }
    Some(frames)
}

/// The ALPN list of a ClientHello, once enough of it has arrived to have one.
///
/// `Some(vec![])` for a complete hello that offers none — which QUIC does not allow, and
/// which the handshake is left to refuse.
fn client_hello_alpn(fragments: &[(u64, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
    // What has arrived contiguously from the start, in whatever order it came.
    let mut sorted: Vec<&(u64, Vec<u8>)> = fragments.iter().collect();
    sorted.sort_by_key(|(offset, _)| *offset);
    let mut hello: Vec<u8> = Vec::new();
    for (offset, data) in sorted {
        let offset = usize::try_from(*offset).ok()?;
        if offset > hello.len() {
            break;
        }
        let overlap = hello.len() - offset;
        if overlap < data.len() {
            hello.extend_from_slice(&data[overlap..]);
        }
    }
    if hello.len() < 4 || hello[0] != 0x01 {
        return None;
    }
    let len = (usize::from(hello[1]) << 16) | (usize::from(hello[2]) << 8) | usize::from(hello[3]);
    let body = hello.get(4..4 + len)?;
    Some(alpn_of(body).unwrap_or_default())
}

fn alpn_of(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let u16_at = |pos: usize| -> Option<usize> {
        Some(usize::from(u16::from_be_bytes(body.get(pos..pos + 2)?.try_into().ok()?)))
    };
    // Legacy version and random, then the session id, the suites and the compressions.
    let mut pos = 2 + 32;
    pos += 1 + usize::from(*body.get(pos)?);
    pos += 2 + u16_at(pos)?;
    pos += 1 + usize::from(*body.get(pos)?);
    let end = pos.checked_add(2 + u16_at(pos)?)?;
    pos += 2;
    while pos + 4 <= end {
        let kind = u16_at(pos)?;
        let len = u16_at(pos + 2)?;
        let data = body.get(pos + 4..pos + 4 + len)?;
        pos += 4 + len;
        if kind != 16 {
            continue;
        }
        let mut names = Vec::new();
        let mut at = 2;
        while at < data.len() {
            let name_len = usize::from(data[at]);
            names.push(data.get(at + 1..at + 1 + name_len)?.to_vec());
            at += 1 + name_len;
        }
        return Some(names);
    }
    Some(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_varint(out: &mut Vec<u8>, value: u64) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16384 {
            out.extend_from_slice(&(0x4000 | value as u16).to_be_bytes());
        } else {
            out.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes());
        }
    }

    /// A ClientHello offering `alpn`, and nothing else a parser would need.
    fn hello_with(alpn: &[&[u8]]) -> Vec<u8> {
        let mut names = Vec::new();
        for name in alpn {
            names.push(name.len() as u8);
            names.extend_from_slice(name);
        }
        let mut ext = vec![0x00, 0x10];
        ext.extend_from_slice(&((names.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(names.len() as u16).to_be_bytes());
        ext.extend_from_slice(&names);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // no session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one suite
        body.extend_from_slice(&[0x01, 0x00]); // no compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hello = vec![0x01];
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    /// A client Initial carrying these CRYPTO fragments, protected the way a client
    /// protects one — with rustls's own client-side keys, so what is read back is checked
    /// against the other half of the library rather than against itself.
    fn client_initial(dcid: &[u8], number: u64, crypto: &[(u64, &[u8])]) -> Vec<u8> {
        let keys = Hellos::new().suite.keys(dcid, Side::Client, Version::V1);
        let mut payload = Vec::new();
        for (offset, data) in crypto {
            payload.push(0x06);
            push_varint(&mut payload, *offset);
            push_varint(&mut payload, data.len() as u64);
            payload.extend_from_slice(data);
        }
        payload.push(0x01); // a PING, as Chrome scatters among the fragments
        payload.resize(payload.len().max(1100), 0); // PADDING, to the size a client sends
        let mut packet = vec![0xc1, 0, 0, 0, 1, dcid.len() as u8];
        packet.extend_from_slice(dcid);
        packet.extend_from_slice(&[0, 0]); // no source id, no token
        packet.extend_from_slice(&(0x4000 | (2 + payload.len() + 16) as u16).to_be_bytes());
        let pn_offset = packet.len();
        packet.extend_from_slice(&(number as u16).to_be_bytes());
        let tag = keys.local.packet.encrypt_in_place(number, &packet, &mut payload).unwrap();
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        let sample = packet[pn_offset + 4..pn_offset + 20].to_vec();
        let (first, rest) = packet.split_at_mut(1);
        keys.local
            .header
            .encrypt_in_place(&sample, &mut first[0], &mut rest[pn_offset - 1..pn_offset + 1])
            .unwrap();
        packet
    }

    fn from() -> SocketAddr {
        "192.0.2.1:4433".parse().unwrap()
    }

    #[test]
    fn a_protected_initial_is_read_for_what_it_offers() {
        let hellos = Hellos::new();
        let hello = hello_with(&[b"h3", b"fgex-test"]);
        hellos.observe(from(), &client_initial(b"\x83\x94\xc8\xf0\x3e\x51\x57\x08", 0, &[(0, &hello)]));
        assert_eq!(hellos.take(from()), Some(vec![b"h3".to_vec(), b"fgex-test".to_vec()]));
    }

    /// Post-quantum key shares make a ClientHello bigger than one packet, and clients
    /// scatter its pieces: two Initials, the second one first.
    #[test]
    fn a_hello_across_two_packets_arriving_backwards_is_reassembled() {
        let hellos = Hellos::new();
        let hello = hello_with(&[b"doq"]);
        let (a, b) = hello.split_at(30);
        let dcid = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        hellos.observe(from(), &client_initial(dcid, 1, &[(30, b)]));
        assert_eq!(hellos.take(from()), None, "half a hello was read as a whole one");
        hellos.observe(from(), &client_initial(dcid, 0, &[(0, a)]));
        assert_eq!(hellos.take(from()), Some(vec![b"doq".to_vec()]));
    }

    /// A Retry answered is a new Initial under a new connection ID, and what was gathered
    /// under the old one is not mixed into it.
    #[test]
    fn a_new_connection_id_starts_again() {
        let hellos = Hellos::new();
        let old = hello_with(&[b"old"]);
        let new = hello_with(&[b"new"]);
        hellos.observe(from(), &client_initial(b"\x11\x11\x11\x11\x11\x11\x11\x11", 0, &[(0, &old[..20])]));
        hellos.observe(from(), &client_initial(b"\x22\x22\x22\x22\x22\x22\x22\x22", 0, &[(0, &new)]));
        assert_eq!(hellos.take(from()), Some(vec![b"new".to_vec()]));
    }

    #[test]
    fn anything_but_an_initial_is_passed_over() {
        let hellos = Hellos::new();
        hellos.observe(from(), &[0x40, 1, 2, 3, 4, 5, 6, 7]);
        hellos.observe(from(), &[0xe0, 0, 0, 0, 1, 0, 0]);
        let mut tampered = client_initial(b"\x09\x09\x09\x09\x09\x09\x09\x09", 0, &[(0, &hello_with(&[b"h3"]))]);
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        hellos.observe(from(), &tampered);
        assert_eq!(hellos.take(from()), None);
    }

    #[tokio::test]
    async fn a_hello_still_arriving_is_waited_for() {
        let hellos = Arc::new(Hellos::new());
        let hello = hello_with(&[b"h3"]);
        let packet = client_initial(b"\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11", 0, &[(0, &hello)]);
        let later = Arc::clone(&hellos);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            later.observe(from(), &packet);
        });
        assert_eq!(hellos.offered(from(), Duration::from_secs(2)).await, Some(vec![b"h3".to_vec()]));
        assert_eq!(hellos.offered(from(), Duration::from_millis(50)).await, None);
    }
}
