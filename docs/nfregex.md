# 📡 Netfilter Regex

Netfilter Regex (`nfregex`) filters network traffic by matching regular expressions directly against packet content, entirely inside a C++ binary (no embedded interpreter, no user-supplied code). It's the fastest filtering module Firegex offers, at the cost of flexibility: if you need custom logic (parsing structured data, stateful decisions, mangling packets), use [Netfilter Proxy](nfproxy.md) instead.

## How to use it

1. Create a service: pick a protocol (`tcp` or `udp`), the target `ip:port` (or attach it to a [TLS Decrypt](tls.md) stream, to see decrypted traffic, `tcp` only), and a name.
2. Add one or more regexes to the service.
3. Start the service. Matching traffic is dropped/rejected according to each regex's direction; everything else passes through unmodified — nfregex has no mangling capability (only [Netfilter Proxy](nfproxy.md) can mangle traffic).

Each regex has:
- **Pattern**: a PCRE2-compatible regular expression, matched as raw bytes (not text) against the traffic.
- **Direction** (`mode`): `S` — match only client → server traffic (to the server); `C` — match only server → client traffic (to the client); `B` — match both directions.
- **Case sensitivity**: matching can be case-sensitive or case-insensitive per regex.
- **Active/inactive**: a regex can be disabled without deleting it — inactive regexes are kept (and still shown with their stats) but never evaluated against traffic.

The service page shows, per regex, how many packets it has blocked so far, and whether it's currently active.

`fail_open` (an advanced per-service option, shared with nfproxy) controls what happens if the underlying nfqueue/binary can't be reached: if enabled, traffic is allowed through unfiltered rather than blocked.

### TCP vs UDP matching

- **TCP**: nfregex reassembles and reorders the stream before matching, so a regex can match a pattern that's split across multiple packets. Out-of-order packets are handled transparently.
- **UDP**: there's no stream to reassemble — each datagram is matched independently, and only the match context (not the full payload) is retained afterwards.

## How it works

The packet filtering process is implemented in C++ and involves several key steps:

- **Packet interception**: the [nfqueue](https://netfilter.org/projects/libnetfilter_queue/) kernel module intercepts network packets (a [netfilter](https://netfilter.org/) module) 🔍. The rules attaching nfqueue to the traffic are generated via the nftables JSON API by the Python manager.
- **Packet reading**: a dedicated thread reads packets from nfqueue. 🧵
- **Packet parsing**: intercepted packets are parsed by [libtins](https://libtins.github.io/), a C++ library that extracts the payload from each packet. 📄
- **Multi-threaded analysis**: multiple threads analyze packets concurrently. While the nfqueue module balances load based solely on IP addresses — resulting in a single thread handling all traffic in NAT environments like CTF networks — Firegex manages threads at the user level differently: traffic is routed based on IP addresses combined with port hashing, giving a more balanced workload while guaranteeing that a given flow is always analyzed by the same thread. ⚡️
- **TCP handling**: for TCP connections, libtins uses a TCP follower to reorder packets received from the kernel. 📈
- **Regex matching**: the extracted payload is matched using [vectorscan](https://github.com/VectorCamp/vectorscan) — a fork of [hyperscan](https://github.com/intel/hyperscan) that also runs on arm64. 🎯
