# ⚡️ Hijack Port to Proxy

Hijack Port to Proxy (`porthijack`) redirects traffic arriving on a public `ip:port` to a proxy you run yourself on `localhost`, without touching the target service's own configuration. Your proxy can then reach the real service on loopback (`127.0.0.1`/`::1`) and do whatever it wants with the traffic — including things Firegex's other modules can't do, like mangling packets (something [Netfilter Proxy](nfproxy.md) can't fully guarantee, since altering TCP payload sizes can desync the stream, while a userspace proxy fully re-terminates the connection and can freely resize packets).

## How to use it

1. Write and run your own proxy, listening on some local port, forwarding to the real service on loopback.
2. Create a service in the UI: the public `ip:port` clients connect to, the protocol (`tcp` or `udp`), and the local port your proxy listens on.
3. Start the service. Public traffic to that `ip:port` is now transparently redirected to your proxy; your proxy's own traffic to the real service (over loopback) is left untouched.

To the original client, responses still appear to come from the original public `ip:port` — the client never sees your proxy's address. To the real service (if it's configured to only accept loopback connections, or logs source IPs), requests appear to come from your proxy, not from the original client.

### Using the nfproxy simulator as your proxy

You don't have to write a proxy from scratch: the `firegex` pip package's `fgex nfproxy` simulator (see the [Netfilter Proxy guide](nfproxy.md)) is a ready-made local proxy that applies a Python filter file to the traffic, and can double as the proxy this module redirects to — this is a convenient way to get nfproxy-style filtering (including mangling, since the simulator fully re-terminates the connection) for a service, driven entirely by port hijacking instead of nfqueue.

```bash
pip install -U firegex
fgex nfproxy test_http.py 127.0.0.1 8080 --proto http --from-port 13377
```

Then create a Hijack Port to Proxy service pointing at local port `13377`. Note: in the simulator, `RawPacket.raw_packet` always equals `RawPacket.l4_data` (there's no real IP/TCP header to mangle, since the simulator re-terminates the connection at the application layer) — see the [nfproxy guide](nfproxy.md) for more on `RawPacket`.

## How it works

This module works by rewriting packet fields directly with [nftables](https://netfilter.org/) rules — there's no connection tracking/NAT involved, just field mangling on matching packets:

- **Inbound** (prerouting): for packets destined to the public `ip:port`, the destination address and port are rewritten in place to loopback and your proxy's port.
- **Outbound** (postrouting): for packets sourced from your proxy's port (destined back to the original client), the source address and port are rewritten back to the public `ip:port`, so the client sees replies coming from where it expects.

This mangling only applies to packets actually matching the public `ip:port`/protocol you configured — traffic to loopback that isn't part of a hijacked flow is left alone.
