# Firegex Python Library and CLI

This is the Python library for [Firegex](https://github.com/Pwnzer0tt1/firegex), a firewall built for CTF Attack-Defense competitions. It provides the `firegex.nfproxy` package used to write [Netfilter Proxy](../docs/nfproxy.md) Python packet filters, the `fgex` CLI, and a local proxy simulator (`proxysim`) for testing filters without a running Firegex instance.

## Installation

```bash
pip install -U firegex
```

`fgex` is an alias package for `firegex`: installing either one gives you the same `firegex` module and the `fgex`/`firegex` CLI commands.

## Documentation

**➡️ [Netfilter Proxy: writing and testing `@pyfilter` scripts](../docs/nfproxy.md)** — the `pyfilter` decorator, every data structure (`RawPacket`, `TCPInputStream`/`TCPOutputStream`, `HttpRequest`/`HttpResponse` and their variants, `HttpHistory`), packet statements, stream limits, the `fgex nfproxy` CLI simulator, and a full worked example.

That page is also what's shown in the Firegex web UI itself (the docs button on the nfproxy pages) — both are generated from that single file, so they can never drift out of sync.

## Firegex's other filtering modules

This library only covers Netfilter Proxy. Firegex ships several other independent modules, each with its own guide:

- **[Netfilter Regex](../docs/nfregex.md)** — fast, PCRE2/hyperscan-based regex matching against raw traffic.
- **[Hijack Port to Proxy](../docs/porthijack.md)** — redirect traffic to your own external proxy without touching the target service.
- **[Firewall Rules](../docs/firewall.md)** — plain nftables allow/drop/reject rules.
- **[TLS Decryption](../docs/tls.md)** — decrypt-and-reinspect bridge for services that speak TLS natively.
