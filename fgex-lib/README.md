# Firegex Python Library and CLI

This is the Python library for [Firegex](https://github.com/Pwnzer0tt1/firegex), a firewall built for CTF Attack-Defense competitions. It provides the `firegex.pyfilters` package used to write [Python filter](../docs/pyfilter.md) Python packet filters, the `fgex` CLI, and a local proxy simulator (`proxysim`) for testing filters without a running Firegex instance.

## Installation

```bash
pip install -U firegex
```

`fgex` is an alias package for `firegex`: installing either one gives you the same `firegex` module and the `fgex`/`firegex` CLI commands.

## Documentation

It carries `firegex.regex`, which binds the same hyperscan firegex matches with, so
a **pattern ruleset** can be checked and tried without a running instance:

```bash
fgex regex check rules.json                    # does it compile? what is in it?
fgex regex test  rules.json --sample req.txt   # what would it do to this?
fgex regex proxy rules.json 10.60.3.1 8080     # a local proxy applying it
```

The ruleset file is the same shape firegex uses. Matching needs `libhs` (vectorscan)
installed; without it the tools say so and stop rather than answering with a different
engine, because a tester that disagrees with production is worse than none.

**➡️ [Writing and testing `@pyfilter` scripts](../docs/pyfilter.md)** — the `pyfilter` decorator, every data structure (`RawPacket`, `TCPInputStream`/`TCPOutputStream`, `HttpRequest`/`HttpResponse` and their variants, `HttpHistory`), packet statements, stream limits, the `fgex pyfilters` CLI simulator, and a full worked example.

That page is also what's shown in the Firegex web UI itself (the docs button on the service pages) — both are generated from that single file, so they can never drift out of sync.

## Firegex's other filtering modules

This library only covers Netfilter Proxy. Firegex ships several other independent modules, each with its own guide:

- **[Services](../docs/services.md)** — fast, PCRE2/hyperscan-based regex matching against raw traffic.
- **[Hijack Port to Proxy](../docs/porthijack.md)** — redirect traffic to your own external proxy without touching the target service.
- **[Firewall Rules](../docs/firewall.md)** — plain nftables allow/drop/reject rules.
- **[Services](../docs/services.md)** — decrypt-and-reinspect bridge for services that speak TLS natively.
