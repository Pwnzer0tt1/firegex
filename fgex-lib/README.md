# Firegex Python Library and CLI

This is the Python library for [Firegex](https://github.com/Pwnzer0tt1/firegex), a firewall built for CTF Attack-Defense competitions. It provides `firegex.pyfilters` — the package you write [Python filters](../docs/pyfilter.md) against — `firegex.regex` for pattern rulesets, the `fgex` CLI, and local simulators for both, so a filter can be tried before it ever reaches a running Firegex.

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

## The rest of Firegex

This package is the part you write filters *with*. What runs them is a Firegex instance,
started from a clone with `python3 run.py` — there is deliberately no deploy command here,
because any second description of that script's arguments would drift from it.

Two guides cover everything an instance does:

- **[Services](../docs/services.md)** — a service is a **network layer** (NFQUEUE, the
  terminating proxy, or a hand-off to a proxy you wrote) plus an ordered chain of
  **filters** (hyperscan patterns, or the Python you write with this library). TLS, QUIC
  and every version of HTTP are protocols a service can speak rather than separate things
  to set up.
- **[Firewall Rules](../docs/firewall.md)** — plain nftables allow/drop/reject rules.

The modules this library used to list — `nfregex`, `nfproxy`, `porthijack` and `tls` —
were folded into services as choices rather than modules in 5.0.0, which is also when
`firegex.nfproxy` became `firegex.pyfilters`.
