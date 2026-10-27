# Firegex Python Library and CLI

The library for [Firegex](https://github.com/Pwnzer0tt1/firegex), a firewall for CTF
Attack-Defense competitions. It provides `firegex.pyfilters` (write [Python
filters](../docs/pyfilter.md)), `firegex.regex` (pattern rulesets), and the `fgex` CLI to
try both locally without a running Firegex.

```bash
pip install -U firegex     # `fgex` is an alias package
```

```bash
fgex pyfilters filter.py 127.0.0.1 8080        # run a Python filter in front of a service
fgex regex check rules.json                    # does the ruleset compile?
fgex regex test  rules.json --sample req.txt   # what would it do to this?
fgex regex proxy rules.json 10.60.3.1 8080     # a local proxy applying it
```

Regex matching needs `libhs` (vectorscan) installed — the same engine Firegex uses; without
it the tools stop rather than guess.

- **[Python filters](../docs/pyfilter.md)** — the decorator, every model, settings, examples.
- **[Services](../docs/services.md)** — what a Firegex instance does with them.
- **[Firewall Rules](../docs/firewall.md)**

A Firegex instance is started from a clone with `python3 run.py`. In 5.0.0 `firegex.nfproxy`
became `firegex.pyfilters`.
