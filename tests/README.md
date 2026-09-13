# Firegex tests

## [GO BACK](../README.md)

One suite, one runner. Everything here is `pytest`; the **benchmarks** live in
[`bench/`](bench/README.md) and are not tests — they measure, so they have no pass or fail
and `pytest` does not collect them.

## Running them

```bash
./run_tests.sh                    # everything this host can run
./run_tests.sh --set-pass         # against an instance still in its initial-setup state
./run_tests.sh mypassword         # a different password
```

`run_tests.sh` installs the dependencies, waits for the instance to answer, and hands
everything else straight to pytest — so anything pytest understands works there, and
`pytest` on its own works too once the dependencies are in place.

Part of "in place" is a **build**: `unit/` imports the filter library out of
`../fgex-lib`, and that library carries a C extension — the llhttp binding that parses
HTTP. `run_tests.sh` builds it for you; doing it by hand once is enough:

```bash
pip install -e ../fgex-lib
```

Without it those tests cannot be collected at all, and pytest says
`ImportError: cannot import name '_llhttp' from 'firegex'`.

```bash
pytest                            # the same thing, if you already have the dependencies
pytest unit                       # the ones that need nothing running at all
pytest -k udp                     # one subject
pytest -m "not slow"              # skip the ones that sit and wait on a real timeout
pytest --layer proxy --no-ipv6    # one network layer, one address family
pytest --fg-address http://box:4444/ --fg-password hunter2
```

| Option | What it does |
|---|---|
| `--fg-address` | where the instance under test is (or `FIREGEX_ADDRESS`) |
| `--fg-password` | its password (or `FIREGEX_PASSWORD`) |
| `--layer` | only these network layers — `proxy`, `nfqueue`, `external`; repeatable |
| `--no-ipv6` | skip the IPv6 half of every parametrised case |
| `--no-tls` | skip the TLS cases |

Markers: `instance` (needs a live firegex), `root` (needs root and a Linux kernel with
nftables), `slow` (waits on a real timeout), `ipv6`, `tls`.

## What is where

| Directory | Needs a running instance | What it covers |
|---|---|---|
| `unit/` | no | `firegex.regex` against libhs, the `firegex.pyfilters` models and knobs, and the address-to-nftables translation in the backend's own modules |
| `integration/` | yes | the product: both network layers, both filter kinds, TLS, UDP, IPv6, the hand-off, addresses on a running service, statistics, logs, limits, resilience |
| `standalone/` | yes, and it restarts it | settings that are only read at process startup, so the test has to bounce the instance itself — **not** collected by default |
| `helpers/` | — | the API client, the stand-in services, certificates, and the traffic channel |
| `bench/` | yes | [measurement, not testing](bench/README.md) |

Most of `integration/` is **parametrised over the combinations**, which is the point of
the suite rather than a detail of it: a service is a network layer and a chain of filters
chosen independently, so the same filters are exercised on `proxy` and on `nfqueue`, over
IPv4 and IPv6, with and without TLS. A filter that works on one layer and not the other is
exactly the failure the unified model exists to prevent, and it only shows up if both are
run. Each case is a test with its own name, so a failure says which combination broke:

```
integration/test_filters_regex.py::test_a_matching_pattern_blocks[nfqueue-ipv6] FAILED
```

This used to be a shell script invoking one 1100-line program eight times with different
flags. The first failure in a run ended it, so the seven other combinations were never
reached, and a host without IPv6 on loopback failed rather than skipped.

**Run the suite twice in a row** when you have changed anything about addresses or TLS:
state left behind by the first pass only shows up on the second.

## Two that are not in the default run

- **`standalone/test_ip_filter.py`.** Access control by CIDR is read once, at process
  startup, so there is no way to test it against a running instance — it drives
  `run.py stop`/`start` itself for each scenario and restores an unrestricted instance at
  the end. Run it on its own, and expect it to bounce whatever you have running:
  ```bash
  pytest standalone
  ```
- **`bench/`.** Minutes rather than seconds, and it answers a different question. See
  [bench/README.md](bench/README.md).

## Adding a test

Put it in the directory that matches what it needs, and take the fixtures from the
conftest rather than building a service by hand — `protected` gives you a started-service
shape for whichever layer is being parametrised, `service` cleans up whatever you create,
and `Channel` asks a protected service a question without the test having to know whether
TLS is in the way. A leaked service is not untidiness: it holds a port and an nftables
rule, so the next test to want that port fails for a reason belonging to yours.

If a case cannot run on some hosts, **skip it with a reason** rather than letting it fail.
A red test nobody can act on teaches less than a summary line saying which half of the
suite this machine declined to run and why.
