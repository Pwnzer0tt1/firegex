# 🧱 Firewall Rules

Plain [nftables](https://netfilter.org/) allow/drop/reject rules — no inspection, like ufw
or iptables, from the interface. Use it to restrict who can reach the machine alongside the
[services](services.md) that inspect traffic.

## Rules

Each rule matches on:

- **Protocol**: `tcp`, `udp`, `both`, or `any` (ports ignored).
- **Source / destination**: an IP/CIDR or an interface name (≤ 15 chars of letters, digits
  and `_.:-`, optionally ending in `*` — `br-*`).
- **Source / destination port range**; `1-65535` matches any.
- **Direction**: `in`, `out`, or `forward` (routed through this host; `filter` table only).
- **Table**: `filter` (input/output/forward hooks) or `mangle` (prerouting/postrouting,
  before routing).
- **Action**: `accept`, `drop`, or `reject` (ICMP/RST reply). `reject` on `out` acts as
  `drop`.

Rules are evaluated in order; the first match wins. Unmatched incoming and forwarded
traffic gets the global **policy**; outgoing traffic is always allowed. A change nftables
refuses is refused whole — the firewall in force and the saved configuration stay as they
were.

## Global settings

- **keep_rules** — leave the rules applied when firegex stops, so the host doesn't open up
  on a restart or crash.
- **allow_loopback**, **allow_established**, **drop_invalid**, **allow_icmp**,
  **allow_dhcp**, **multicast_dns**, **allow_upnp** — shortcut accept/drop rules placed
  before yours.
- **allow_dnat** (on by default) — container traffic is left to Docker/podman's own rules
  when none of yours matched: published container ports (and other DNATed traffic), and
  anything from `docker0`, `br-*`, `docker_gwbridge`, `podman*`, `cni-podman*`. Without it
  a `drop` policy cuts off published containers and containers talking to each other. Your
  `forward` rules still apply first.

## How it works

Rules are compiled to nftables JSON. Everything lives in firegex's own tables —
`fgex_filter` and `fgex_mangle` per family — and every object is named `fgex_`:

```bash
sudo nft list ruleset | grep -A100 fgex_
```

- **`iptables` keeps working**, since firegex never writes into the tables `iptables-nft`
  uses, and turning firegex off never touches the host's own chains or policy.
- **If something removes the tables** (`flush ruleset`, `systemctl restart nftables`),
  firegex puts them back within a few seconds and logs the gap. Better to make your
  nftables config leave the `fgex` tables alone.
- **"Accept" means firegex doesn't block it**, not that nothing else will; other base
  chains at the same hook still apply. A `drop` is final.
- A rule's **table** field is the hook it runs at, not the nftables table it lands in.

Upgrading from a version that wrote into the shared `filter`/`mangle` tables? Its leftovers
are still there — check `sudo nft list table ip filter` (and `ip6`, and mangle) once and
clear them by hand.
