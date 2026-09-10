# 🧱 Firewall Rules

Firewall Rules is a plain [nftables](https://netfilter.org/) allow/drop/reject rule manager — no packet inspection, no filtering module attached, just classic firewall rules. Use it to restrict which hosts/ports can reach the machine (or be reached by it) alongside the other, traffic-inspecting modules.

## How to use it

Each rule matches on:

- **Protocol**: `tcp`, `udp`, `both` (adds a matching TCP and UDP rule) or `any` (matches all protocols, ports are ignored).
- **Source / Destination**: an IP/CIDR, or an interface name (e.g. `eth0`) instead of an address.
- **Source / Destination port range**: `from`/`to` for each side; leave as the full `1-65535` range to match any port.
- **Direction** (`mode`): `in` (incoming traffic — the nftables `INPUT`/`PREROUTING` hook), `out` (outgoing traffic — `OUTPUT`/`POSTROUTING`), or `forward` (traffic routed through this host, `FORWARD` — only meaningful with the `filter` table, see below).
- **Table**: `filter` — standard firewall rules evaluated at the normal input/output/forward hooks; `mangle` — rules evaluated earlier in the pipeline (`prerouting`/`postrouting`, before routing decisions), useful when a rule needs to run before other processing (e.g. before a an external-proxy [service](services.md) or TLS rule takes effect on the same traffic).
- **Action**: `accept`, `drop`, or `reject` (closes the connection with an ICMP/RST reply instead of silently dropping it). `reject` on outgoing (`out`) traffic isn't meaningful — Firegex silently treats it as `drop` in that direction.

Rules are evaluated in order; the first match wins. Traffic that matches no rule falls through to the global **policy** (`accept`/`drop`/`reject`), which applies to incoming and forwarded traffic — outgoing traffic is always allowed by default regardless of the policy, so Firegex itself is never at risk of losing its own outbound connectivity by misconfiguring rules.

### Global settings

Beyond the rule list and policy, a few toggles affect the whole module:

- **keep_rules**: if enabled, the nftables rules stay applied when Firegex shuts down instead of being torn down — useful so the firewall doesn't silently open up if the Firegex process/container restarts or crashes.
- **allow_loopback**: always accept traffic on the loopback interface, regardless of other rules.
- **allow_established**: always accept traffic belonging to an already-established/related connection, so rules only need to cover new connections.
- **drop_invalid**: drop packets nftables' connection tracking considers invalid (malformed/out-of-state).
- **allow_icmp**: always accept ICMP (ping, etc.).
- **allow_dhcp**: always accept DHCP traffic.
- **multicast_dns**: always accept mDNS (multicast DNS) traffic.
- **allow_upnp**: always accept UPnP traffic.

Each of these, when enabled, inserts a small accept rule ahead of your own rules — they're conveniences for common cases you'd otherwise have to write by hand.

## How it works

Rules are compiled directly into nftables' JSON rule format and applied via the nftables JSON API — there's no packet interception/inspection involved (unlike [services](services.md), which sit in front of a service and inspect its traffic).

**Everything Firegex installs lives in tables of its own, and every object is named `fgex_`.** The filter rules go in `fgex_filter` and the mangle ones in `fgex_mangle` (one of each per address family), with base chains `fgex_input`, `fgex_forward`, `fgex_output`, `fgex_prerouting` and `fgex_postrouting` handing over to `fgex_rules_in`, `fgex_rules_out` and `fgex_rules_fwd`. You can see the whole of it with:

```bash
sudo nft list ruleset | grep -A100 fgex_
```

Two things follow from Firegex owning those tables rather than writing into the ones `iptables` uses:

- **`iptables` keeps working.** Earlier versions put their chains into the tables named `filter` and `mangle`, which is where `iptables-nft` — the default `iptables` on most current distributions — keeps its own. `iptables` rejects a whole table as soon as it contains a rule it cannot express in its own format, and the connection-tracking rules Firegex writes for **allow_established** and **drop_invalid** are exactly that. The result was `iptables -L` and `iptables-save` answering ``table `filter' is incompatible, use 'nft' tool`` on a host where Docker, ufw, fail2ban or the organisers' own scripts were the ones asking. That cannot happen now: `iptables` never looks at a table Firegex owns.
- **Turning the firewall off no longer touches the host's own.** The default policy is a property of a base chain, and it used to be *your* `INPUT` chain that Firegex set to `drop` — and set back to `accept` on shutdown, silently undoing a default-deny an administrator had configured elsewhere. Firegex now sets the policy on its own base chain, so a reset is just deleting two tables.

If you are upgrading from a version that used the shared tables, whatever it left behind is still there — Firegex does not go looking in tables it no longer owns. Clear it by hand once, and check the policy while you are there, since an older Firegex was the one driving it:

```bash
sudo nft list table ip filter    # and ip6, and the mangle pair
```

A rule's **table** field (`filter` or `mangle`) still means what it always did — it's the hook the rule is evaluated at, not the name of the nftables table it ends up in.

Note that "accept" here means *Firegex* does not block the packet, not that nothing else will: other base chains at the same hook still get their say, exactly as they do between any two nftables tables. A `drop`, on the other hand, is final wherever it comes from.
