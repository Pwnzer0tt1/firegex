# 🧱 Firewall Rules

Firewall Rules is a plain [nftables](https://netfilter.org/) allow/drop/reject rule manager — no packet inspection, no filtering module attached, just classic firewall rules. Use it to restrict which hosts/ports can reach the machine (or be reached by it) alongside the other, traffic-inspecting modules.

## How to use it

Each rule matches on:

- **Protocol**: `tcp`, `udp`, `both` (adds a matching TCP and UDP rule) or `any` (matches all protocols, ports are ignored).
- **Source / Destination**: an IP/CIDR, or an interface name (e.g. `eth0`) instead of an address.
- **Source / Destination port range**: `from`/`to` for each side; leave as the full `1-65535` range to match any port.
- **Direction** (`mode`): `in` (incoming traffic — the nftables `INPUT`/`PREROUTING` hook), `out` (outgoing traffic — `OUTPUT`/`POSTROUTING`), or `forward` (traffic routed through this host, `FORWARD` — only meaningful with the `filter` table, see below).
- **Table**: `filter` — standard firewall rules evaluated at the normal input/output/forward hooks; `mangle` — rules evaluated earlier in the pipeline (`prerouting`/`postrouting`, before routing decisions), useful when a rule needs to run before other processing (e.g. before a [Hijack Port to Proxy](porthijack.md) or [TLS Decrypt](tls.md) rule takes effect on the same traffic).
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

Rules are compiled directly into nftables' JSON rule format and applied via the nftables JSON API — there's no packet interception/inspection involved (unlike [Netfilter Regex](nfregex.md) or [Netfilter Proxy](nfproxy.md), which sit in front of a service via nfqueue). Firegex maintains its own dedicated chains (jumped to from the base `INPUT`/`OUTPUT`/`FORWARD` filter hooks and `PREROUTING`/`POSTROUTING` mangle hooks) so its rules can be fully reset without touching anything else on the system.
