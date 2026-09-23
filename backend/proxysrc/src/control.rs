//! The control channel: one JSON ruleset per line on stdin, one ACK per line out.
//!
//! Same shape the NFQUEUE engines use, so the backend side is the code it already
//! has: write the whole ruleset, wait for `ACK OK` or `ACK FAIL <why>`.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};

use crate::filter::{ChainHandle, FilterChain};
use crate::proxy::{Edge, Onward, Published, Targets};
use crate::relays::Relays;
use crate::rules::parse_ruleset;

fn ack(ok: bool, detail: &str) {
    if ok {
        println!("ACK OK");
    } else {
        println!("ACK FAIL {detail}");
    }
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Apply rulesets and handle control commands until stdin closes.
///
/// A rejected update leaves the running chain in place: the engine keeps enforcing
/// what it already had rather than falling back to enforcing nothing, which is the
/// opposite of the fail-open rule and deliberately so. Failing open covers a filter
/// that breaks at runtime; it is not a licence to silently drop a ruleset the
/// operator asked for.
pub async fn serve_stdin(
    chain: ChainHandle,
    deadline: Duration,
    relays: Relays,
    targets: std::sync::Arc<Targets>,
) {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            // stdin closed: the backend is gone. Keep serving traffic with the
            // ruleset we have — the datapath outliving its control channel is the
            // whole point of failing open.
            Ok(None) => {
                eprintln!("[info] [control] stdin closed, keeping the current ruleset");
                return;
            }
            Err(e) => {
                eprintln!("[warn] [control] cannot read stdin: {e}");
                return;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // `ADD_UDP` whatever is behind it: the command names what the *rules* match on,
        // and a QUIC service is UDP to the kernel. The backend asks for a port to point
        // an address at, and that question has one answer whichever relay gives it.
        if let Some(rest) = trimmed.strip_prefix("ADD_UDP ") {
            // `<address>` or `<address> <onward>` — what the service behind this relay
            // speaks, which is the relay's own answer and not the process's.
            let mut parts = rest.split_whitespace();
            let target_str = parts.next().unwrap_or("").trim();
            let onward = match parts.next() {
                None => Onward::Same,
                Some(word) => match Onward::from_word(word) {
                    Some(onward) => onward,
                    None => {
                        let err = format!("unknown upstream {word:?}");
                        eprintln!("[warn] [control] {err}");
                        ack(false, &err);
                        continue;
                    }
                },
            };
            match target_str.parse::<SocketAddr>() {
                Ok(upstream) => match relays.add_relay(upstream, onward).await {
                    Ok(port) => {
                        println!("UDP {upstream}|{} {port}", onward.word());
                        ack(true, "");
                    }
                    Err(e) => {
                        eprintln!("[warn] [control] failed to add UDP relay for {upstream}: {e}");
                        ack(false, &e.to_string());
                    }
                },
                Err(e) => {
                    let err = format!("invalid target address {target_str}: {e}");
                    eprintln!("[warn] [control] {err}");
                    ack(false, &err);
                }
            }
            continue;
        }

        // `PUBLISH <dialled> <target>` and `WITHDRAW <dialled>`: one address is being
        // served on a port the service does not listen on. Sent while the engine runs
        // because an address can be added to a running service, and the startup list
        // (`FGEX_PROXY_TARGETS`) says the same thing for the ones it began with.
        if let Some(rest) = trimmed.strip_prefix("PUBLISH ") {
            // `PUBLISH <dialled> <edge> <onward> [<service>]`: what is spoken at one
            // address, what is spoken to the service behind it, and — where it is not
            // simply the service — where that service is. A dash for the last says the
            // address *is* the service, which is every address until an operator says
            // otherwise.
            let mut parts = rest.split_whitespace();
            let public = parts.next().map(str::parse::<SocketAddr>);
            let edge = match parts.next() {
                Some("tls") => Some(Edge::Tls),
                Some("any") | Some("clear") | None => Some(Edge::Whatever),
                Some(_) => None,
            };
            let onward = match parts.next() {
                Some("plain") => Some(Onward::Plain),
                Some("tls") => Some(Onward::Tls),
                Some("same") | None => Some(Onward::Same),
                Some(_) => None,
            };
            let target = match parts.next() {
                None | Some("-") => Ok(None),
                Some(addr) => addr.parse::<SocketAddr>().map(Some),
            };
            match (public, edge, onward, target) {
                (Some(Ok(public)), Some(edge), Some(upstream), Ok(target)) => {
                    targets.publish(public, Published { target, edge, upstream });
                    match target {
                        Some(target) => {
                            eprintln!("[info] [control] {public} now fronts {target}")
                        }
                        None => eprintln!("[info] [control] {public} declared"),
                    }
                    ack(true, "");
                }
                _ => {
                    let err =
                        format!("PUBLISH wants `<address> <edge> <onward> [<service>]`, got {rest:?}");
                    eprintln!("[warn] [control] {err}");
                    ack(false, &err);
                }
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("WITHDRAW ") {
            match rest.trim().parse::<SocketAddr>() {
                Ok(public) => {
                    targets.withdraw(&public);
                    ack(true, "");
                }
                Err(e) => {
                    let err = format!("invalid address {rest:?}: {e}");
                    eprintln!("[warn] [control] {err}");
                    ack(false, &err);
                }
            }
            continue;
        }

        match parse_ruleset(trimmed).and_then(|filters| {
            // Everything that has to be started is started here, while the old chain
            // is still the one enforcing.
            for filter in &filters {
                filter.prepare()?;
            }
            Ok(filters)
        }) {
            Ok(filters) => {
                let n = filters.len();
                chain.replace(FilterChain::new(filters, deadline));
                eprintln!("[info] [control] ruleset replaced, {n} rule(s) active");
                ack(true, "");
            }
            Err(e) => {
                eprintln!("[warn] [control] ruleset rejected, keeping the previous one: {e}");
                ack(false, &e);
            }
        }
    }
}
