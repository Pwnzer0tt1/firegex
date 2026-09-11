//! The control channel: one JSON ruleset per line on stdin, one ACK per line out.
//!
//! Same shape the NFQUEUE engines use, so the backend side is the code it already
//! has: write the whole ruleset, wait for `ACK OK` or `ACK FAIL <why>`.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};

use crate::filter::{ChainHandle, FilterChain};
use crate::rules::parse_ruleset;
use crate::udp::UdpManager;

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
pub async fn serve_stdin(chain: ChainHandle, deadline: Duration, udp: UdpManager) {
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

        if let Some(rest) = trimmed.strip_prefix("ADD_UDP ") {
            let target_str = rest.trim();
            match target_str.parse::<SocketAddr>() {
                Ok(upstream) => match udp.add_relay(upstream).await {
                    Ok(port) => {
                        println!("UDP {upstream} {port}");
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
