use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use fgex_proxy::control::serve_stdin;
use fgex_proxy::filter::{ChainHandle, FilterChain};
use fgex_proxy::proxy::{Proxy, ProxyConfig, TlsSetup, Upstream};
use fgex_proxy::spec::parse_filters;
use fgex_proxy::transparent::probe_capability;

/// How often the engine reports its connection counters. One short line, so the cost is
/// nothing; the first is sent immediately so a freshly started service has a baseline
/// rather than an unknown for the first interval.
const STATS_INTERVAL: Duration = Duration::from_secs(2);

fn env_or_exit(key: &str) -> String {
    match std::env::var(key) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[fatal] [main] {key} is required");
            exit(2);
        }
    }
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).unwrap_or_default().trim(),
        "1" | "true" | "yes"
    )
}

fn parse_addr(key: &str, raw: &str) -> SocketAddr {
    match raw.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[fatal] [main] {key}='{raw}' is not a valid address: {e}");
            exit(2);
        }
    }
}

/// `FGEX_PROXY_TLS_CERT` / `_KEY` are paths, not the material itself: a certificate
/// on a command line or in an env dump is a certificate in a log somewhere.
fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.trim().parse().ok()
}

fn build_tls() -> Result<TlsSetup, String> {
    let cert_path = std::env::var("FGEX_PROXY_TLS_CERT").ok();
    let key_path = std::env::var("FGEX_PROXY_TLS_KEY").ok();
    let server = match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            let cert =
                std::fs::read_to_string(&cert).map_err(|e| format!("cannot read {cert}: {e}"))?;
            let key =
                std::fs::read_to_string(&key).map_err(|e| format!("cannot read the key: {e}"))?;
            Some(fgex_proxy::tls::server_config(&cert, &key)?)
        }
        (None, None) => None,
        _ => return Err("FGEX_PROXY_TLS_CERT and FGEX_PROXY_TLS_KEY go together".to_string()),
    };
    let upstream = if env_flag("FGEX_PROXY_TLS_UPSTREAM") {
        Some(fgex_proxy::tls::client_config()?)
    } else {
        None
    };
    Ok(TlsSetup { server, upstream })
}

/// Answer one regex-debug request and exit, instead of starting a datapath.
///
/// Its own mode rather than a long-running service: the backend asks rarely, an
/// operator's half-written pattern must not be able to affect anything that is
/// carrying traffic, and a process that exits cannot leak scratch space or state
/// between requests.
fn debug_regex() -> ! {
    use std::io::Read;
    let mut request = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut request) {
        eprintln!("[fatal] [debug] cannot read the request: {e}");
        exit(2);
    }
    let response = fgex_proxy::debug::run(&request);
    match serde_json::to_string(&response) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("[fatal] [debug] cannot encode the response: {e}");
            exit(2);
        }
    }
    exit(0);
}

/// How many worker threads the runtime gets.
///
/// `NTHREADS` is what `run.py --threads` sets, and it used to reach only the NFQUEUE
/// binaries — this engine took every core whatever the operator asked for, so the same
/// flag meant one thing on one layer and nothing on the other. It means the same thing
/// on both now. Absent or unparseable is "as many as there are cores", which is tokio's
/// own default and the right answer when nobody has said otherwise.
fn worker_threads() -> usize {
    std::env::var("NTHREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}

fn main() {
    // Built by hand rather than through `#[tokio::main]`, which offers no way to say how
    // many workers it should have.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads())
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[fatal] [main] cannot start the runtime: {e}");
            exit(1);
        }
    };
    runtime.block_on(run());
}

async fn run() {
    // Checked before anything else reads the environment: this mode starts no
    // listener, opens no sockets and touches no rules.
    if std::env::args().any(|a| a == "--debug-regex") {
        debug_regex();
    }

    let listen_raw = env_or_exit("FGEX_PROXY_LISTEN");
    let listen = parse_addr("FGEX_PROXY_LISTEN", &listen_raw);

    // "original" puts one listener in front of every intercepted service; a literal
    // address keeps the simpler one-listener-one-service shape.
    let upstream_raw = env_or_exit("FGEX_PROXY_UPSTREAM");
    let upstream = if matches!(upstream_raw.trim(), "original" | "auto") {
        Upstream::Original
    } else {
        Upstream::Fixed(parse_addr("FGEX_PROXY_UPSTREAM", &upstream_raw))
    };

    // Only the outbound dial needs IP_TRANSPARENT now: the listener is a plain one
    // that traffic is redirected into. Binding a foreign address was a tproxy
    // requirement, and tproxy is gone.
    let spoof_source = env_flag("FGEX_PROXY_SPOOF_SOURCE");

    // Fail here rather than per connection: a missing CAP_NET_ADMIN would otherwise
    // show up only as every service seeing the proxy's address instead of the client's.
    if spoof_source {
        if let Err(e) = probe_capability(listen.is_ipv6()) {
            eprintln!(
                "[fatal] [main] transparent mode needs CAP_NET_ADMIN, IP_TRANSPARENT failed: {e}"
            );
            exit(1);
        }
    }

    let deadline = std::env::var("FGEX_PROXY_FILTER_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(200);
    let connect_timeout = std::env::var("FGEX_PROXY_CONNECT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5000);

    let specs = std::env::var("FGEX_PROXY_FILTERS").unwrap_or_default();
    let filters = match parse_filters(&specs) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[fatal] [main] bad FGEX_PROXY_FILTERS: {e}");
            exit(2);
        }
    };

    // TLS terminated here rather than by an nginx in front. Rules see plaintext that
    // never leaves the process.
    let tls = match build_tls() {
        Ok(setup) => setup,
        Err(e) => {
            eprintln!("[fatal] [main] {e}");
            exit(2);
        }
    };

    // Stamped on every socket this engine opens towards a service, so the rules that
    // intercept that service can tell our own dial from the traffic they are meant to
    // catch. Read once: the UDP relays need the same mark as the TCP path.
    let cfg_self_mark = std::env::var("FGEX_PROXY_SELF_MARK")
        .ok()
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .or(Some(fgex_proxy::transparent::SELF_MARK));

    // Read once and shared by both paths: TCP connections and UDP flows are the same
    // resource being defended, and two numbers meaning "how much of it may be spent"
    // would be two things to keep in step.
    let max_connections = env_usize("FGEX_PROXY_MAX_CONNECTIONS").unwrap_or(0);
    let over_limit_forwards = env_flag("FGEX_PROXY_OVER_LIMIT_FORWARD");
    // In seconds, because that is the unit an operator thinks in for "how long may a
    // connection say nothing". Zero and absent both mean off.
    let first_byte_timeout = match env_usize("FGEX_PROXY_FIRST_BYTE_TIMEOUT").unwrap_or(0) {
        0 => None,
        secs => Some(Duration::from_secs(secs as u64)),
    };

    let cfg = ProxyConfig {
        listen,
        upstream,
        spoof_source,
        connect_timeout: Duration::from_millis(connect_timeout),
        tls,
        // Opened once for the process and shared: the interface exists only while some
        // TLS service is running, and `None` here simply means nothing is watching.
        capture: fgex_proxy::capture::Capture::open(),
        // Zero means no limit, which is what it was before there was one. The backend
        // always sends a value; the default here is for anyone running the engine by
        // hand, where a surprise limit would be worse than none.
        max_connections,
        over_limit_forwards,
        first_byte_timeout,
        self_mark: cfg_self_mark,
    };
    let chain = ChainHandle::new(FilterChain::new(filters, Duration::from_millis(deadline)));
    let chain_handle = chain.clone();
    let proxy = match Proxy::bind(cfg, chain).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[fatal] [main] cannot bind {listen}: {e}");
            exit(1);
        }
    };

    // Handshake, in the shape the other engines use (`QUEUE <n>` from cppregex):
    // one machine-readable line on stdout, so the caller can pass port 0 and learn
    // which port it actually got. Everything descriptive goes to stderr.
    let bound = proxy.local_addr().unwrap();
    // Taken before the UDP relays are built: they share it, so one service reports one
    // pair of numbers whichever half of it the traffic arrived on.
    let counters = proxy.stats();

    println!("PORT {}", bound.port());
    use std::io::Write;
    let _ = std::io::stdout().flush();
    eprintln!(
        "[info] [main] listening on {bound} -> {upstream_raw} \
         (spoof_source={spoof_source})"
    );

    // Rulesets arrive on stdin from here on. It runs alongside the datapath rather
    // than gating it: traffic must flow before, during and after a rule change.
    let deadline_dur = Duration::from_millis(deadline);
    let control_chain = chain_handle.clone();
    tokio::spawn(async move { serve_stdin(control_chain, deadline_dur).await });

    // How many connections have been through, reported on a timer rather than one
    // line per connection: the backend wants a denominator, not a firehose. Counted
    // where the connection is accepted and where a filter refuses it, so both numbers
    // are in the same unit and their ratio means something — unlike a share computed
    // against a packet count, which is what the kernel can offer and a block is not.
    // UDP, when the backend asks for it: a comma-separated list of protected
    // addresses, one relay each. One socket per address rather than one for all of
    // them, because `SO_ORIGINAL_DST` — which is how the TCP side learns where a
    // connection was headed — is TCP and SCTP only. With the upstream fixed per socket
    // there is nothing to recover.
    //
    // The client's address is *not* preserved on this path, and that is the trade the
    // operator is shown before choosing it.
    if let Ok(spec) = std::env::var("FGEX_PROXY_UDP") {
        for target in spec.split(',').filter(|s| !s.trim().is_empty()) {
            let upstream = parse_addr("FGEX_PROXY_UDP", target.trim());
            let bind: SocketAddr = if upstream.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            let relay = match fgex_proxy::udp::UdpRelay::bind(
                bind,
                upstream,
                chain_handle.clone(),
                cfg_self_mark,
                max_connections,
                over_limit_forwards,
                Arc::clone(&counters),
            )
            .await
            {
                Ok(relay) => relay,
                Err(e) => {
                    eprintln!("[fatal] [main] cannot bind a UDP relay for {upstream}: {e}");
                    exit(1);
                }
            };
            // One line per relay, so the backend can point each address's rule at the
            // port that actually fronts it.
            println!("UDP {} {}", upstream, relay.local_addr().unwrap().port());
            let _ = std::io::stdout().flush();
            tokio::spawn(async move {
                if let Err(e) = relay.serve().await {
                    eprintln!("[fatal] [udp] relay for {upstream} died: {e}");
                }
            });
        }
    }

    // Both counters live on the proxy, not on the chain: a chain is replaced wholesale
    // every time a ruleset is pushed, and counters that reset on a rule edit would make
    // the ratio jump for a reason nobody could see.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(STATS_INTERVAL);
        loop {
            // The first tick fires immediately, which is the point: zero out of zero is
            // a baseline, and "no answer yet" is not.
            tick.tick().await;
            // `live` and `over_limit` ride along with the two that were already here:
            // the backend parses this line as key/value pairs, so a new number costs no
            // protocol. `over_limit` is cumulative on purpose — a service that hit the
            // wall once an hour ago still says so, which is the whole point of a trace.
            println!(
                "STATS seen={} refused={} live={} over_limit={} no_first_byte={}",
                counters.accepted.load(std::sync::atomic::Ordering::Relaxed),
                counters.closed_by_filter.load(std::sync::atomic::Ordering::Relaxed),
                counters.live.load(std::sync::atomic::Ordering::Relaxed),
                counters.over_limit.load(std::sync::atomic::Ordering::Relaxed),
                counters.no_first_byte.load(std::sync::atomic::Ordering::Relaxed),
            );
            let _ = std::io::stdout().flush();
        }
    });

    if let Err(e) = proxy.serve().await {
        eprintln!("[fatal] [main] accept loop died: {e}");
        exit(1);
    }
}
