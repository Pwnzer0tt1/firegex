use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use fgex_proxy::control::serve_stdin;
use fgex_proxy::filter::{ChainHandle, FilterChain};
use fgex_proxy::proxy::{Proxy, ProxyConfig, TlsSetup, Upstream};
use fgex_proxy::quic::{QuicConfig, QuicManager, QuicSetup};
use fgex_proxy::relays::Relays;
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

/// The certificate and key this service terminates with, read once.
///
/// Read rather than passed: a certificate on a command line or in an environment dump is
/// a certificate in a log somewhere. Both edges that need it — TLS over TCP and QUIC —
/// ask for the same pair, so it is read here and handed to whichever wants it.
fn read_material() -> Result<Option<(String, String)>, String> {
    let cert_path = std::env::var("FGEX_PROXY_TLS_CERT").ok();
    let key_path = std::env::var("FGEX_PROXY_TLS_KEY").ok();
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            let certificate =
                std::fs::read_to_string(&cert).map_err(|e| format!("cannot read {cert}: {e}"))?;
            let key =
                std::fs::read_to_string(&key).map_err(|e| format!("cannot read the key: {e}"))?;
            Ok(Some((certificate, key)))
        }
        (None, None) => Ok(None),
        _ => Err("FGEX_PROXY_TLS_CERT and FGEX_PROXY_TLS_KEY go together".to_string()),
    }
}

fn build_tls(material: Option<&(String, String)>, optional: bool) -> Result<TlsSetup, String> {
    let server = match material {
        Some((cert, key)) => Some(fgex_proxy::tls::server_config(cert, key)?),
        None => None,
    };
    // Built whenever this engine terminates anything, and *used* per address: whether a
    // given connection is re-encrypted on the way out is the address's answer
    // (`Onward`), not the process's. A plain TCP service terminates nothing, so it has
    // no client configuration and never did — which is why none of this reaches it.
    let upstream = match server {
        Some(_) => Some(fgex_proxy::tls::client_config()?),
        None => None,
    };
    Ok(TlsSetup {
        server,
        upstream,
        optional,
    })
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
        .unwrap_or(2000);
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

    // Read before either edge is built: TLS over TCP and QUIC terminate with the same
    // certificate, and a service speaks one of them or the other.
    let material = match read_material() {
        Ok(material) => material,
        Err(e) => {
            eprintln!("[fatal] [main] {e}");
            exit(2);
        }
    };

    // QUIC is UDP on the wire, so it takes the place of the datagram relays rather than
    // sitting beside them: the same map of one port per protected address, bound by
    // something that terminates instead of something that forwards.
    let quic = env_flag("FGEX_PROXY_QUIC");

    // Whether the TCP listener terminates TLS, and whether it insists on it.
    //
    // `FGEX_PROXY_TLS_OPTIONAL` is what an `http` service sets: one certificate, one
    // chain, and each connection carried as whatever the client opened it with — in the
    // clear on one port and under TLS on another. It also means TLS on TCP and QUIC on
    // UDP live in **one** engine process, which they could not before: the two used to be
    // exclusive here, on the reasoning that a service speaks one or the other, and an
    // HTTP service speaks both.
    let tls_optional = env_flag("FGEX_PROXY_TLS_OPTIONAL");
    // Absent, the old rule: a certificate means terminate, unless this is a QUIC service,
    // where the certificate belongs to the QUIC edge and the TCP listener has nothing
    // pointed at it. Said explicitly by anything that wants both.
    let terminate_tls = env_flag("FGEX_PROXY_TLS") || tls_optional || !quic;
    let tls = match build_tls(
        if terminate_tls { material.as_ref() } else { None },
        tls_optional,
    ) {
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

    // Opened once for the process and shared by every path that reconstructs something:
    // the interface belongs to the instance, not to a service or a connection.
    let capture = fgex_proxy::capture::Capture::open();

    // Where each published address sends its traffic, for the ones this engine starts
    // with. `10.0.0.1:443=10.0.0.1:80` reads as "what arrives at the first is the
    // service at the second" — an address published on a port the service does not
    // listen on. Absent, and for every address not named, the answer is the address
    // itself, which is what transparent means and what every service had before.
    let targets = std::sync::Arc::new(fgex_proxy::proxy::Targets::default());
    if let Ok(spec) = std::env::var("FGEX_PROXY_TARGETS") {
        for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            // `10.0.0.1:443|tls=10.0.0.1:80`, and every part after the address optional:
            // the edge says what is spoken there and the target where the service is,
            // and an address that says neither is one this engine is simply in front of.
            let (address, target) = match entry.split_once('=') {
                Some((address, target)) => (
                    address,
                    Some(parse_addr("FGEX_PROXY_TARGETS", target.trim())),
                ),
                None => (entry, None),
            };
            // `<address>|<edge>|<onward>`, both words optional and both defaulting to
            // the answer every address gave before there was a question.
            let mut words = address.split('|');
            let address = words.next().unwrap_or(address);
            let edge = match words.next() {
                Some("tls") => fgex_proxy::proxy::Edge::Tls,
                None | Some("clear") | Some("any") => fgex_proxy::proxy::Edge::Whatever,
                Some(other) => {
                    eprintln!("[fatal] [main] FGEX_PROXY_TARGETS: unknown edge '{other}'");
                    exit(2);
                }
            };
            let upstream = match words.next() {
                Some("plain") => fgex_proxy::proxy::Onward::Plain,
                Some("tls") => fgex_proxy::proxy::Onward::Tls,
                None | Some("same") => fgex_proxy::proxy::Onward::Same,
                Some(other) => {
                    eprintln!("[fatal] [main] FGEX_PROXY_TARGETS: unknown upstream '{other}'");
                    exit(2);
                }
            };
            let public = parse_addr("FGEX_PROXY_TARGETS", address.trim());
            // Said out loud, because everything else about an address is visible in the
            // rules and this is not: it lives in this process and nowhere else, so an
            // operator wondering why a port behaves the way it does has nothing to read.
            eprintln!(
                "[info] [main] {public} carries {} to {}",
                match edge {
                    fgex_proxy::proxy::Edge::Tls => "TLS only",
                    _ => "whatever arrives",
                },
                match (target, upstream) {
                    (Some(target), fgex_proxy::proxy::Onward::Plain) => {
                        format!("{target} in the clear")
                    }
                    (Some(target), fgex_proxy::proxy::Onward::Tls) => format!("{target} on TLS"),
                    (Some(target), _) => format!("{target} as it arrived"),
                    (None, fgex_proxy::proxy::Onward::Plain) => "the service in the clear".into(),
                    (None, fgex_proxy::proxy::Onward::Tls) => "the service on TLS".into(),
                    (None, _) => "the service as it arrived".into(),
                }
            );
            targets.publish(public, fgex_proxy::proxy::Published { target, edge, upstream });
        }
    }

    let cfg = ProxyConfig {
        listen,
        upstream,
        spoof_source,
        connect_timeout: Duration::from_millis(connect_timeout),
        tls,
        // `None` simply means nothing is watching, which is the ordinary case.
        capture: capture.clone(),
        // Zero means no limit, which is what it was before there was one. The backend
        // always sends a value; the default here is for anyone running the engine by
        // hand, where a surprise limit would be worse than none.
        max_connections,
        over_limit_forwards,
        first_byte_timeout,
        self_mark: cfg_self_mark,
        targets: std::sync::Arc::clone(&targets),
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

    fgex_proxy::report::reply(format!("PORT {}", bound.port()));
    eprintln!(
        "[info] [main] listening on {bound} -> {upstream_raw} \
         (spoof_source={spoof_source})"
    );

    // The relays this service's addresses get, bound at startup and added to on demand.
    // Which kind is not a per-address choice: a service speaks QUIC or it speaks
    // datagrams, and the one it speaks is what every one of its addresses gets.
    let relays = if quic {
        let (cert, key) = match &material {
            Some(pair) => pair,
            None => {
                eprintln!(
                    "[fatal] [main] a QUIC service needs a certificate: QUIC carries TLS 1.3 \
                     inside it, and terminating it is the only way a filter sees anything"
                );
                exit(2);
            }
        };
        let setup = match QuicSetup::build(cert, key) {
            Ok(setup) => Arc::new(setup),
            Err(e) => {
                eprintln!("[fatal] [main] {e}");
                exit(2);
            }
        };
        eprintln!(
            "[info] [main] QUIC terminated here; each client's own protocols are offered \
             to the service"
        );
        Relays::Quic(QuicManager::new(
            chain_handle.clone(),
            QuicConfig {
                setup,
                capture: capture.clone(),
                self_mark: cfg_self_mark,
                spoof_source,
                max_connections,
                over_limit_forwards,
                first_byte_timeout,
                connect_timeout: Duration::from_millis(connect_timeout),
                // The default for a relay that was added without saying; the backend
                // says, per address, on `FGEX_PROXY_UDP` and on `ADD_UDP`.
                upstream: fgex_proxy::proxy::Onward::Same,
            },
            Arc::clone(&counters),
        ))
    } else {
        Relays::Datagram(fgex_proxy::udp::UdpManager::new(
            chain_handle.clone(),
            cfg_self_mark,
            spoof_source,
            max_connections,
            over_limit_forwards,
            Arc::clone(&counters),
        ))
    };

    // UDP, when the backend asks for it: a comma-separated list of protected
    // addresses, one relay each. One socket per address rather than one for all of
    // them, because `SO_ORIGINAL_DST` — which is how the TCP side learns where a
    // connection was headed — is TCP and SCTP only. With the upstream fixed per socket
    // there is nothing to recover.
    if let Ok(spec) = std::env::var("FGEX_PROXY_UDP") {
        for target in spec.split(',').filter(|s| !s.trim().is_empty()) {
            // `<address>` or `<address>|<onward>`: what the service behind this one
            // relay speaks. Per relay because a relay is one protected address, and
            // two ports of one service can be reached differently.
            let (target, onward) = match target.trim().split_once('|') {
                Some((target, word)) => match fgex_proxy::proxy::Onward::from_word(word) {
                    Some(onward) => (target, onward),
                    None => {
                        eprintln!("[fatal] [main] FGEX_PROXY_UDP: unknown upstream '{word}'");
                        exit(2);
                    }
                },
                None => (target.trim(), fgex_proxy::proxy::Onward::Same),
            };
            let upstream = parse_addr("FGEX_PROXY_UDP", target.trim());
            match relays.add_relay(upstream, onward).await {
                Ok(port) => {
                    // With what it speaks onward, because that is half of what names a
                    // relay: two addresses sending to one service port can want different
                    // answers, and each gets a relay of its own.
                    fgex_proxy::report::reply(format!("UDP {upstream}|{} {port}", onward.word()));
                }
                Err(e) => {
                    eprintln!("[fatal] [main] cannot bind a UDP relay for {upstream}: {e}");
                    exit(1);
                }
            }
        }
    }

    // Rulesets and control commands (e.g. ADD_UDP) arrive on stdin from here on.
    // It runs alongside the datapath rather than gating it: traffic must flow
    // before, during and after a rule change or relay addition.
    let deadline_dur = Duration::from_millis(deadline);
    let control_chain = chain_handle.clone();
    let control_relays = relays.clone();
    tokio::spawn(async move { serve_stdin(control_chain, deadline_dur, control_relays, targets).await });

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
            // Dropped rather than waited for when the backend is behind: the next one
            // carries the same cumulative numbers two seconds later.
            fgex_proxy::report::event(format!(
                "STATS seen={} refused={} live={} over_limit={} no_first_byte={}",
                counters.accepted.load(std::sync::atomic::Ordering::Relaxed),
                counters.closed_by_filter.load(std::sync::atomic::Ordering::Relaxed),
                counters.live.load(std::sync::atomic::Ordering::Relaxed),
                counters.over_limit.load(std::sync::atomic::Ordering::Relaxed),
                counters.no_first_byte.load(std::sync::atomic::Ordering::Relaxed),
            ));
        }
    });

    if let Err(e) = proxy.serve().await {
        eprintln!("[fatal] [main] accept loop died: {e}");
        exit(1);
    }
}
