//! What the filter layer costs, in bytes per second.
//!
//! Ignored by default: it measures rather than asserts, and a number that depends on
//! the machine has no business failing a test run. Run it deliberately:
//!
//! ```text
//! cargo test --release --test throughput -- --ignored --nocapture
//! ```
//!
//! Read the slope, not the absolute number. The buffer is reused and stays in cache,
//! so the throughput here is an upper bound on the matcher alone — real traffic is
//! bounded by sockets long before it is bounded by this. What the benchmark is for is
//! the shape of the curve: matching should cost about the same at two hundred rules
//! as at one, because every pattern for a direction lives in one hyperscan database.
//! A per-rule loop made that curve steep enough to be the reason this file exists.

use std::time::{Duration, Instant};

use fgex_proxy::filter::{next_connection_id, ChainSessions, Direction, FilterChain, Verdict};
use fgex_proxy::rules::parse_ruleset;

const CHUNK: usize = 64 * 1024; // what the relay actually reads at a time
const TOTAL: usize = 512 * 1024 * 1024;

fn ruleset(n: usize) -> String {
    let rules: Vec<String> = (0..n)
        .map(|i| format!(r#"{{"kind":"regex","id":"r{i}","pattern":"needle{i}z"}}"#))
        .collect();
    format!("[{}]", rules.join(","))
}

async fn measure(rules: usize) -> f64 {
    let chain = FilterChain::new(
        parse_ruleset(&ruleset(rules)).unwrap(),
        Duration::from_millis(500),
    );
    // Traffic that matches nothing, but is not one repeated byte either: a uniform
    // buffer is not what a matcher meets in practice and can flatter it.
    let chunk: Vec<u8> = (0..CHUNK).map(|i| b'a' + ((i * 7 + i / 31) % 26) as u8).collect();
    let mut sessions = ChainSessions::new(next_connection_id());

    let start = Instant::now();
    let mut sent = 0usize;
    while sent < TOTAL {
        assert_eq!(
            chain.run(Direction::ClientToServer, &chunk, &mut sessions).await,
            Verdict::Accept
        );
        sent += CHUNK;
    }
    let secs = start.elapsed().as_secs_f64();
    (sent as f64) / secs / (1024.0 * 1024.0)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, not an assertion"]
async fn filter_throughput_by_rule_count() {
    println!("\n  rules      MB/s");
    for n in [0, 1, 10, 50, 200] {
        let mbs = measure(n).await;
        println!("  {n:>5}   {mbs:>9.0}");
    }
}
