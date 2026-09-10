//! The filters the backend actually configures, and the boundary case that decides
//! whether they are worth anything.

use std::sync::Arc;
use std::time::Duration;

use fgex_proxy::filter::{
    next_connection_id, ChainHandle, ChainSessions, Direction, FilterChain, Verdict,
};
use fgex_proxy::rules::parse_ruleset;

fn chain(json: &str) -> FilterChain {
    FilterChain::new(parse_ruleset(json).unwrap(), Duration::from_millis(500))
}

async fn feed(c: &FilterChain, dir: Direction, chunks: &[&[u8]]) -> Vec<Verdict> {
    let mut sessions = ChainSessions::new(next_connection_id());
    let mut out = Vec::new();
    for chunk in chunks {
        out.push(c.run(dir, chunk, &mut sessions).await);
    }
    out
}

/// A block carries the id of the pattern that fired, so the tests can name it.
fn reject(id: &str) -> Verdict {
    Verdict::Reject(Some(id.to_string()))
}

#[tokio::test]
async fn regex_rule_blocks_on_match() {
    let c = chain(r#"[{"kind":"regex","id":"r1","pattern":"FLAG\\{[a-z]+\\}"}]"#);
    let v = feed(&c, Direction::ClientToServer, &[b"nothing here"]).await;
    assert_eq!(v, vec![Verdict::Accept]);

    let v = feed(&c, Direction::ClientToServer, &[b"give me FLAG{abc} now"]).await;
    assert_eq!(v, vec![reject("r1")]);
}

/// The reason the chain keeps a per-direction sessions at all. Split the pattern
/// across two reads and a chunk-only matcher goes blind — which is exactly the
/// evasion nfregex has to reassemble the stream to prevent.
#[tokio::test]
async fn regex_rule_matches_across_a_segment_boundary() {
    let c = chain(r#"[{"kind":"regex","id":"r1","pattern":"/etc/passwd"}]"#);
    let v = feed(
        &c,
        Direction::ClientToServer,
        &[b"GET /etc/pa", b"sswd HTTP/1.1"],
    )
    .await;
    assert_eq!(
        v,
        vec![Verdict::Accept, reject("r1")],
        "a pattern split over two reads was missed"
    );
}

/// The property an overlap window could not have at any size.
///
/// The previous matcher kept the last 4096 bytes and rescanned them with each chunk,
/// so a match spanning more than that was invisible — and raising the number would
/// have cost every byte of every connection. hyperscan carries the automaton state
/// instead: the span is unbounded and costs nothing per chunk.
#[tokio::test]
async fn regex_rule_matches_across_more_than_the_old_window() {
    let c = chain(r#"[{"kind":"regex","id":"r1","pattern":"BEGIN.{9000,}END"}]"#);
    let filler = vec![b'.'; 3000];
    let v = feed(
        &c,
        Direction::ClientToServer,
        &[b"BEGIN", &filler, &filler, &filler, &filler, b"END"],
    )
    .await;
    assert_eq!(
        v.last(),
        Some(&reject("r1")),
        "a match spanning 12000 bytes was missed"
    );
}

#[tokio::test]
async fn regex_rule_honours_direction() {
    // Only the server's answers are inspected: a request mentioning it is fine.
    let c = chain(r#"[{"kind":"regex","id":"r1","pattern":"FLAG","direction":"s2c"}]"#);
    let v = feed(&c, Direction::ClientToServer, &[b"where is the FLAG"]).await;
    assert_eq!(v, vec![Verdict::Accept]);

    let v = feed(&c, Direction::ServerToClient, &[b"here: FLAG{x}"]).await;
    assert_eq!(v, vec![reject("r1")]);
}

#[tokio::test]
async fn regex_rule_can_ignore_case() {
    let c =
        chain(r#"[{"kind":"regex","id":"r1","pattern":"union select","case_sensitive":false}]"#);
    let v = feed(&c, Direction::ClientToServer, &[b"1 UNION SELECT 1"]).await;
    assert_eq!(v, vec![reject("r1")]);
}

#[tokio::test]
async fn a_bad_rule_rejects_the_whole_ruleset() {
    // Half a ruleset is worse than the one already running, so nothing is applied.
    let bad =
        r#"[{"kind":"regex","id":"ok","pattern":"a"},{"kind":"regex","id":"bad","pattern":"("}]"#;
    let err = match parse_ruleset(bad) {
        Err(e) => e,
        Ok(rules) => panic!(
            "a broken pattern was accepted ({} rules built)",
            rules.len()
        ),
    };
    assert!(err.contains("invalid regex"), "unhelpful error: {err}");

    assert!(parse_ruleset("not json").is_err());
    assert!(parse_ruleset(r#"[{"kind":"nope","id":"x"}]"#).is_err());
    assert!(parse_ruleset("[]").unwrap().is_empty());
}

/// Rules reach connections that are already open, which is what makes editing them
/// during a competition safe.
#[tokio::test]
async fn a_new_ruleset_reaches_an_open_connection() {
    let handle = ChainHandle::new(chain("[]"));
    let mut sessions = ChainSessions::new(next_connection_id());

    let v = handle
        .current()
        .run(Direction::ClientToServer, b"FLAG{x}", &mut sessions)
        .await;
    assert_eq!(v, Verdict::Accept);

    handle.replace(chain(r#"[{"kind":"regex","id":"r1","pattern":"FLAG"}]"#));

    let v = handle
        .current()
        .run(Direction::ClientToServer, b"FLAG{x}", &mut sessions)
        .await;
    assert_eq!(v, reject("r1"));
}

/// The sessions is per connection: one client's traffic must never complete another
/// client's pattern.
#[tokio::test]
async fn windows_do_not_leak_between_connections() {
    let c = Arc::new(chain(
        r#"[{"kind":"regex","id":"r1","pattern":"/etc/passwd"}]"#,
    ));

    let mut first = ChainSessions::new(next_connection_id());
    assert_eq!(
        c.run(Direction::ClientToServer, b"GET /etc/pa", &mut first)
            .await,
        Verdict::Accept
    );

    // A different connection sending the tail must not be blocked by the half a
    // previous client left behind.
    let mut second = ChainSessions::new(next_connection_id());
    assert_eq!(
        c.run(Direction::ClientToServer, b"sswd HTTP/1.1", &mut second)
            .await,
        Verdict::Accept
    );
}

/// Blocking rules that share a direction and a case setting are compiled into one
/// automaton, so adding rules stops costing a scan each. Measured against nfregex,
/// the per-rule scan was the difference between 100 MB/s and 2400.
#[tokio::test]
async fn blocking_rules_are_matched_in_one_pass() {
    let many: Vec<String> = (0..50)
        // Suffixed so no pattern is a prefix of another: the set reports the first
        // index that matched, and overlapping patterns would make that ambiguous.
        .map(|i| format!(r#"{{"kind":"regex","id":"r{i}","pattern":"needle{i}z"}}"#))
        .collect();
    let filters = parse_ruleset(&format!("[{}]", many.join(","))).unwrap();
    // Two matchers, not fifty: one hyperscan database per direction, each holding
    // every pattern that applies that way. A chunk is scanned by exactly one of
    // them, so the cost of matching stops depending on how many rules there are —
    // the property a per-rule loop gave away and a benchmark caught.
    assert_eq!(
        filters.len(),
        2,
        "50 blocking rules should collapse into one matcher per direction, got {}",
        filters.len()
    );

    let c = FilterChain::new(filters, Duration::from_millis(500));
    let v = feed(&c, Direction::ClientToServer, &[b"harmless"]).await;
    assert_eq!(v, vec![Verdict::Accept]);
    // Still attributed to the individual rule that fired.
    let v = feed(
        &c,
        Direction::ClientToServer,
        &[b"here is needle37z for you"],
    )
    .await;
    assert_eq!(v, vec![reject("r37")]);
}

/// Rules that cannot share an automaton stay apart, and still work.
#[tokio::test]
async fn only_direction_splits_the_matchers() {
    let filters = parse_ruleset(
        r#"[{"kind":"regex","id":"a","pattern":"aaa","direction":"c2s"},
            {"kind":"regex","id":"b","pattern":"bbb","direction":"s2c"},
            {"kind":"regex","id":"c","pattern":"ccc","case_sensitive":false}]"#,
    )
    .unwrap();
    // Two: one blocking matcher per direction.
    // Case-insensitivity does not split anything — hyperscan takes it as a per-pattern flag.
    assert_eq!(
        filters.len(),
        2,
        "one blocking matcher per direction"
    );

    let c = FilterChain::new(filters, Duration::from_millis(500));
    assert_eq!(
        feed(&c, Direction::ClientToServer, &[b"aaa"]).await,
        vec![reject("a")]
    );
    assert_eq!(
        feed(&c, Direction::ClientToServer, &[b"bbb"]).await,
        vec![Verdict::Accept],
        "an s2c rule fired on client traffic"
    );
    assert_eq!(
        feed(&c, Direction::ServerToClient, &[b"CCC"]).await,
        vec![reject("c")]
    );
}

/// Does the scan actually traverse the whole buffer? Plant the needle at the very
/// last byte of a 64 KiB chunk: a matcher that short-circuits would miss it.
#[tokio::test]
async fn a_needle_at_the_end_of_a_chunk_is_found() {
    let rules: Vec<String> = (0..50)
        .map(|i| format!(r#"{{"kind":"regex","id":"r{i}","pattern":"needle{i}z"}}"#))
        .collect();
    let c = chain(&format!("[{}]", rules.join(",")));
    let mut chunk = vec![b'x'; 64 * 1024];
    let needle = b"needle37z";
    let at = chunk.len() - needle.len();
    chunk[at..].copy_from_slice(needle);

    let mut s = ChainSessions::new(next_connection_id());
    assert_eq!(
        c.run(Direction::ClientToServer, &chunk, &mut s).await,
        reject("r37")
    );
}
