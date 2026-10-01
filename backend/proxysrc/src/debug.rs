//! Answering "what would this pattern actually do?" with the engine that would do it.
//!
//! An in-app regex tester is only worth having if it is the same matcher the datapath
//! runs. A tester built on Python's `re` would accept backreferences hyperscan rejects,
//! disagree about what `.` matches, and quietly bless a pattern that will be refused
//! the moment it is saved — which is worse than having no tester, because the operator
//! would trust it.
//!
//! So the backend asks this binary instead. One JSON request in, one JSON response
//! out, block mode with start-of-match offsets so the answer can be highlighted.

use serde::{Deserialize, Serialize};

use crate::hyperscan::{self, Mode, Pattern};

/// Enough matches to show, few enough to render. A pattern like `.*` over a sizeable
/// sample matches at almost every offset, and an operator learns nothing from the
/// ten thousandth one.
const MATCH_LIMIT: usize = 1000;

#[derive(Deserialize)]
pub struct DebugRequest {
    pub patterns: Vec<DebugPattern>,
    /// The sample to scan, base64-encoded: a pattern is matched against bytes, and
    /// testing one against bytes that are not valid text is a normal thing to want.
    pub sample: String,
}

#[derive(Deserialize)]
pub struct DebugPattern {
    pub id: String,
    pub expr: String,
    #[serde(default = "yes")]
    pub case_sensitive: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize)]
pub struct DebugResponse {
    pub matches: Vec<DebugMatch>,
    /// Per pattern, the compile error if there was one. A ruleset with one broken
    /// pattern still reports the others, because the operator is usually editing one
    /// pattern and should not lose the answers about the rest.
    pub errors: Vec<DebugError>,
    /// Set when the whole request failed rather than one pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Patterns that are valid and will run, but that this tester cannot show matches
    /// for. Highlighting needs block-mode scanning, and block mode rejects a few
    /// patterns streaming accepts. Saying so beats either refusing them or silently
    /// showing no matches.
    pub unscannable: Vec<DebugError>,

    pub truncated: bool,
}

#[derive(Serialize)]
pub struct DebugMatch {
    pub id: String,
    pub from: u64,
    pub to: u64,
}

#[derive(Serialize, Debug)]
pub struct DebugError {
    pub id: String,
    pub error: String,
}

fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    // A dependency for this would be a dependency in the datapath, and the datapath's
    // dependency list is a thing worth keeping short.
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for ch in input.bytes() {
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return Err("the sample is not valid base64".to_string()),
        } as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Scan one sample with one set of patterns.
pub fn run(request: &str) -> DebugResponse {
    let req: DebugRequest = match serde_json::from_str(request) {
        Ok(r) => r,
        Err(e) => {
            return DebugResponse {
                matches: Vec::new(),
                errors: Vec::new(),
                error: Some(format!("malformed request: {e}")),
                unscannable: Vec::new(),
                truncated: false,
            }
        }
    };
    let sample = match b64_decode(&req.sample) {
        Ok(s) => s,
        Err(e) => {
            return DebugResponse {
                matches: Vec::new(),
                errors: Vec::new(),
                error: Some(e),
                unscannable: Vec::new(),
                truncated: false,
            }
        }
    };

    // Compiled one at a time rather than as a set: a set reports only the first
    // pattern that failed, and the point of a tester is to say which of the operator's
    // patterns is wrong and why.
    let mut errors = Vec::new();
    let mut unscannable = Vec::new();
    let mut good = Vec::new();
    for p in &req.patterns {
        let pattern = Pattern {
            expr: p.expr.clone(),
            case_sensitive: p.case_sensitive,
        };
        // Validity is judged against the mode this pattern will actually run in, so the
        // tester's verdict is the same one the datapath will reach.
        let runtime_mode = Mode::Stream;
        if let Err(e) = hyperscan::Database::compile(std::slice::from_ref(&pattern), runtime_mode)
        {
            errors.push(DebugError { id: p.id.clone(), error: e });
            continue;
        }
        // Showing where it matches is a separate question: only block mode reports
        // offsets, and it accepts slightly less.
        match hyperscan::Database::compile(std::slice::from_ref(&pattern), Mode::Block) {
            Ok(_) => good.push((p.id.clone(), pattern)),
            Err(e) => unscannable.push(DebugError { id: p.id.clone(), error: e }),
        }
    }

    if good.is_empty() {
        return DebugResponse {
            matches: Vec::new(),
            errors,
            error: None,
            unscannable,
            truncated: false,
        };
    }

    let (ids, patterns): (Vec<String>, Vec<Pattern>) = good.into_iter().unzip();
    let db = match hyperscan::Database::compile(&patterns, Mode::Block) {
        Ok(db) => db,
        Err(e) => {
            return DebugResponse {
                matches: Vec::new(),
                errors,
                error: Some(e),
                unscannable,
                truncated: false,
            }
        }
    };
    let hits = match hyperscan::scan_block(&db, &sample, MATCH_LIMIT) {
        Ok(h) => h,
        Err(e) => {
            return DebugResponse {
                matches: Vec::new(),
                errors,
                error: Some(e),
                unscannable,
                truncated: false,
            }
        }
    };
    let truncated = hits.len() >= MATCH_LIMIT;



    DebugResponse {
        matches: hits
            .into_iter()
            .map(|m| DebugMatch {
                id: ids
                    .get(m.id as usize)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
                from: m.from,
                to: m.to,
            })
            .collect(),
        errors,
        error: None,
        unscannable,
        truncated,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn ask(patterns: &str, sample: &[u8]) -> DebugResponse {
        // base64 by hand, to keep the encoder and the decoder honest about each other
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::new();
        for block in sample.chunks(3) {
            let b = [
                block[0],
                *block.get(1).unwrap_or(&0),
                *block.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            for i in 0..4 {
                if i <= block.len() {
                    encoded.push(ALPHABET[((n >> (18 - i * 6)) & 63) as usize] as char);
                } else {
                    encoded.push('=');
                }
            }
        }
        run(&format!(r#"{{"patterns":{patterns},"sample":"{encoded}"}}"#))
    }



    #[test]
    fn reports_where_a_pattern_matched() {
        let res = ask(r#"[{"id":"a","expr":"FLAG\\{[a-z]+\\}"}]"#, b"xx FLAG{abc} yy");
        assert!(res.error.is_none(), "{:?}", res.error);
        assert_eq!(res.matches.len(), 1);
        assert_eq!(res.matches[0].id, "a");
        assert_eq!((res.matches[0].from, res.matches[0].to), (3, 12));
    }

    #[test]
    fn reports_every_match_not_just_the_first() {
        let res = ask(r#"[{"id":"a","expr":"ab"}]"#, b"ab_ab_ab");
        assert_eq!(res.matches.len(), 3);
    }

    #[test]
    fn names_the_pattern_that_failed_and_keeps_the_rest() {
        let res = ask(
            r#"[{"id":"bad","expr":"(unclosed"},{"id":"good","expr":"ok"}]"#,
            b"this is ok",
        );
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].id, "bad");
        assert!(!res.errors[0].error.is_empty());
        assert_eq!(res.matches.len(), 1, "the valid pattern still reported");
        assert_eq!(res.matches[0].id, "good");
    }

    #[test]
    fn honours_case_sensitivity_per_pattern() {
        let res = ask(
            r#"[{"id":"s","expr":"ABC"},{"id":"i","expr":"ABC","case_sensitive":false}]"#,
            b"abc",
        );
        let ids: Vec<&str> = res.matches.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["i"]);
    }

    #[test]
    fn matches_bytes_that_are_not_text() {
        let res = ask(r#"[{"id":"a","expr":"\\xff\\xfe"}]"#, &[0x41, 0xff, 0xfe]);
        assert!(res.error.is_none(), "{:?}", res.error);
        assert_eq!(res.matches.len(), 1);
        assert_eq!((res.matches[0].from, res.matches[0].to), (1, 3));
    }

    /// The two modes do not accept exactly the same patterns, and judging a pattern by
    /// the wrong one refuses something that works. A bounded repeat compiles for
    /// streaming — which is how a blocking pattern runs — but not for the block-mode
    /// scanning the tester highlights with.
    #[test]
    fn a_pattern_is_judged_by_the_mode_it_will_run_in() {
        let res = ask(r#"[{"id":"a","expr":"a{1,1000}b"}]"#, b"aab");
        assert!(res.errors.is_empty(), "a valid blocking pattern was refused: {:?}", res.errors);
        assert_eq!(
            res.unscannable.len(),
            1,
            "it is valid but cannot be highlighted, and that has to be said"
        );
    }

    #[test]
    fn a_malformed_request_is_an_error_not_a_panic() {
        let res = run("{not json");
        assert!(res.error.is_some());
    }

    #[test]
    fn an_empty_sample_matches_nothing_and_does_not_fail() {
        let res = ask(r#"[{"id":"a","expr":"x"}]"#, b"");
        assert!(res.error.is_none());
        assert!(res.matches.is_empty());
    }
}
