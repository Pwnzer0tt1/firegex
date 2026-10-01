//! Bindings to the hyperscan/vectorscan C API.
//!
//! Firegex already matches with hyperscan on the NFQUEUE side (`binsrc/regex/`),
//! and the proxy transport has to match with the *same* engine — not a similar one.
//! Two engines would mean a pattern that blocks on one transport and not the other,
//! and an in-app regex debugger that tests neither. So this is a binding rather than
//! a second implementation, and the flags below deliberately mirror
//! `regex_rules.cpp`: `SINGLEMATCH | ALLOWEMPTY`, plus `CASELESS` when asked.
//!
//! Stream mode is the other reason. A proxy sees a byte stream in arbitrary chunks,
//! and a pattern may straddle two of them. Rescanning an overlap window bounds the
//! cost but also bounds what can match. `hs_scan_stream` carries the automaton state
//! across chunks instead, so a match is found wherever it falls, at no extra scanning.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::ptr;
use std::sync::Arc;

#[allow(non_camel_case_types)]
type hs_database_t = c_void;
#[allow(non_camel_case_types)]
type hs_scratch_t = c_void;
#[allow(non_camel_case_types)]
type hs_stream_t = c_void;

#[repr(C)]
struct hs_compile_error_t {
    message: *mut c_char,
    expression: c_int,
}

type MatchEventHandler = extern "C" fn(
    id: c_uint,
    from: u64,
    to: u64,
    flags: c_uint,
    context: *mut c_void,
) -> c_int;

const HS_SUCCESS: c_int = 0;
const HS_SCAN_TERMINATED: c_int = -3;

const HS_FLAG_CASELESS: c_uint = 1;
#[allow(dead_code)]
const HS_FLAG_SINGLEMATCH: c_uint = 8;
const HS_FLAG_ALLOWEMPTY: c_uint = 16;
const HS_FLAG_SOM_LEFTMOST: c_uint = 256;

const HS_MODE_BLOCK: c_uint = 1;
const HS_MODE_STREAM: c_uint = 2;

#[link(name = "hs")]
extern "C" {
    fn hs_compile_multi(
        expressions: *const *const c_char,
        flags: *const c_uint,
        ids: *const c_uint,
        elements: c_uint,
        mode: c_uint,
        platform: *const c_void,
        db: *mut *mut hs_database_t,
        error: *mut *mut hs_compile_error_t,
    ) -> c_int;
    fn hs_free_database(db: *mut hs_database_t) -> c_int;
    fn hs_free_compile_error(error: *mut hs_compile_error_t) -> c_int;
    fn hs_alloc_scratch(db: *const hs_database_t, scratch: *mut *mut hs_scratch_t) -> c_int;
    fn hs_free_scratch(scratch: *mut hs_scratch_t) -> c_int;
    fn hs_open_stream(
        db: *const hs_database_t,
        flags: c_uint,
        stream: *mut *mut hs_stream_t,
    ) -> c_int;
    fn hs_scan_stream(
        id: *mut hs_stream_t,
        data: *const c_char,
        length: c_uint,
        flags: c_uint,
        scratch: *mut hs_scratch_t,
        on_event: Option<MatchEventHandler>,
        ctxt: *mut c_void,
    ) -> c_int;
    fn hs_close_stream(
        id: *mut hs_stream_t,
        scratch: *mut hs_scratch_t,
        on_event: Option<MatchEventHandler>,
        ctxt: *mut c_void,
    ) -> c_int;
    fn hs_reset_stream(
        id: *mut hs_stream_t,
        flags: c_uint,
        scratch: *mut hs_scratch_t,
        on_event: Option<MatchEventHandler>,
        ctxt: *mut c_void,
    ) -> c_int;
    fn hs_scan(
        db: *const hs_database_t,
        data: *const c_char,
        length: c_uint,
        flags: c_uint,
        scratch: *mut hs_scratch_t,
        on_event: Option<MatchEventHandler>,
        ctxt: *mut c_void,
    ) -> c_int;
}

/// How a compiled database will be used. The mode is baked into the database, so a
/// database compiled for one cannot be scanned with the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Live traffic: state carries across chunks, first match per pattern wins.
    Stream,
    /// One self-contained buffer, every match reported with its start offset.
    /// This is what the in-app debugger scans with.
    Block,
}

/// One pattern as the operator wrote it.
pub struct Pattern {
    pub expr: String,
    pub case_sensitive: bool,
}

/// A compiled set of patterns.
///
/// Immutable once built, which is what lets every connection share one `Arc` of it
/// instead of recompiling per connection — and what makes the `Sync` below sound.
pub struct Database {
    db: *mut hs_database_t,
    mode: Mode,
    count: usize,
}

// hyperscan states that a compiled database is read-only at scan time and may be
// shared by any number of concurrent scans, each with its own scratch. The scratch
// is the mutable part, and it is owned per-scanner below.
unsafe impl Send for Database {}
unsafe impl Sync for Database {}

impl Drop for Database {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe { hs_free_database(self.db) };
        }
    }
}

fn take_compile_error(err: *mut hs_compile_error_t) -> String {
    if err.is_null() {
        return "hyperscan failed to compile the pattern".to_string();
    }
    let msg = unsafe {
        if (*err).message.is_null() {
            "hyperscan failed to compile the pattern".to_string()
        } else {
            CStr::from_ptr((*err).message).to_string_lossy().into_owned()
        }
    };
    unsafe { hs_free_compile_error(err) };
    msg
}

impl Database {
    /// Compile the patterns into one database, ids being their index in `patterns`.
    ///
    /// One database for many patterns is the whole point of hyperscan: the automata
    /// are merged, so scanning for fifty patterns costs about what scanning for one
    /// costs. Adding a pattern must therefore rebuild, never chain.
    pub fn compile(patterns: &[Pattern], mode: Mode) -> Result<Database, String> {
        if patterns.is_empty() {
            return Err("no patterns to compile".to_string());
        }
        let owned: Vec<CString> = patterns
            .iter()
            .map(|p| {
                CString::new(p.expr.as_bytes())
                    .map_err(|_| "a pattern contains a null byte".to_string())
            })
            .collect::<Result<_, _>>()?;
        let ptrs: Vec<*const c_char> = owned.iter().map(|s| s.as_ptr()).collect();

        let base = match mode {
            Mode::Stream => HS_FLAG_ALLOWEMPTY,
            // The debugger wants every match and where it started, so neither
            // SINGLEMATCH (one report per pattern) nor the default no-start-offset.
            Mode::Block => HS_FLAG_SOM_LEFTMOST | HS_FLAG_ALLOWEMPTY,
        };
        let flags: Vec<c_uint> = patterns
            .iter()
            .map(|p| if p.case_sensitive { base } else { base | HS_FLAG_CASELESS })
            .collect();
        let ids: Vec<c_uint> = (0..patterns.len() as c_uint).collect();

        let hs_mode = match mode {
            Mode::Stream => HS_MODE_STREAM,
            // No SOM horizon flag: those are a streaming-mode bound on how far
            // back a start offset may be remembered. Block mode scans one buffer and
            // always reports the true start.
            Mode::Block => HS_MODE_BLOCK,
        };

        let mut db: *mut hs_database_t = ptr::null_mut();
        let mut err: *mut hs_compile_error_t = ptr::null_mut();
        let rc = unsafe {
            hs_compile_multi(
                ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                patterns.len() as c_uint,
                hs_mode,
                ptr::null(),
                &mut db,
                &mut err,
            )
        };
        if rc != HS_SUCCESS {
            return Err(take_compile_error(err));
        }
        Ok(Database { db, mode, count: patterns.len() })
    }

    /// Compile one pattern on its own, purely to find out whether it is valid.
    ///
    /// Worth the extra compile: `hs_compile_multi` reports the first bad pattern and
    /// stops, so a ruleset with one typo would otherwise reject every pattern in it
    /// with a message about a different one.
    pub fn validate(expr: &str, case_sensitive: bool, mode: Mode) -> Result<(), String> {
        Database::compile(
            &[Pattern { expr: expr.to_string(), case_sensitive }],
            mode,
        )
        .map(|_| ())
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }
}

struct Scratch {
    scratch: *mut hs_scratch_t,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.scratch.is_null() {
            unsafe { hs_free_scratch(self.scratch) };
        }
    }
}

impl Scratch {
    fn alloc(db: &Database) -> Result<Scratch, String> {
        let mut scratch: *mut hs_scratch_t = ptr::null_mut();
        let rc = unsafe { hs_alloc_scratch(db.db, &mut scratch) };
        if rc != HS_SUCCESS {
            return Err(format!("hyperscan could not allocate scratch space ({rc})"));
        }
        Ok(Scratch { scratch })
    }
}

/// Context handed to the C callback. `id` of the first match, if any.
struct FirstMatch {
    hit: Option<u32>,
}

extern "C" fn on_first_match(
    id: c_uint,
    _from: u64,
    _to: u64,
    _flags: c_uint,
    context: *mut c_void,
) -> c_int {
    // SAFETY: `context` is the `&mut FirstMatch` passed to hs_scan_stream, which
    // outlives the scan and is not aliased — hyperscan calls this synchronously.
    let res = unsafe { &mut *(context as *mut FirstMatch) };
    res.hit = Some(id as u32);
    -1 // stop scanning: one match is enough to decide a verdict
}

/// A scanner bound to one direction of one connection.
///
/// Owns its scratch rather than borrowing a shared one: scratch is the mutable
/// working memory of a scan and must not be touched by two scans at once. Tying its
/// lifetime to the stream's makes that unrepresentable instead of a rule to remember.
pub struct StreamScanner {
    db: Arc<Database>,
    stream: *mut hs_stream_t,
    scratch: Scratch,
}

// Both pointers are owned exclusively by this struct and never shared; moving the
// whole scanner to another thread moves both together.
unsafe impl Send for StreamScanner {}

impl Drop for StreamScanner {
    fn drop(&mut self) {
        if !self.stream.is_null() {
            unsafe { hs_close_stream(self.stream, self.scratch.scratch, None, ptr::null_mut()) };
        }
    }
}

impl StreamScanner {
    pub fn open(db: Arc<Database>) -> Result<StreamScanner, String> {
        if db.mode != Mode::Stream {
            return Err("this database was not compiled for stream scanning".to_string());
        }
        let scratch = Scratch::alloc(&db)?;
        let mut stream: *mut hs_stream_t = ptr::null_mut();
        let rc = unsafe { hs_open_stream(db.db, 0, &mut stream) };
        if rc != HS_SUCCESS {
            return Err(format!("hyperscan could not open a stream ({rc})"));
        }
        Ok(StreamScanner { db, stream, scratch })
    }

    /// Feed the next chunk. Returns the id of the pattern that matched, if one did.
    ///
    /// The stream keeps its own state, so a caller must never re-feed bytes it has
    /// already fed — that would match patterns that never actually appeared.
    pub fn scan(&mut self, data: &[u8]) -> Result<Option<u32>, String> {
        if data.is_empty() {
            return Ok(None);
        }
        let mut res = FirstMatch { hit: None };
        // The C API takes a 32-bit length. Real chunks are far below that, but a
        // caller is not obliged to know it, so feed in pieces rather than truncate.
        for piece in data.chunks(u32::MAX as usize) {
            let rc = unsafe {
                hs_scan_stream(
                    self.stream,
                    piece.as_ptr() as *const c_char,
                    piece.len() as c_uint,
                    0,
                    self.scratch.scratch,
                    Some(on_first_match),
                    &mut res as *mut FirstMatch as *mut c_void,
                )
            };
            if rc == HS_SCAN_TERMINATED {
                break;
            }
            if rc != HS_SUCCESS {
                return Err(format!("hyperscan stream scan failed ({rc})"));
            }
        }
        Ok(res.hit)
    }

    /// Reset the stream to its initial state, clearing any previous match or terminated status.
    pub fn reset(&mut self) -> Result<(), String> {
        if self.stream.is_null() {
            return Ok(());
        }
        let rc = unsafe {
            hs_reset_stream(
                self.stream,
                0,
                self.scratch.scratch,
                None,
                ptr::null_mut(),
            )
        };
        if rc != HS_SUCCESS {
            // If reset failed, close and reopen the stream cleanly.
            unsafe { hs_close_stream(self.stream, self.scratch.scratch, None, ptr::null_mut()) };
            self.stream = ptr::null_mut();
            let reopen_rc = unsafe { hs_open_stream(self.db.db, 0, &mut self.stream) };
            if reopen_rc != HS_SUCCESS {
                return Err(format!("hyperscan reset stream failed ({rc}/{reopen_rc})"));
            }
        }
        Ok(())
    }

    pub fn pattern_count(&self) -> usize {
        self.db.count
    }
}

/// One match found by a block-mode scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub id: u32,
    pub from: u64,
    pub to: u64,
}

struct AllMatches {
    hits: Vec<Match>,
    limit: usize,
}

extern "C" fn on_every_match(
    id: c_uint,
    from: u64,
    to: u64,
    _flags: c_uint,
    context: *mut c_void,
) -> c_int {
    // SAFETY: as above — synchronous, single-threaded, outlives the scan.
    let res = unsafe { &mut *(context as *mut AllMatches) };
    res.hits.push(Match { id: id as u32, from, to });
    // A pathological pattern over a large sample can match at nearly every offset;
    // the debugger wants a readable answer, not every one of them.
    if res.hits.len() >= res.limit {
        -1
    } else {
        0
    }
}

/// Scan one self-contained buffer and report every match with its offsets.
///
/// This is what the debugger runs, so what it shows is what the datapath would see.
pub fn scan_block(db: &Database, data: &[u8], limit: usize) -> Result<Vec<Match>, String> {
    if db.mode != Mode::Block {
        return Err("this database was not compiled for block scanning".to_string());
    }
    let scratch = Scratch::alloc(db)?;
    scan_block_with(db, scratch.scratch, data, limit)
}

fn scan_block_with(
    db: &Database,
    scratch: *mut hs_scratch_t,
    data: &[u8],
    limit: usize,
) -> Result<Vec<Match>, String> {
    let mut res = AllMatches { hits: Vec::new(), limit };
    let rc = unsafe {
        hs_scan(
            db.db,
            data.as_ptr() as *const c_char,
            data.len() as c_uint,
            0,
            scratch,
            Some(on_every_match),
            &mut res as *mut AllMatches as *mut c_void,
        )
    };
    if rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED {
        return Err(format!("hyperscan block scan failed ({rc})"));
    }
    Ok(res.hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_db(exprs: &[(&str, bool)]) -> Arc<Database> {
        let pats: Vec<Pattern> = exprs
            .iter()
            .map(|(e, cs)| Pattern { expr: e.to_string(), case_sensitive: *cs })
            .collect();
        Arc::new(Database::compile(&pats, Mode::Stream).expect("compile"))
    }

    #[test]
    fn matches_a_pattern_in_one_chunk() {
        let db = stream_db(&[("needle", true)]);
        let mut sc = StreamScanner::open(db).unwrap();
        assert_eq!(sc.scan(b"a haystack with a needle in it").unwrap(), Some(0));
    }

    #[test]
    fn reports_which_pattern_matched() {
        let db = stream_db(&[("alpha", true), ("bravo", true), ("charlie", true)]);
        let mut sc = StreamScanner::open(db).unwrap();
        assert_eq!(sc.scan(b"...bravo...").unwrap(), Some(1));
    }

    /// The reason stream mode exists: a match split across two writes.
    #[test]
    fn matches_across_a_chunk_boundary() {
        let db = stream_db(&[("secret-token", true)]);
        let mut sc = StreamScanner::open(db).unwrap();
        assert_eq!(sc.scan(b"GET /?k=secr").unwrap(), None);
        assert_eq!(sc.scan(b"et-token HTTP/1.1").unwrap(), Some(0));
    }

    /// ...and it holds however small the pieces are, which no overlap window does.
    #[test]
    fn matches_across_many_one_byte_chunks() {
        let db = stream_db(&[("abcdefghij", true)]);
        let mut sc = StreamScanner::open(db).unwrap();
        let mut hit = None;
        for b in b"xxxabcdefghijxxx" {
            if let Some(id) = sc.scan(&[*b]).unwrap() {
                hit = Some(id);
            }
        }
        assert_eq!(hit, Some(0));
    }

    #[test]
    fn honours_case_sensitivity() {
        let sensitive = stream_db(&[("NeEdLe", true)]);
        let mut sc = StreamScanner::open(sensitive).unwrap();
        assert_eq!(sc.scan(b"needle").unwrap(), None);

        let insensitive = stream_db(&[("NeEdLe", false)]);
        let mut sc = StreamScanner::open(insensitive).unwrap();
        assert_eq!(sc.scan(b"needle").unwrap(), Some(0));
    }

    #[test]
    fn scans_arbitrary_bytes_not_just_utf8() {
        let db = stream_db(&[(r"\x00\xff\xfe", true)]);
        let mut sc = StreamScanner::open(db).unwrap();
        assert_eq!(sc.scan(&[0x41, 0x00, 0xff, 0xfe, 0x42]).unwrap(), Some(0));
    }

    #[test]
    fn two_scanners_of_one_database_are_independent() {
        let db = stream_db(&[("split-me", true)]);
        let mut a = StreamScanner::open(db.clone()).unwrap();
        let mut b = StreamScanner::open(db).unwrap();
        assert_eq!(a.scan(b"spl").unwrap(), None);
        // b has seen nothing, so a's partial progress must not carry into it
        assert_eq!(b.scan(b"it-me").unwrap(), None);
        assert_eq!(a.scan(b"it-me").unwrap(), Some(0));
    }

    #[test]
    fn a_bad_pattern_names_itself() {
        let err = Database::validate("(unclosed", true, Mode::Stream).unwrap_err();
        assert!(!err.is_empty(), "the compile error should carry a message");
        assert!(Database::validate("(closed)", true, Mode::Stream).is_ok());
    }

    #[test]
    fn block_mode_reports_every_match_with_offsets() {
        let db = Database::compile(
            &[Pattern { expr: "a.c".to_string(), case_sensitive: true }],
            Mode::Block,
        )
        .unwrap();
        let hits = scan_block(&db, b"abc___axc", 100).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!((hits[0].from, hits[0].to), (0, 3));
        assert_eq!((hits[1].from, hits[1].to), (6, 9));
    }

    #[test]
    fn block_mode_stops_at_the_limit() {
        let db = Database::compile(
            &[Pattern { expr: "x".to_string(), case_sensitive: true }],
            Mode::Block,
        )
        .unwrap();
        let hits = scan_block(&db, &[b'x'; 1000], 10).unwrap();
        assert_eq!(hits.len(), 10);
    }

    #[test]
    fn a_database_refuses_the_wrong_scan_mode() {
        let block = Database::compile(
            &[Pattern { expr: "x".to_string(), case_sensitive: true }],
            Mode::Block,
        )
        .unwrap();
        assert!(StreamScanner::open(Arc::new(block)).is_err());

        let stream = Database::compile(
            &[Pattern { expr: "x".to_string(), case_sensitive: true }],
            Mode::Stream,
        )
        .unwrap();
        assert!(scan_block(&stream, b"x", 10).is_err());
    }
}
