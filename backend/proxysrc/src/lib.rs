//! Proxy datapath engine for firegex.
//!
//! An alternative to the NFQUEUE engine: instead of lifting packets to userspace and
//! handing a verdict back to the kernel, terminate the connection and own both halves.
//! That buys exact rewriting, kernel-side reassembly and real backpressure — and costs
//! the kernel's fail-open backstop, which [`filter`] rebuilds by hand.

pub mod control;
pub mod debug;
pub mod filter;
pub mod h1up;
pub mod h2;
pub mod h3;
pub mod http1;
pub mod hyperscan;
pub mod proxy;
pub mod quic;
pub mod quic_hello;
pub mod pyworker;
pub mod rules;
pub mod spec;
pub mod capture;
pub mod tls;
pub mod transparent;
pub mod relays;
pub mod report;
pub mod udp;

pub use filter::{
    ChainHandle, ChainSessions, Direction, Filter, FilterChain, FilterCtx, FilterSession, Verdict,
};
pub use proxy::{Proxy, ProxyConfig, Upstream};
