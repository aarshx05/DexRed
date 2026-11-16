//! DexRed security assessment extensions.
//!
//! Provides agent-loop-level stuck detection, circuit breaking, and
//! HTTP replay infrastructure for the security assessment harness.

pub mod stuck_detector;
pub mod circuit_breaker;
pub mod replay;
