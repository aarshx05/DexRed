//! DexRed security assessment extensions.
//!
//! Provides agent-loop-level stuck detection, circuit breaking, and
//! HTTP replay infrastructure for the security assessment harness.

pub mod stuck_detector;
pub mod circuit_breaker;
pub mod replay;

use std::sync::Mutex;

/// Shared state for DexRed security monitors, stored in the turn's
/// ExtensionData so it's accessible at every level of the agent loop
/// without changing function signatures.
pub struct DexRedMonitors {
    pub stuck: Mutex<stuck_detector::StuckDetector>,
    pub circuit: Mutex<circuit_breaker::CircuitBreaker>,
}

impl DexRedMonitors {
    pub fn new() -> Self {
        Self {
            stuck: Mutex::new(stuck_detector::StuckDetector::new()),
            circuit: Mutex::new(circuit_breaker::CircuitBreaker::new()),
        }
    }
}

impl std::fmt::Debug for DexRedMonitors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DexRedMonitors").finish_non_exhaustive()
    }
}
