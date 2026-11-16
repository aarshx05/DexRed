//! Stuck detection for the security assessment agent.
//!
//! Monitors iteration patterns in the agent loop and signals when
//! the agent is unproductive — hitting the same endpoint, looping
//! on errors, or making no progress finding vulnerabilities.
//!
//! Integrated at the sampling-result level in `turn.rs`: after each
//! successful model response, the detector is updated with the tool
//! calls and results from that iteration.

use std::collections::VecDeque;
use std::time::Instant;

const DEFAULT_WINDOW: usize = 20;
const DEFAULT_SAME_ENDPOINT_THRESHOLD: usize = 5;
const DEFAULT_ERROR_STREAK_THRESHOLD: usize = 5;
const DEFAULT_NO_PROGRESS_THRESHOLD: u32 = 20;

/// What the detector recommends after analyzing recent iterations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StuckAction {
    /// Agent is productive — no intervention needed.
    Continue,
    /// Agent appears stuck — inject a warning into the next prompt.
    Warn(StuckWarning),
    /// Agent is deeply stuck — request a fresh restart with new strategy.
    Restart(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckWarning {
    pub kind: StuckKind,
    pub message: String,
    pub iterations_stuck: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckKind {
    SameEndpoint,
    ErrorLoop,
    NoProgress,
    TechniqueExhaustion,
}

/// Tracks recent agent behavior to detect unproductive patterns.
pub struct StuckDetector {
    recent_endpoints: VecDeque<String>,
    recent_results: VecDeque<IterationResult>,
    iteration_count: u32,
    findings_count: u32,
    last_finding_at: u32,
    same_endpoint_threshold: usize,
    error_streak_threshold: usize,
    no_progress_threshold: u32,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct IterationResult {
    endpoint: String,
    technique: String,
    is_error: bool,
    is_finding: bool,
}

impl Default for StuckDetector {
    fn default() -> Self {
        Self {
            recent_endpoints: VecDeque::with_capacity(DEFAULT_WINDOW),
            recent_results: VecDeque::with_capacity(DEFAULT_WINDOW),
            iteration_count: 0,
            findings_count: 0,
            last_finding_at: 0,
            same_endpoint_threshold: DEFAULT_SAME_ENDPOINT_THRESHOLD,
            error_streak_threshold: DEFAULT_ERROR_STREAK_THRESHOLD,
            no_progress_threshold: DEFAULT_NO_PROGRESS_THRESHOLD,
            created_at: Instant::now(),
        }
    }
}

impl StuckDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new iteration from the agent loop. Call this after each
    /// sampling request completes and tool results are drained.
    pub fn record_iteration(&mut self, endpoint: &str, technique: &str, is_error: bool) {
        self.iteration_count += 1;

        let result = IterationResult {
            endpoint: endpoint.to_string(),
            technique: technique.to_string(),
            is_error,
            is_finding: false,
        };

        if self.recent_endpoints.len() >= DEFAULT_WINDOW {
            self.recent_endpoints.pop_front();
        }
        self.recent_endpoints.push_back(endpoint.to_string());

        if self.recent_results.len() >= DEFAULT_WINDOW {
            self.recent_results.pop_front();
        }
        self.recent_results.push_back(result);
    }

    /// Record that a finding was reported.
    pub fn record_finding(&mut self) {
        self.findings_count += 1;
        self.last_finding_at = self.iteration_count;
    }

    /// Analyze recent iterations and return the recommended action.
    pub fn check(&self) -> StuckAction {
        if let Some(warning) = self.check_same_endpoint() {
            if warning.iterations_stuck as usize >= self.same_endpoint_threshold + 3 {
                return StuckAction::Restart(format!(
                    "Stuck on {} for {} iterations. Restarting with fresh strategy.",
                    self.recent_endpoints.back().unwrap_or(&String::new()),
                    warning.iterations_stuck,
                ));
            }
            return StuckAction::Warn(warning);
        }

        if let Some(warning) = self.check_error_loop() {
            if warning.iterations_stuck as usize >= self.error_streak_threshold + 3 {
                return StuckAction::Restart(
                    "Error loop detected for 8+ iterations. Restarting.".into(),
                );
            }
            return StuckAction::Warn(warning);
        }

        if let Some(warning) = self.check_no_progress() {
            let since = self.iteration_count - self.last_finding_at;
            if since >= self.no_progress_threshold * 2 {
                return StuckAction::Restart(format!(
                    "No findings in {} iterations. Full restart needed.",
                    since,
                ));
            }
            return StuckAction::Warn(warning);
        }

        if let Some(warning) = self.check_technique_exhaustion() {
            return StuckAction::Warn(warning);
        }

        StuckAction::Continue
    }

    fn check_same_endpoint(&self) -> Option<StuckWarning> {
        if self.recent_endpoints.len() < self.same_endpoint_threshold {
            return None;
        }
        let last_n: Vec<&String> = self
            .recent_endpoints
            .iter()
            .rev()
            .take(self.same_endpoint_threshold)
            .collect();

        if last_n.is_empty() {
            return None;
        }
        let first = last_n[0];
        if first.is_empty() {
            return None;
        }
        if last_n.iter().all(|e| *e == first) {
            Some(StuckWarning {
                kind: StuckKind::SameEndpoint,
                message: format!(
                    "You have been targeting {} for {} consecutive iterations. \
                     Move to a different endpoint or technique immediately.",
                    first,
                    self.same_endpoint_threshold,
                ),
                iterations_stuck: self.same_endpoint_threshold as u32,
            })
        } else {
            None
        }
    }

    fn check_error_loop(&self) -> Option<StuckWarning> {
        let streak: usize = self
            .recent_results
            .iter()
            .rev()
            .take_while(|r| r.is_error)
            .count();

        if streak >= self.error_streak_threshold {
            Some(StuckWarning {
                kind: StuckKind::ErrorLoop,
                message: format!(
                    "Last {} iterations all resulted in errors. \
                     Stop this approach entirely and try a different attack vector.",
                    streak,
                ),
                iterations_stuck: streak as u32,
            })
        } else {
            None
        }
    }

    fn check_no_progress(&self) -> Option<StuckWarning> {
        if self.iteration_count < self.no_progress_threshold {
            return None;
        }
        let since_finding = self.iteration_count - self.last_finding_at;
        if since_finding >= self.no_progress_threshold {
            Some(StuckWarning {
                kind: StuckKind::NoProgress,
                message: format!(
                    "No new findings in {} iterations. Reassess your attack surface. \
                     Try: hidden parameters, alternative auth methods, race conditions, \
                     business logic flaws, request smuggling, cache poisoning.",
                    since_finding,
                ),
                iterations_stuck: since_finding,
            })
        } else {
            None
        }
    }

    fn check_technique_exhaustion(&self) -> Option<StuckWarning> {
        if self.recent_results.len() < 8 {
            return None;
        }
        let mut counts = std::collections::HashMap::new();
        for r in self.recent_results.iter().rev().take(10) {
            if !r.technique.is_empty() {
                *counts.entry(r.technique.as_str()).or_insert(0u32) += 1;
            }
        }
        for (technique, count) in &counts {
            if *count >= 6 {
                return Some(StuckWarning {
                    kind: StuckKind::TechniqueExhaustion,
                    message: format!(
                        "Technique '{}' used {} times in last 10 iterations. \
                         Try a completely different approach.",
                        technique, count,
                    ),
                    iterations_stuck: *count,
                });
            }
        }
        None
    }

    pub fn iteration_count(&self) -> u32 {
        self.iteration_count
    }

    pub fn findings_count(&self) -> u32 {
        self.findings_count
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_stuck_on_fresh_detector() {
        let d = StuckDetector::new();
        assert_eq!(d.check(), StuckAction::Continue);
    }

    #[test]
    fn detects_same_endpoint() {
        let mut d = StuckDetector::new();
        for _ in 0..5 {
            d.record_iteration("/api/v1/users", "idor", false);
        }
        match d.check() {
            StuckAction::Warn(w) => assert_eq!(w.kind, StuckKind::SameEndpoint),
            other => panic!("Expected Warn(SameEndpoint), got {:?}", other),
        }
    }

    #[test]
    fn detects_error_loop() {
        let mut d = StuckDetector::new();
        for _ in 0..5 {
            d.record_iteration("/api/v1/login", "sqli", true);
        }
        match d.check() {
            StuckAction::Warn(w) => assert_eq!(w.kind, StuckKind::ErrorLoop),
            other => panic!("Expected Warn(ErrorLoop), got {:?}", other),
        }
    }

    #[test]
    fn resets_on_varied_endpoints() {
        let mut d = StuckDetector::new();
        for i in 0..5 {
            d.record_iteration(&format!("/api/v{}", i), "scan", false);
        }
        assert_eq!(d.check(), StuckAction::Continue);
    }

    #[test]
    fn finding_resets_no_progress() {
        let mut d = StuckDetector::new();
        for _ in 0..19 {
            d.record_iteration("/api/test", "scan", false);
        }
        d.record_finding();
        d.record_iteration("/api/test2", "scan", false);
        assert_eq!(d.check(), StuckAction::Continue);
    }
}
