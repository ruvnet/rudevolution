//! Confidence-gated cost cascade for AI name recovery.
//!
//! rudevolution already computes a [`crate::types::InferredName::confidence`]
//! score for every recovered name. This module wires a *cost cascade* onto that
//! existing gate: run a **cheap** model first, and **escalate to a more
//! expensive (frontier) model only when the cheap result's confidence falls
//! below a threshold**. Most names are recovered cheaply; you only pay the
//! frontier price for the hard, low-confidence ones. This is a pure
//! cost-Pareto win — no accuracy is sacrificed, because the cheap tier's answer
//! is kept whenever it is already confident enough.
//!
//! ## Mapping to the metaharness thesis
//!
//! The metaharness "cascade" thesis says: route work to the cheapest model that
//! can do it, and escalate only on signal. rudevolution's per-inference
//! confidence score *is* that signal, so the cascade is a thin, native wiring
//! rather than bolted-on machinery.
//!
//! ## Default = unchanged behavior
//!
//! A [`CascadeInferrer`] built with a single tier behaves exactly like calling
//! that tier directly. The crate's existing pipeline does not use the cascade
//! unless a caller explicitly opts in via [`crate::infer_names_cascade`], so all
//! pre-existing tests and the default `decompile()` path are untouched.
//!
//! ## Self-tuning (closes the self-learning loop)
//!
//! Every inference records a [`CascadeOutcome`] (which tier answered, its
//! confidence, whether it escalated, and whether escalation changed the answer).
//! [`CascadeInferrer::suggest_threshold`] reads that log and proposes an
//! adjusted threshold for the next run: if frontier escalations keep *agreeing*
//! with the cheap tier, the threshold drops (stop paying for confirmations); if
//! they keep *overturning* it, the threshold rises (escalate more eagerly).

use crate::inferrer::{infer_declaration_name, InferenceContext};
use crate::training::TrainingCorpus;
use crate::types::{Declaration, InferredName, Module};

/// A single model tier in the cascade.
///
/// Implementors range from the built-in pattern/corpus inferrer (cheap, $0) to
/// a neural transformer (medium) to an external frontier model behind a network
/// call (expensive). The cascade only knows two things about a tier: a human
/// label/relative cost (for reporting + self-tuning) and how to attempt an
/// inference for one declaration.
pub trait NameInferrer {
    /// Short label for this tier, e.g. `"corpus"`, `"transformer"`, `"frontier"`.
    fn label(&self) -> &str;

    /// Relative cost weight of invoking this tier (arbitrary units; only the
    /// ordering/ratio matters). Used purely for cost accounting in
    /// [`CascadeStats`]. A typical scheme: corpus = 0.0, local model = 1.0,
    /// frontier API = 100.0.
    fn cost(&self) -> f64 {
        0.0
    }

    /// Attempt to infer a name for `decl`. Returns `None` if this tier has no
    /// opinion (the cascade then keeps the previous best, if any, and may still
    /// escalate).
    fn infer(&self, decl: &Declaration, ctx: &InferenceContext) -> Option<InferredName>;
}

/// The built-in cheap tier: pattern tables + training corpus + structural
/// heuristics. This is exactly the inference the crate has always done, wrapped
/// as a cascade tier. Cost is $0 (no model call).
pub struct CorpusTier {
    corpus: TrainingCorpus,
}

impl CorpusTier {
    /// Build a corpus tier from the built-in Claude Code patterns.
    pub fn builtin() -> Self {
        Self {
            corpus: TrainingCorpus::builtin(),
        }
    }

    /// Build a corpus tier from a caller-supplied corpus.
    pub fn with_corpus(corpus: TrainingCorpus) -> Self {
        Self { corpus }
    }
}

impl NameInferrer for CorpusTier {
    fn label(&self) -> &str {
        "corpus"
    }

    fn cost(&self) -> f64 {
        0.0
    }

    fn infer(&self, decl: &Declaration, _ctx: &InferenceContext) -> Option<InferredName> {
        infer_declaration_name(decl, &self.corpus)
    }
}

/// Outcome of a single declaration's pass through the cascade.
///
/// Recorded so the existing self-learning loop can both (a) attribute results to
/// model tiers and (b) self-tune the escalation threshold over runs.
#[derive(Debug, Clone)]
pub struct CascadeOutcome {
    /// The minified identifier that was being recovered.
    pub original: String,
    /// Label of the tier whose answer was ultimately kept.
    pub winning_tier: String,
    /// Confidence of the kept answer.
    pub confidence: f64,
    /// Number of tiers actually invoked (1 = cheap tier was enough).
    pub tiers_tried: usize,
    /// Whether the cascade escalated past the first (cheapest) tier.
    pub escalated: bool,
    /// When escalation happened: did the more expensive tier produce a
    /// *different* name than the cheap tier? `None` if no escalation occurred.
    /// `Some(false)` means the frontier merely confirmed the cheap answer —
    /// a signal the threshold could be lowered.
    pub escalation_changed_answer: Option<bool>,
    /// Total relative cost spent on this declaration (sum of invoked tier costs).
    pub cost: f64,
}

/// Aggregate statistics over a batch of cascade inferences.
#[derive(Debug, Clone, Default)]
pub struct CascadeStats {
    /// Total declarations processed.
    pub total: usize,
    /// How many were answered by the cheapest tier alone.
    pub cheap_wins: usize,
    /// How many escalated to a more expensive tier.
    pub escalations: usize,
    /// Of the escalations, how many had the frontier *agree* with the cheap tier.
    pub escalations_confirmed: usize,
    /// Of the escalations, how many had the frontier *overturn* the cheap tier.
    pub escalations_overturned: usize,
    /// Total relative cost spent.
    pub total_cost: f64,
    /// Hypothetical cost if every declaration had gone straight to the most
    /// expensive tier (the "frontier-only" baseline). Lets callers report
    /// savings.
    pub frontier_only_cost: f64,
}

impl CascadeStats {
    /// Fraction of declarations resolved without escalation (0.0..=1.0).
    pub fn cheap_win_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.cheap_wins as f64 / self.total as f64
        }
    }

    /// Cost saved versus the frontier-only baseline (>= 0.0).
    pub fn cost_saved(&self) -> f64 {
        (self.frontier_only_cost - self.total_cost).max(0.0)
    }
}

/// A confidence-gated cost cascade over an ordered list of model tiers.
///
/// Tiers must be ordered cheapest-first. For each declaration the cascade
/// invokes tiers in order, stopping as soon as a tier returns an answer with
/// `confidence >= threshold`. If no tier clears the bar, the highest-confidence
/// answer seen across all tiers is kept.
pub struct CascadeInferrer {
    tiers: Vec<Box<dyn NameInferrer>>,
    threshold: f64,
    outcomes: Vec<CascadeOutcome>,
}

impl CascadeInferrer {
    /// Default escalation threshold. Mirrors the crate's existing "high
    /// confidence" boundary (see [`crate::types::Confidence::High`]): a cheap
    /// answer at or above this is trusted without paying for a frontier call.
    pub const DEFAULT_THRESHOLD: f64 = 0.9;

    /// Build a cascade from cheapest-first tiers and an escalation threshold.
    ///
    /// # Panics
    /// Panics if `tiers` is empty — a cascade needs at least one tier.
    pub fn new(tiers: Vec<Box<dyn NameInferrer>>, threshold: f64) -> Self {
        assert!(!tiers.is_empty(), "cascade requires at least one tier");
        Self {
            tiers,
            threshold: threshold.clamp(0.0, 1.0),
            outcomes: Vec::new(),
        }
    }

    /// Build a single-tier cascade over the built-in corpus inferrer.
    ///
    /// This is the **default-unchanged** constructor: with one tier and any
    /// threshold, the cascade can never escalate, so its output is identical to
    /// the crate's existing [`crate::inferrer::infer_names`].
    pub fn single_corpus() -> Self {
        Self::new(
            vec![Box::new(CorpusTier::builtin())],
            Self::DEFAULT_THRESHOLD,
        )
    }

    /// Current escalation threshold.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Override the escalation threshold (clamped to `0.0..=1.0`).
    pub fn set_threshold(&mut self, threshold: f64) {
        self.threshold = threshold.clamp(0.0, 1.0);
    }

    /// Number of configured tiers.
    pub fn tier_count(&self) -> usize {
        self.tiers.len()
    }

    /// Recorded per-inference outcomes since construction (or last [`Self::reset`]).
    pub fn outcomes(&self) -> &[CascadeOutcome] {
        &self.outcomes
    }

    /// Clear the recorded outcome log.
    pub fn reset(&mut self) {
        self.outcomes.clear();
    }

    /// Infer a name for one declaration, recording the outcome.
    ///
    /// Returns `None` only if *no* tier produced any answer at all.
    pub fn infer_declaration(&mut self, decl: &Declaration) -> Option<InferredName> {
        let ctx = InferenceContext::from_declaration(decl);

        let mut best: Option<InferredName> = None;
        let mut best_tier_idx = 0usize;
        let mut tiers_tried = 0usize;
        let mut spent = 0.0f64;
        // Track the first tier's answer so we can tell whether escalation
        // changed it (the self-tuning signal).
        let mut first_answer: Option<String> = None;

        for (idx, tier) in self.tiers.iter().enumerate() {
            tiers_tried += 1;
            spent += tier.cost();

            if let Some(candidate) = tier.infer(decl, &ctx) {
                if idx == 0 {
                    first_answer = Some(candidate.inferred.clone());
                }
                let candidate_conf = candidate.confidence;
                let candidate_name = candidate.inferred.clone();

                // Keep the higher-confidence answer.
                if best.as_ref().map_or(true, |b| candidate_conf > b.confidence) {
                    best = Some(candidate);
                    best_tier_idx = idx;
                }

                // Confident enough? Stop — don't pay for the next tier.
                if candidate_conf >= self.threshold {
                    let _ = candidate_name;
                    break;
                }
            }
            // else: this tier abstained; fall through and try the next one.
        }

        let escalated = tiers_tried > 1;
        let escalation_changed_answer = if escalated {
            match (&first_answer, &best) {
                (Some(first), Some(b)) => Some(first != &b.inferred),
                // Cheap tier abstained but a later tier answered: count as changed.
                (None, Some(_)) => Some(true),
                _ => None,
            }
        } else {
            None
        };

        if let Some(ref b) = best {
            self.outcomes.push(CascadeOutcome {
                original: decl.name.clone(),
                winning_tier: self.tiers[best_tier_idx].label().to_string(),
                confidence: b.confidence,
                tiers_tried,
                escalated,
                escalation_changed_answer,
                cost: spent,
            });
        }

        best
    }

    /// Infer names for every declaration across all modules.
    pub fn infer_modules(&mut self, modules: &[Module]) -> Vec<InferredName> {
        let mut out = Vec::new();
        for module in modules {
            for decl in &module.declarations {
                if let Some(name) = self.infer_declaration(decl) {
                    out.push(name);
                }
            }
        }
        out
    }

    /// Aggregate statistics over all recorded outcomes.
    pub fn stats(&self) -> CascadeStats {
        let frontier_cost = self.tiers.iter().map(|t| t.cost()).sum::<f64>();
        let mut s = CascadeStats {
            frontier_only_cost: frontier_cost * self.outcomes.len() as f64,
            ..Default::default()
        };
        for o in &self.outcomes {
            s.total += 1;
            s.total_cost += o.cost;
            if o.escalated {
                s.escalations += 1;
                match o.escalation_changed_answer {
                    Some(true) => s.escalations_overturned += 1,
                    Some(false) => s.escalations_confirmed += 1,
                    None => {}
                }
            } else {
                s.cheap_wins += 1;
            }
        }
        s
    }

    /// Propose an adjusted escalation threshold for the next run, learning from
    /// recorded outcomes. This is the self-tuning step that closes the loop with
    /// rudevolution's "gets smarter every run" design.
    ///
    /// Heuristic:
    /// - If escalations mostly **confirmed** the cheap answer, the threshold is
    ///   too high (we paid for needless frontier calls) → lower it.
    /// - If escalations mostly **overturned** the cheap answer, the cheap tier
    ///   was being trusted too readily near the bar → raise it.
    /// - With no escalations, leave the threshold unchanged.
    ///
    /// `step` bounds the per-call adjustment (e.g. `0.05`). The result is
    /// clamped to a sane `0.5..=0.99` band.
    pub fn suggest_threshold(&self, step: f64) -> f64 {
        let s = self.stats();
        if s.escalations == 0 {
            return self.threshold;
        }
        let confirmed = s.escalations_confirmed as f64;
        let overturned = s.escalations_overturned as f64;
        let total = (confirmed + overturned).max(1.0);
        // Net signal in [-1, 1]: positive => mostly confirmed => lower threshold.
        let confirm_ratio = (confirmed - overturned) / total;
        let delta = -confirm_ratio * step;
        (self.threshold + delta).clamp(0.5, 0.99)
    }

    /// Apply [`Self::suggest_threshold`] in place and return the new value.
    pub fn self_tune(&mut self, step: f64) -> f64 {
        let next = self.suggest_threshold(step);
        self.threshold = next;
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeclKind, Declaration, Module};

    /// Deterministic fake tier for testing escalation — no real model call.
    /// Returns a fixed name at a fixed confidence for any declaration.
    struct FakeTier {
        label: &'static str,
        cost: f64,
        name: &'static str,
        confidence: f64,
        /// If true, abstain (return None) instead of answering.
        abstain: bool,
    }

    impl NameInferrer for FakeTier {
        fn label(&self) -> &str {
            self.label
        }
        fn cost(&self) -> f64 {
            self.cost
        }
        fn infer(&self, decl: &Declaration, _ctx: &InferenceContext) -> Option<InferredName> {
            if self.abstain {
                return None;
            }
            Some(InferredName {
                original: decl.name.clone(),
                inferred: self.name.to_string(),
                confidence: self.confidence,
                evidence: vec![format!("fake tier {}", self.label)],
            })
        }
    }

    fn decl(name: &str) -> Declaration {
        Declaration {
            name: name.to_string(),
            kind: DeclKind::Var,
            byte_range: (0, 4),
            string_literals: vec![],
            property_accesses: vec![],
            references: vec![],
        }
    }

    fn module(decls: Vec<Declaration>) -> Module {
        Module {
            name: "m".to_string(),
            index: 0,
            declarations: decls,
            source: String::new(),
            byte_range: (0, 0),
        }
    }

    fn fake(label: &'static str, cost: f64, name: &'static str, conf: f64) -> Box<dyn NameInferrer> {
        Box::new(FakeTier {
            label,
            cost,
            name,
            confidence: conf,
            abstain: false,
        })
    }

    #[test]
    fn cheap_win_does_not_escalate() {
        // Cheap tier returns a high-confidence answer (>= threshold).
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "cheap_name", 0.95),
                fake("frontier", 100.0, "frontier_name", 0.99),
            ],
            0.9,
        );
        let got = c.infer_declaration(&decl("a")).unwrap();
        assert_eq!(got.inferred, "cheap_name");
        let o = &c.outcomes()[0];
        assert_eq!(o.tiers_tried, 1, "must not invoke the frontier tier");
        assert!(!o.escalated);
        assert_eq!(o.winning_tier, "cheap");
        assert_eq!(o.cost, 0.0, "no frontier cost paid");
    }

    #[test]
    fn low_confidence_escalates_to_frontier() {
        // Cheap tier is below threshold → escalate; frontier is more confident.
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "cheap_name", 0.4),
                fake("frontier", 100.0, "frontier_name", 0.95),
            ],
            0.9,
        );
        let got = c.infer_declaration(&decl("a")).unwrap();
        assert_eq!(got.inferred, "frontier_name");
        let o = &c.outcomes()[0];
        assert_eq!(o.tiers_tried, 2);
        assert!(o.escalated);
        assert_eq!(o.escalation_changed_answer, Some(true));
        assert_eq!(o.winning_tier, "frontier");
        assert_eq!(o.cost, 100.0);
    }

    #[test]
    fn escalation_keeps_best_when_frontier_weaker() {
        // Cheap below threshold, frontier even weaker → keep cheap (highest conf).
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "cheap_name", 0.6),
                fake("frontier", 100.0, "frontier_name", 0.3),
            ],
            0.9,
        );
        let got = c.infer_declaration(&decl("a")).unwrap();
        assert_eq!(got.inferred, "cheap_name");
        let o = &c.outcomes()[0];
        assert!(o.escalated, "still escalated because cheap was below bar");
        assert_eq!(o.winning_tier, "cheap");
    }

    #[test]
    fn frontier_confirming_cheap_is_recorded() {
        // Both produce the SAME name; cheap is below bar so it escalates and the
        // frontier confirms → escalation_changed_answer = Some(false).
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "same_name", 0.5),
                fake("frontier", 100.0, "same_name", 0.95),
            ],
            0.9,
        );
        c.infer_declaration(&decl("a")).unwrap();
        let o = &c.outcomes()[0];
        assert_eq!(o.escalation_changed_answer, Some(false));
    }

    #[test]
    fn single_tier_never_escalates_default_unchanged() {
        // A single-tier cascade behaves exactly like the wrapped tier — the
        // default-unchanged guarantee. Even a below-threshold answer is returned
        // as-is with no escalation.
        let mut c = CascadeInferrer::new(vec![fake("only", 0.0, "only_name", 0.2)], 0.9);
        let got = c.infer_declaration(&decl("a")).unwrap();
        assert_eq!(got.inferred, "only_name");
        let o = &c.outcomes()[0];
        assert_eq!(o.tiers_tried, 1);
        assert!(!o.escalated);
    }

    #[test]
    fn single_corpus_matches_existing_inferrer() {
        // The opt-in single-corpus cascade must reproduce the crate's existing
        // corpus inference for a known high-confidence pattern.
        let mut d = decl("x");
        d.string_literals = vec!["tools/call".to_string()];
        let mut c = CascadeInferrer::single_corpus();
        let got = c.infer_declaration(&d).expect("should infer");
        assert!(got.confidence > 0.9);
        // Matches inferrer.rs's KNOWN_PATTERNS mapping.
        assert_eq!(got.inferred, "mcp_tool_call");
        assert!(!c.outcomes()[0].escalated);
    }

    #[test]
    fn abstaining_cheap_tier_escalates() {
        let mut c = CascadeInferrer::new(
            vec![
                Box::new(FakeTier {
                    label: "cheap",
                    cost: 0.0,
                    name: "unused",
                    confidence: 0.0,
                    abstain: true,
                }),
                fake("frontier", 100.0, "frontier_name", 0.95),
            ],
            0.9,
        );
        let got = c.infer_declaration(&decl("a")).unwrap();
        assert_eq!(got.inferred, "frontier_name");
        let o = &c.outcomes()[0];
        assert!(o.escalated);
        assert_eq!(o.escalation_changed_answer, Some(true));
    }

    #[test]
    fn stats_track_cheap_wins_and_savings() {
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "cheap_name", 0.95),
                fake("frontier", 100.0, "frontier_name", 0.99),
            ],
            0.9,
        );
        let m = module(vec![decl("a"), decl("b"), decl("c")]);
        let names = c.infer_modules(&[m]);
        assert_eq!(names.len(), 3);
        let s = c.stats();
        assert_eq!(s.total, 3);
        assert_eq!(s.cheap_wins, 3);
        assert_eq!(s.escalations, 0);
        assert_eq!(s.total_cost, 0.0);
        assert_eq!(s.frontier_only_cost, 100.0 * 3.0);
        assert_eq!(s.cost_saved(), 300.0);
        assert!((s.cheap_win_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn self_tune_lowers_threshold_when_frontier_confirms() {
        // All escalations confirm the cheap answer → threshold should drop.
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "same", 0.5),
                fake("frontier", 100.0, "same", 0.95),
            ],
            0.9,
        );
        for n in ["a", "b", "c", "d"] {
            c.infer_declaration(&decl(n));
        }
        let before = c.threshold();
        let after = c.self_tune(0.05);
        assert!(after < before, "confirmations should lower threshold");
        assert!(after >= 0.5);
    }

    #[test]
    fn self_tune_raises_threshold_when_frontier_overturns() {
        // All escalations overturn the cheap answer → threshold should rise.
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "cheap_wrong", 0.5),
                fake("frontier", 100.0, "frontier_right", 0.95),
            ],
            0.9,
        );
        for n in ["a", "b", "c", "d"] {
            c.infer_declaration(&decl(n));
        }
        let before = c.threshold();
        let after = c.self_tune(0.05);
        assert!(after > before, "overturns should raise threshold");
        assert!(after <= 0.99);
    }

    #[test]
    fn self_tune_no_op_without_escalations() {
        let mut c = CascadeInferrer::new(vec![fake("cheap", 0.0, "n", 0.95)], 0.9);
        c.infer_declaration(&decl("a"));
        assert_eq!(c.suggest_threshold(0.05), 0.9);
    }

    #[test]
    fn three_tier_stops_at_middle_when_confident() {
        // cheap below bar, middle clears bar → frontier never runs.
        let mut c = CascadeInferrer::new(
            vec![
                fake("cheap", 0.0, "c", 0.4),
                fake("middle", 1.0, "m", 0.92),
                fake("frontier", 100.0, "f", 0.99),
            ],
            0.9,
        );
        let got = c.infer_declaration(&decl("a")).unwrap();
        assert_eq!(got.inferred, "m");
        let o = &c.outcomes()[0];
        assert_eq!(o.tiers_tried, 2);
        assert_eq!(o.cost, 1.0, "frontier (cost 100) must not be paid");
    }

    #[test]
    #[should_panic(expected = "at least one tier")]
    fn empty_cascade_panics() {
        let _ = CascadeInferrer::new(vec![], 0.9);
    }
}
