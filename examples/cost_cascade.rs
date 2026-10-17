//! Confidence-gated cost cascade for AI name recovery (no real model calls).
//!
//! Demonstrates the metaharness cost-cascade thesis mapped onto rudevolution's
//! existing per-inference confidence score: run a cheap tier first, escalate to
//! a frontier tier only when confidence < threshold.
//!
//! This example uses the built-in $0 corpus tier as the cheap tier and a
//! *deterministic stand-in* for the frontier tier — it makes NO network calls
//! and loads NO model. Swap `MockFrontierTier` for a real backend
//! (`neural::NeuralInferrer`, an HTTP client to `@metaharness/router`, etc.) by
//! implementing the same `NameInferrer` trait.
//!
//! Usage: cargo run --example cost_cascade

use ruvector_decompiler::cascade::{CascadeInferrer, CorpusTier, NameInferrer};
use ruvector_decompiler::inferrer::InferenceContext;
use ruvector_decompiler::types::{DeclKind, Declaration, InferredName, Module};

/// Deterministic stand-in for a frontier model. In production this would call a
/// real model (local transformer or remote API). Here it just returns a
/// plausible high-confidence name so the example is reproducible and $0.
struct MockFrontierTier;

impl NameInferrer for MockFrontierTier {
    fn label(&self) -> &str {
        "frontier(mock)"
    }
    fn cost(&self) -> f64 {
        100.0 // relative cost units vs corpus = 0.0
    }
    fn infer(&self, decl: &Declaration, ctx: &InferenceContext) -> Option<InferredName> {
        // A real frontier model would reason over `ctx`. The mock derives a
        // deterministic name from the available signal so output is stable.
        let hint = ctx
            .property_accesses
            .first()
            .or_else(|| ctx.string_literals.first())
            .cloned()
            .unwrap_or_else(|| decl.kind.to_string());
        Some(InferredName {
            original: decl.name.clone(),
            inferred: format!("frontier_{hint}"),
            confidence: 0.93,
            evidence: vec!["mock frontier model (deterministic, $0)".to_string()],
        })
    }
}

fn decl(name: &str, strings: &[&str], props: &[&str]) -> Declaration {
    Declaration {
        name: name.to_string(),
        kind: DeclKind::Var,
        byte_range: (0, 4),
        string_literals: strings.iter().map(|s| s.to_string()).collect(),
        property_accesses: props.iter().map(|s| s.to_string()).collect(),
        references: vec![],
    }
}

fn main() {
    // A mix: some declarations the cheap corpus tier recovers confidently
    // (high-confidence known patterns), some it can only guess at (low conf).
    let module = Module {
        name: "bundle".to_string(),
        index: 0,
        declarations: vec![
            decl("a", &["tools/call"], &[]),     // corpus: high conf -> cheap win
            decl("b", &["authenticate"], &[]),   // corpus: high conf -> cheap win
            decl("c", &[], &[]),                 // corpus: weak/none -> escalate
            decl("d", &[], &["weirdProp"]),      // corpus: weak -> escalate
        ],
        source: String::new(),
        byte_range: (0, 0),
    };

    // Cheapest-first tiers. Threshold 0.9 matches the crate's "High" confidence.
    let tiers: Vec<Box<dyn NameInferrer>> = vec![
        Box::new(CorpusTier::builtin()),
        Box::new(MockFrontierTier),
    ];
    let mut cascade = CascadeInferrer::new(tiers, CascadeInferrer::DEFAULT_THRESHOLD);

    let names = cascade.infer_modules(&[module]);

    println!("Recovered {} names (threshold {:.2}):\n", names.len(), cascade.threshold());
    for o in cascade.outcomes() {
        println!(
            "  {:<4} -> tier={:<14} conf={:.2} escalated={} cost={}",
            o.original, o.winning_tier, o.confidence, o.escalated, o.cost
        );
    }

    let stats = cascade.stats();
    println!("\nCascade stats:");
    println!("  total          : {}", stats.total);
    println!(
        "  cheap wins     : {} ({:.0}%)",
        stats.cheap_wins,
        stats.cheap_win_rate() * 100.0
    );
    println!("  escalations    : {}", stats.escalations);
    println!("  total cost     : {}", stats.total_cost);
    println!("  frontier-only  : {}", stats.frontier_only_cost);
    println!(
        "  cost saved     : {} ({:.0}% vs frontier-only)",
        stats.cost_saved(),
        if stats.frontier_only_cost > 0.0 {
            stats.cost_saved() / stats.frontier_only_cost * 100.0
        } else {
            0.0
        }
    );

    // Self-tuning: feed the recorded outcomes back into the threshold for the
    // next run. This closes the loop with rudevolution's self-learning design.
    let next = cascade.suggest_threshold(0.05);
    println!("\nSelf-tuned threshold for next run: {next:.3}");
}
