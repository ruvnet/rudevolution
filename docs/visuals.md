# ruDevolution visual system

The visuals are editable, self-contained SVG assets used by the repository README. They illustrate architectural stages and evidence boundaries. They are not benchmark outputs or correctness proofs.

| Asset | Meaning |
| --- | --- |
| [Animated header](assets/rudevolution-hero.svg) | Untrusted bundle → reference graph → candidate modules |
| [Introduction](assets/rudevolution-intro.svg) | Three views of the supplied input, without executing it |
| [Five-phase pipeline](assets/rudevolution-pipeline.svg) | Conceptual stages of the Rust analysis engine |
| [Human feedback loop](assets/rudevolution-learning.svg) | Human-reviewed labels, candidate learning, held-out evaluation |
| [Evidence boundaries](assets/rudevolution-trust.svg) | What byte integrity checks can and cannot verify |

## Visual vocabulary

**Teal** denotes input observations and parsing. **Blue** denotes reference relationships. **Violet** denotes proposed identifiers. **Amber** denotes integrity boundaries and cautions. Animated traces represent information flow, not real-time telemetry or measured performance.

Animations are declarative SVG/CSS with a `prefers-reduced-motion` override. All files include `title` and `desc`; the README includes descriptive `alt` text. The nearby Markdown provides a text path independently of images. No remote font, CDN, JavaScript, or executable content is needed.

## Verification

Run from the repository root:

```bash
python3 scripts/check_visuals.py
npm test
cargo test --locked
(cd dashboard && npm ci --ignore-scripts && npm run build)
```

The Python check validates XML, accessibility metadata, local README references, uniqueness of SVG IDs, content size, reduced-motion rules, and rejects executable or remote references. CI runs the same gate.

These checks test asset structure, unit behavior, and compilation. They do not establish general name-recovery accuracy or semantic equivalence. For those claims, use a held-out, provenance-controlled differential corpus as described in [the security and performance review](reviews/2026-09-security-performance.md).
