# Diagrams

Ten diagrams, one per file, each a single fenced `mermaid` block with a caption
that says what mechanism it shows, which page should carry it, and what in this
repository it can be checked against.

This directory is the canonical source. Nothing here is wired into a page by
itself: to use one, copy its fenced block into the target README.

## Format

Diagrams use Mermaid so their structure is reviewable in Git and renders inline
on GitHub. Captions link each mechanism to its implementation and validation.

## The set

| # | File | The mechanism it shows | Meant for |
| --- | --- | --- | --- |
| 01 | [`01-learning-loop.md`](01-learning-loop.md) | One market, end to end, and the four different ways the loop can close, three of which are refusals. | `polymind/README.md`, at the top |
| 02 | [`02-role-lens-record.md`](02-role-lens-record.md) | A role is given, a lens is a portable procedure, a record is earned. The graft carries the first two and raises on the third. | `polymind/README.md`, `method_graft.py` row |
| 03 | [`03-four-honest-states.md`](03-four-honest-states.md) | The four states and the order they are decided in, beside the default argument path that renders a failed read as a clean zero. | `polymind/README.md`; [`../THEMES.md`](../THEMES.md) theme 3 |
| 04 | [`04-control-not-in-effect.md`](04-control-not-in-effect.md) | The check runs, the verdict is produced, the decision reads something else. Plus the five real instances of that exact shape. | `ai_security/README.md`; [`../THEMES.md`](../THEMES.md) theme 1 |
| 05 | [`05-mount-surface-audit.md`](05-mount-surface-audit.md) | Route by route: mutating or not, effective auth rather than declared auth, and the runtime override that neutralises a declared dependency. Carries the worked route table too. | `ai_security/README.md`, `mount_audit.py` row |
| 06 | [`06-skill-lifecycle.md`](06-skill-lifecycle.md) | An illustrative separation between measurement, validation, and permission to change behavior. | `polymind/README.md`, architecture principles; `GOVERNANCE.md` control 1 |
| 07 | [`07-evidence-gate.md`](07-evidence-gate.md) | Three independent channels, any one disqualifying, and the three non collapsed seat outcomes, including why a seat can report unearned instead of a rate. | `polymind/README.md`, `evidence_gate.py` row |
| 08 | [`08-agent-action-gates.md`](08-agent-action-gates.md) | Four gates that can only subtract, and four outcomes, two of which a dashboard usually merges although they are opposites. | `ai_security/README.md`, `agentic_soc.py` row |
| 09 | [`09-release-gate.md`](09-release-gate.md) | Why three buckets are not enough: the agent that refuses everything, and the empty bucket that must not count as a perfect result. | `ai_security/README.md`, `eval_harness.py` row |
| 10 | [`10-log-odds-fusion.md`](10-log-odds-fusion.md) | Why a neutral signal contributes exactly zero by construction, which a weighted average cannot do. | `polymind/README.md`, `signal_fusion.py` row |

## What each page renders

**Fifty five mermaid blocks render across the repository:** five on the root
`README.md`, ten on `polymind/`, thirteen on `ai_security/`, ten on
`blackgate/`, two on `automation/`, five on [`../THEMES.md`](../THEMES.md), and
the ten canonical sources here. The inventory is checked by
[`../../tests/check_claims.py`](../../tests/check_claims.py).

| # | Subject | Rendered on | Relationship |
| --- | --- | --- | --- |
| 01 | One market end to end | **Here only.** `polymind/README.md` opens with an end to end walk of one claim, which covers the scoring half of this subject; the reset and graft loop is prose there rather than a diagram | This page contains the complete loop; the other views focus on its component responsibilities |
| 02 | Role given, lens portable, record earned | `polymind/README.md`, `method_graft.py` row, and again on [`../THEMES.md`](../THEMES.md) under theme 4 | Drawn independently on both |
| 03 | The four honest states | `polymind/README.md`, `honest_states.py` row, and again on [`../THEMES.md`](../THEMES.md) under theme 3 | Drawn independently on both |
| 04 | A control that is written, reviewed and not in effect | `ai_security/README.md` as a flowchart, and on [`../THEMES.md`](../THEMES.md) under theme 1 as a state diagram of the five shapes a dead control takes | Drawn independently on both, in three different diagram types across the three places |
| 05 | The mount surface audit | `ai_security/README.md`, `mount_audit.py` row | Drawn independently |
| 06 | The skill lifecycle | `polymind/README.md`, "Measurement before behavior changes" | **Copied verbatim from this directory** |
| 07 | The evidence gate, three channels | `polymind/README.md`, `evidence_gate.py` row | Drawn independently |
| 08 | Four gates that can only subtract | `ai_security/README.md`, `agentic_soc.py` row | Drawn independently, as a before and after pair |
| 09 | The release gate and the empty bucket | `ai_security/README.md`, `eval_harness.py` row | Drawn independently |
| 10 | Why fusing beats averaging | `polymind/README.md`, `signal_fusion.py` row | **Copied verbatim from this directory** |

Use the captioned sources when adding diagrams to a new page. Keep verbatim
copies synchronized; the automated checks verify the declared copies.

## How to embed one

Copy the whole fenced block, from its opening fence line through its closing
fence, into the target page. Nothing else needs to travel with it.

Three rules that cost time to learn:

- **Never nest a mermaid block inside a collapsed `<details>` element.** On
  GitHub it renders at zero width, so the diagram is simply not there until the
  reader opens the section, and often not then either.
- **Do not wrap it in `<div align="center">`.** The block must start at the
  beginning of a line for the fence to be recognised.
- Leave a blank line before and after the fence.

## Light and dark

GitHub picks the mermaid theme from the reader's colour mode, so anything that
relies on the default text colour or the default node fill flips with it. Two
rules keep every diagram here legible in both:

1. **Meaning is carried by shape and line style first.** A gated off stage is a
   dashed border, a decision is a diamond. Those survive any theme and any
   colour blindness.
2. **Where a fill is set, the text colour and the stroke are always set with
   it.** Every `classDef` in this directory pairs a light fill with an explicit
   dark `color` and a mid tone `stroke`, so a node is a light chip with dark
   text on a white page and a light chip with dark text on a dark page. No
   diagram inherits a colour that only one background defines.

The palette is one set of six classes shared across the directory, so the set
reads as one system: `live` green, `gate` amber, `refuse` red, `honest` violet,
`data` slate, `off` dashed grey. Each file draws the subset its diagram needs,
four of them use all six, and no file introduces a seventh.

The one exception is the sequence diagram in 04, which uses two translucent
`rect` bands at ten percent alpha to separate "as built" from "as wired now".
A ten percent tint is a tint of whatever is behind it, so it works on both
backgrounds by construction, and everything inside those bands is default
themed.

## Verification

Run `python3 tests/check_claims.py` from the repository root to check diagram
inventory, declared copies, links and numeric claims. These structural checks
are separate from Mermaid parsing and visual inspection.

The optional [`render_diagrams.py`](../../tools/render_diagrams.py) tool renders
all tracked blocks in both themes and writes SVGs, widths and a JSON report to
a temporary directory. Install Mermaid CLI separately from the Python examples,
then provide its executable and a local Chrome or Chromium path:

```bash
python3 tools/render_diagrams.py --mmdc /path/to/mmdc --browser /path/to/chrome
```

The September 18, 2026 validation used Mermaid CLI 11.17.0: **55 blocks,
110 SVG renders**, with the invalid-syntax control rejected. All rendered
widths were below 1,500 viewBox units. Re-run after changing a diagram.

For visual validation, render every block locally in light and dark themes with
Mermaid CLI. Require a successful exit and a nonempty SVG, then inspect labels
at GitHub's reading width. Keep diagrams below approximately 1,500 viewBox units
where practical. Include an intentionally invalid block to confirm that the
renderer rejects syntax errors. Third-party rendering endpoints are not part
of the verification workflow.

## Scope

Diagrams explain control flow, evidence and decision boundaries. Repository
navigation and numeric inventories remain tables. Examples use synthetic data;
they do not represent investment performance or production detection rates.
Detection logic is available in the linked source queries.
