# AI Governance and Security Mapping

My approach to governing agentic systems: explicit decision boundaries,
measurable behavior and reviewable evidence. The examples below demonstrate
selected controls; framework mappings are not certifications or compliance
assessments.

## The frameworks I build to

| Framework | What it governs | Where it shows up here |
| --- | --- | --- |
| **NIST AI RMF 1.0** | Map, Measure, Manage, Govern AI risk | [`eval_harness.py`](ai_security/eval_harness.py) (Measure), the reviewer gate in [`agentic_soc.py`](ai_security/agentic_soc.py) (Manage), the substrate census described below (Govern) |
| **ISO/IEC 42001** | AI management system, lifecycle controls | The private-by-design posture, release gating, and a documented lifecycle in which a capability is only promoted once its evidence clears a stated bar |
| **OWASP Top 10 for LLM Applications** | LLM-specific vulnerabilities | [`prompt_guard.py`](ai_security/prompt_guard.py) (LLM01:2026, LLM01:2025), [`llm_output_validator.py`](ai_security/llm_output_validator.py) (LLM10:2026 and LLM05:2025 Improper Output Handling; LLM03:2026 and LLM06:2025 Excessive Agency) |
| **MITRE ATLAS** | Adversarial ML tactics and techniques | Injection tests in [`eval_harness.py`](ai_security/eval_harness.py); the full technique table in [`ai_security/README.md`](ai_security/README.md) |
| **MITRE ATT&CK** | Detection engineering coverage | [`ai_security/detections/`](ai_security/detections), and the integrity and prohibition controls in [`blackgate/`](blackgate/) |

Framework mappings include edition identifiers because control numbering can
change between releases. Detailed mappings and their scope are documented in
[`ai_security/README.md`](ai_security/README.md) and
[`blackgate/README.md`](blackgate/README.md).

## The three questions I make sure I can answer

1. **Is it measured?** A release policy should require a fixed evaluation
   suite with separate quality, safety, injection, and helpfulness gates. See [`ai_security/eval_harness.py`](ai_security/eval_harness.py).
2. **How is autonomous action constrained?** Agency is bounded by a default-deny
   allowlist and a human-in-the-loop for high-impact actions. See
   [`ai_security/llm_output_validator.py`](ai_security/llm_output_validator.py)
   and [`ai_security/agentic_soc.py`](ai_security/agentic_soc.py).
3. **Is it accountable?** Decisions should carry traceable evidence, sources
   should earn influence from verified results, and consequential actions
   should require an authorization gate. See [`polymind/calibration.py`](polymind/calibration.py).

## Four controls I would not ship an autonomous system without

These design principles are illustrated by the public examples. They describe
control requirements, not an attestation of a private deployment. The public
architecture walkthrough is at
[polymindatlas.uliseshurtado.com](https://polymindatlas.uliseshurtado.com).

### 1. Measurement is live before action is

Measurement and authorization to change behavior should be separate stages.
A candidate remains inactive until it clears predeclared validation criteria.
The public examples demonstrate evidence screening and evaluation; they do not
expose the private deployment schedule or certify which services are running.

### 2. Every learning stage declares whether it ran

A ledger sitting at zero rows because nothing ever called the writer is
indistinguishable from a ledger at zero rows because the writer ran and found
nothing, unless the system says which out loud. Every stage is registered with
its schedule, its gate, the key it writes, and what it is permitted to touch,
and a reader reports each one as ran, not run because the gate is off,
throttled, unavailable, scheduled but silent, or never scheduled at all. The
"scheduled but silent" state exists specifically to surface a control that
everyone believes is running and is not.

### 3. Four states, never collapsed

*Not measured*, *measured and found nothing*, *measured*, and *not available*
are four different answers. Collapsing them is how a failed read renders as a
reassuring zero, which is the single most dangerous output an assurance
dashboard can produce. The same discipline applies to rates: a rate is refused
unless it arrives with its denominator and the baseline it is supposed to beat,
so "better than chance" can never be presented as "better than the market."

### 4. Provenance decides what counts as evidence

Any output that did not come from a real model call is recorded as an explicit
placeholder and excluded from every ranking, every learned weight and every
reported record, through one shared predicate that every consumer must import
rather than re-derive locally. Every count of placeholder data is published as
a lower bound, because a count of what you detected is never a count of what
exists. A shared predicate prevents consumers from applying inconsistent
definitions of admissible evidence.

## What the system is not allowed to do

- **Public examples use synthetic data.** They do not place orders or expose
  private trading configuration.

- **No transferring what was not earned.** A frozen set of three kinds, skill,
  calibration and heuristic, may never be copied between models. Every transfer
  path imports that one set, so the rule cannot drift as the code grows. A
  donor's calibration may travel only as a borrowed prior that is labeled
  borrowed and is never written into the calibration tables.
- **No stripping a model's original reasoning.** Only habits a model acquired
  are eligible for removal after a losing streak; the way it originally reasons
  should remain distinct from learned overlays. The public examples illustrate
  transfer boundaries; they do not certify private reset behavior.
- **No adjudicating in the dark.** The reviewer that decides whether to remove
  a habit fails closed: any error, timeout or unparsable answer removes
  nothing.
- **No deleting history.** A reset is an epoch marker, not a balance write. The
  record stays byte-identical and the new state falls out of replaying what
  came after the marker.

## What I refuse to claim

- No return, win rate or investment performance is claimed anywhere in this
  repository, for any system described in it.
- Conceptual architecture is not a statement of private deployment status.
  Public examples establish only the behavior that can be reproduced here.
- Where a measurement depends on the environment it ran in, the environment is
  published with the number instead of one figure being presented as universal.

## Why this matters for hiring me

These examples show how I approach authorization, evidence quality, and
regression testing. Each claim should be traceable to a public implementation
or a reproducible test, with deployment assumptions stated separately.

---

The four controls above are the general statement. Every one of them has
concrete instances in the code, catalogued by theme rather than by project in
[`docs/THEMES.md`](docs/THEMES.md): control 1 and control 2 are theme 1 there,
control 3 is theme 3, and control 4 is themes 3 and 4 together. That page also
records where each theme is **absent**, which is the part of a governance claim
nobody usually writes down.

<div align="center">

[`README.md`](README.md) &nbsp;&middot;&nbsp;
[`docs/THEMES.md`](docs/THEMES.md) &nbsp;&middot;&nbsp;
[`SECURITY.md`](SECURITY.md) &nbsp;&middot;&nbsp;
[`polymind/`](polymind/README.md) &nbsp;&middot;&nbsp;
[`ai_security/`](ai_security/README.md) &nbsp;&middot;&nbsp;
[`blackgate/`](blackgate/README.md) &nbsp;&middot;&nbsp;
[`automation/`](automation/README.md)

</div>
