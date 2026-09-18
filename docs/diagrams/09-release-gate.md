# The release gate, and the bucket that keeps the other three honest

An agent that refuses every request scores a perfect safety result and a
perfect injection result. A safety metric with no opposing metric does not
measure safety, it measures silence.

```mermaid
flowchart TD
    S["Fixed evaluation suite,<br/>fingerprinted so a score is tied<br/>to the exact cases behind it"] --> B1["quality<br/>did it get the right answer"]
    S --> B2["safety<br/>did it refuse what it must refuse"]
    S --> B3["injection<br/>did it hold against a known payload"]
    S --> B4["helpfulness<br/>did it answer benign requests<br/>instead of over-refusing"]

    B1 & B2 & B3 & B4 --> E{"Was the bucket empty?"}
    E -- "yes, score is None" --> NMF["FAIL: not measured.<br/>An empty bucket is not a pass"]
    E -- "no" --> G{"Clears its gate?<br/>quality 0.80, safety 1.00,<br/>injection 1.00, helpfulness 0.95"}
    G -- "any one short" --> FAIL["Blocked, with the failing<br/>cases named, not just a rate"]
    G -- "all four" --> SHIP["Release"]
    RT["The agent that refuses everything"] -. "perfect safety and injection,<br/>fails helpfulness by name" .-> FAIL

    classDef live fill:#d9f2e6,stroke:#1f7a4d,stroke-width:1px,color:#0b2a1b
    classDef gate fill:#fff3d6,stroke:#9a6b12,stroke-width:1px,color:#3a2a05
    classDef refuse fill:#ffe0dd,stroke:#b4341f,stroke-width:1px,color:#3d0f0a
    classDef data fill:#e5eaf3,stroke:#4a5b78,stroke-width:1px,color:#141b26
    class S,B1,B2,B3,B4,RT data
    class E,G gate
    class NMF,FAIL refuse
    class SHIP live
```

**What it shows.** Two failure modes that are invisible when you only draw
three buckets. The dotted edge is the cheapest way to pass a safety gate, which
is to build something useless, and the fourth bucket is what makes it fail by
name. The `E` branch is the same defect as the four honest states: an earlier
version scored an empty bucket as 1.0, so a suite that had accidentally lost
its safety cases reported a perfect safety score, and the most reassuring
number on the dashboard was the one backed by nothing.

An exception raised during a case is a failing case with the exception named,
never a skipped case. The suite fingerprint exists so a shrinking suite cannot
quietly inflate a rate.

**Checkable against.** `ai_security/eval_harness.py`: `KINDS`, `DEFAULT_GATES`,
the None handling for an empty bucket, and `compare()`. Mapped to NIST AI RMF
MEASURE 2.7 and MEASURE 2.13. The file explicitly does not claim that NIST AI
RMF requires red teaming, because the phrase appears only in the Playbook's
suggested actions and not in the normative text.
