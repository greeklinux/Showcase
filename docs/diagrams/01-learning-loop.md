# The learning loop

One market, end to end, and every point at which the system is allowed to
refuse. This is a conceptual architecture, not a live deployment report.

```mermaid
flowchart TD
    A["Market intake"] --> B["Every seat predicts<br/>independently, under its<br/>own named reasoning role"]
    B --> C{"Evidence gate:<br/>real model call,<br/>or placeholder?"}
    C -- "placeholder" --> R["Refused. Out of every<br/>rate, weight and<br/>money query"]
    C -- "real call" --> D["Paper trade booked,<br/>simulated bankroll"]
    D --> E["Settlement against<br/>ground truth"]
    E --> F["Calibration: Brier score.<br/>Influence re-earned,<br/>or quietly lost"]
    E --> G["Posterior: Beta mean,<br/>95 percent Wilson<br/>lower bound"]
    G --> H{"Rule table, first match wins.<br/>The null is the price implied<br/>favourite rate, not a coin flip"}
    H -- "verdict row written" --> P["Promotion to active:<br/>built, tested,<br/>gated off on purpose"]
    E --> L{"Predeclared loss-streak<br/>review threshold<br/>reached?"}
    L -- "yes" --> M["Reset epoch marker.<br/>Acquired habits stripped,<br/>original reasoning protected,<br/>donor method grafted<br/>as a prompt overlay"]
    M --> A
    L -- "no" --> A
    F --> A
    R --> A

    classDef live fill:#d9f2e6,stroke:#1f7a4d,stroke-width:1px,color:#0b2a1b
    classDef gate fill:#fff3d6,stroke:#9a6b12,stroke-width:1px,color:#3a2a05
    classDef refuse fill:#ffe0dd,stroke:#b4341f,stroke-width:1px,color:#3d0f0a
    classDef honest fill:#e6e2f8,stroke:#5b4bb5,stroke-width:1px,color:#1a1440
    classDef data fill:#e5eaf3,stroke:#4a5b78,stroke-width:1px,color:#141b26
    classDef off fill:#f0eeec,stroke:#7a6f66,stroke-width:1px,color:#2a2420,stroke-dasharray: 5 3
    class A,B,D,E,F,G,M live
    class C,H,L gate
    class R refuse
    class P off
```

**What it shows.** The loop closes four different ways, and three of them are
refusals: a row the evidence gate rejects, a verdict that never reaches a
promotion stage because that stage is switched off, and a losing streak that
resets a seat rather than letting it keep compounding. The dashed node is the
honest part. Measurement runs all the way round; the step that would let a
measurement change live behaviour does not.

**Checkable against.** `polymind/evidence_gate.py`, `polymind/posterior.py`
(`RULE_TABLE`, `price_implied_null`), `polymind/calibration.py`,
`polymind/method_graft.py`, The reset and promotion stages are conceptual; these public modules do not
implement the full loop.
