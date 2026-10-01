# The skill lifecycle: measure before promotion

An illustrative design separates measurement from permission to change behavior.
This is a design pattern, not an inventory of private running services.

```mermaid
flowchart TD
    subgraph MEASURE["Illustrative measurement stages"]
        direction TB
        M1["Candidate<br/>detection"] --> M2["Evaluation against<br/>the price implied null"]
        M2 --> M3["Verdict row<br/>written"]
        M3 --> M4["Loss streak<br/>detection"]
        M4 --> M5["Fail closed adjudication:<br/>any error, timeout or<br/>unparsable answer<br/>removes nothing"]
        M5 --> M6["Record measurement<br/>provenance"]
    end

    MEASURE == "a measurement now exists,<br/>and it stops here" ==> BOUND{"Has the evidence cleared<br/>predeclared validation criteria?"}

    BOUND -- "no: keep changes gated" --> A1["Walk forward<br/>validation"]
    BOUND --> A2["Promotion<br/>to active"]
    BOUND --> A3["Per sport<br/>sweep"]
    BOUND --> A4["Bind a finding onto<br/>the live prompt by name"]

    A1 --> REP["Every stage reports which it is:<br/>ran, gate off, throttled, unavailable,<br/>scheduled but silent, or never scheduled.<br/>Status accompanies the count"]
    A2 --> REP
    A3 --> REP
    A4 --> REP

    classDef live fill:#d9f2e6,stroke:#1f7a4d,stroke-width:1px,color:#0b2a1b
    classDef gate fill:#fff3d6,stroke:#9a6b12,stroke-width:1px,color:#3a2a05
    classDef honest fill:#e6e2f8,stroke:#5b4bb5,stroke-width:1px,color:#1a1440
    classDef off fill:#f0eeec,stroke:#7a6f66,stroke-width:1px,color:#2a2420,stroke-dasharray: 5 3
    class M1,M2,M3,M4,M5,M6 live
    class BOUND gate
    class A1,A2,A3,A4 off
    class REP honest
```

**What it shows.** Candidate evaluation and promotion are separate decisions.
A stage reports whether it ran, was gated off, failed, or was not scheduled.
The diagram does not claim an implemented scheduler or a live deployment.

**Where this is rendered.** `polymind/README.md`, under "Measurement before
behavior changes".

**Related examples.** `polymind/evidence_gate.py`, `polymind/posterior.py`,
and `polymind/honest_states.py` demonstrate component concepts. They do not
implement this full lifecycle.
