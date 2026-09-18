# Gates that can only subtract

A multi-agent SOC triage pipeline where an action executes on its own only if
every gate says yes, and no gate can ever raise the answer.

```mermaid
flowchart TD
    AL["Alert arrives. Model tier chosen<br/>by severity, never by confidence"] --> PR{"Did an agent<br/>propose anything?"}
    PR -- "no" --> NA["NO ACTION NEEDED"]
    PR -- "yes" --> G1{"Gate 1, schema and allowlist.<br/>Default deny, exhaustive argument<br/>bounds, unknown keys are a refusal"}
    G1 -- "fails" --> RF["REFUSED, and the record names<br/>the gate that stopped it"]
    G1 -- "passes" --> G2{"Gate 2, independent review.<br/>A second agent must return an explicit<br/>APPROVE. Unparsable is a rejection,<br/>because silence is not consent"}
    G2 -- "not APPROVE" --> RF
    G2 -- "APPROVE" --> G3{"Gate 3, impact. A high impact<br/>mutating action needs a person,<br/>whatever the reviewer thought"}
    G3 -- "high impact" --> HH["HELD FOR HUMAN"]
    G3 -- "low impact" --> G4{"Gate 4, severity.<br/>Raises the bar, never lowers it"}
    G4 -- "high or critical" --> HH
    G4 -- "low or<br/>medium" --> AE["AUTO EXECUTE, with an approval bound<br/>to a digest of this exact call"]

    classDef live fill:#d9f2e6,stroke:#1f7a4d,stroke-width:1px,color:#0b2a1b
    classDef gate fill:#fff3d6,stroke:#9a6b12,stroke-width:1px,color:#3a2a05
    classDef refuse fill:#ffe0dd,stroke:#b4341f,stroke-width:1px,color:#3d0f0a
    classDef honest fill:#e6e2f8,stroke:#5b4bb5,stroke-width:1px,color:#1a1440
    classDef data fill:#e5eaf3,stroke:#4a5b78,stroke-width:1px,color:#141b26
    classDef off fill:#f0eeec,stroke:#7a6f66,stroke-width:1px,color:#2a2420,stroke-dasharray: 5 3
    class AL data
    class PR,G1,G2,G3,G4 gate
    class RF refuse
    class AE live
    class HH,NA honest
```

**What it shows.** Four outcomes, and the two that a dashboard usually merges
are opposites: NO ACTION NEEDED means nothing needed doing, HELD FOR HUMAN
means something needed doing and is waiting for a person. A dashboard that only
tracks whether an action ran renders both as "no action", which is how a queue
of pending containment goes unnoticed.

Note where severity enters. It chooses the model tier at the top and it raises
the bar at the bottom, and it is never allowed to authorize an action on its
own. That separation exists because the first version of this pipeline computed
execution from severity alone while a reviewer agent's verdict sat unread in
the response. The blast radius of being wrong is what scales, not the
confidence.

Approvals are bound to a digest of one exact tool and argument set, so an
approval for a lookup cannot be replayed onto a later account disable.

**Checkable against.** `ai_security/agentic_soc.py`: `Severity`,
`MODEL_BY_SEVERITY`, `HUMAN_REQUIRED_AT`, `review_action`, the `triage` gate
chain and `TriageRecord.render`, whose four outcome strings are the four leaves
here. `call_digest` and `validate_tool_call` live in
`ai_security/llm_output_validator.py`. Mapped to NIST AI RMF MANAGE 2.4,
OWASP LLM03:2026 Excessive Agency (LLM06:2025) and MITRE ATLAS AML.T0053.
