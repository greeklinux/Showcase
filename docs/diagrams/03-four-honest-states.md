# The four honest states, and the default argument that lies

Four different answers that most dashboards collapse into one number. The
lower path is the defect, kept visible on purpose.

```mermaid
flowchart TD
    Q["A metric is requested"] --> AP{"Does this metric<br/>apply to this subject?"}
    AP -- "no" --> NA["NOT_AVAILABLE<br/>a fact about the subject,<br/>not about the check"]
    AP -- "yes" --> RD{"Did the read complete?"}
    RD -- "raised ReadFailure or KeyError" --> NM["NOT_MEASURED<br/>unknown. The check did not run"]
    RD -- "yes" --> RW{"Were there rows in scope?"}
    RW -- "none" --> MN["MEASURED_NONE<br/>it ran, and found nothing.<br/>This is a result"]
    RW -- "k of N" --> ME["MEASURED<br/>k of N rows"]

    Q -. "the usual way, for comparison" .-> DEF["rows = store.get(key, 0)<br/>except: rows = []"]
    DEF --> LIE["renders '0 of 0 rows'<br/>for a failed read AND for a clean empty result.<br/>The worst outcome on the screen<br/>is now the most reassuring one"]

    classDef honest fill:#e6e2f8,stroke:#5b4bb5,stroke-width:1px,color:#1a1440
    classDef gate fill:#fff3d6,stroke:#9a6b12,stroke-width:1px,color:#3a2a05
    classDef refuse fill:#ffe0dd,stroke:#b4341f,stroke-width:1px,color:#3d0f0a
    classDef data fill:#e5eaf3,stroke:#4a5b78,stroke-width:1px,color:#141b26
    class NA,NM,MN,ME honest
    class AP,RD,RW gate
    class DEF,LIE refuse
    class Q data
```

**What it shows.** The order is load bearing, and a flow diagram is the only
way to show that. Applicability is decided *before* the read is attempted,
because "this subject has no such metric" is something you already know and
must not discover as a read failure. Collapse any two of the four states and
you have re-invented the bug on the lower path.

**Checkable against.** `polymind/honest_states.py`: `State`, `read_state`,
`render`, and `render_naive`, which is the lower path kept in the file so the
difference is visible. Tests in `tests/test_honest_states.py`.
