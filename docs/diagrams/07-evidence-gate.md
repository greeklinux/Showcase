# The evidence gate: three channels, and why a seat can report unearned

When a provider does not answer, the row still has to be filled or coverage
silently drops, so a clearly marked placeholder is written. That is honest at
write time. The dishonesty happens later, when something counts those rows.

```mermaid
flowchart TD
    ROW["One booked row"] --> C1["Channel 1<br/>persisted placeholder flag,<br/>read as bool, int or string"]
    ROW --> C2["Channel 2<br/>in-flight fallback key, set<br/>before the row is persisted"]
    ROW --> C3["Channel 3<br/>coverage fallback marker in the<br/>reasoning text, which catches rows<br/>written before the flag column existed"]
    C1 --> ANY{"Did any channel fire?<br/>All three always run. Not first<br/>match wins, so a row caught<br/>by two is reported as two"}
    C2 --> ANY
    C3 --> ANY
    ANY -- "one or more fired" --> REF["Refused, and the gate records WHICH.<br/>Every count is a LOWER BOUND: a path<br/>that sets none of the three<br/>is invisible to all three"]
    ANY -- "none fired" --> ADM["Admitted into the arithmetic"]
    REF --> SR{"Seat report"}
    ADM --> SR
    SR -- "rows offered,<br/>none admitted" --> UN["UNEARNED, with its refused count.<br/>The seat keeps its row"]
    SR -- "no rows<br/>offered" --> NR["NO_ROWS"]
    SR -- "admitted<br/>rows exist" --> EA["EARNED, over<br/>admitted rows only"]

    classDef live fill:#d9f2e6,stroke:#1f7a4d,stroke-width:1px,color:#0b2a1b
    classDef gate fill:#fff3d6,stroke:#9a6b12,stroke-width:1px,color:#3a2a05
    classDef refuse fill:#ffe0dd,stroke:#b4341f,stroke-width:1px,color:#3d0f0a
    classDef honest fill:#e6e2f8,stroke:#5b4bb5,stroke-width:1px,color:#1a1440
    classDef data fill:#e5eaf3,stroke:#4a5b78,stroke-width:1px,color:#141b26
    classDef off fill:#f0eeec,stroke:#7a6f66,stroke-width:1px,color:#2a2420,stroke-dasharray: 5 3
    class ANY,SR gate
    class REF refuse
    class ADM,EA live
    class UN,NR honest
    class ROW,C1,C2,C3 data
```

**What it shows.** Three independent channels, because any single one leaks.
The persisted flag misses a row that never got the column. The in-flight key
misses a row written before that code path existed. The text marker catches
rows written before the flag column existed at all. Any one firing disqualifies
the row, and the gate records which fired.

The subtle half is the right hand side. Filtering placeholders out of the
arithmetic is correct. Dropping the seat from the report is not. A seat that
exists and has earned nothing is a different fact from a seat that does not
exist, and rendering them the same way turns "we measured this and it is empty"
into "there is nothing here". So an all placeholder seat reports UNEARNED, and
a seat that is absent from the ledger entirely is absent from the report, which
is the fourth and different fact.

**Checkable against.** `polymind/evidence_gate.py`: `screen`, the three channel
constants, `seat_report` and its three non collapsed outcomes, and
`counts_are_a_lower_bound`. Tests in `tests/test_evidence_gate.py`.
