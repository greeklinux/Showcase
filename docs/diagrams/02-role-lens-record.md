# Role, lens and record: what a graft may carry

Three things a model can hold. Two of them are a procedure and port cleanly.
The third is a measurement of one specific model and may never move.

```mermaid
flowchart TD
    subgraph DONOR["Donor seat, the one that is working"]
        RO["ROLE<br/>the job the seat is given"]
        LE["LENS<br/>reasoning rubric,<br/>factor weights, style prior"]
        RE["RECORD<br/>fitted calibration curve,<br/>validated skill, settled record"]
    end

    RO -- "given, so it<br/>can be given again" --> G{"assert_transferable(kind)"}
    LE -- "a procedure, portable<br/>by construction" --> G
    RE -- "a measurement<br/>of the donor" --> G

    G -- "TRANSFERABLE_KINDS" --> T["Grafted onto the recipient as<br/>an additive prompt overlay"]
    G -- "NEVER_TRANSFERABLE_KINDS" --> X["UnearnedClaimError raised.<br/>A refusal is an item in the plan,<br/>never a silent omission"]

    RE -. "the only way<br/>a curve may travel" .-> B["BORROWED prior, labelled borrowed<br/>not earned, metadata forbids writing to<br/>calibration_store or earned_record"]
    B --> T
    T --> U["Recipient record after the graft:<br/>UNKNOWN_NOT_MEASURED"]
    X --> U

    classDef live fill:#d9f2e6,stroke:#1f7a4d,stroke-width:1px,color:#0b2a1b
    classDef gate fill:#fff3d6,stroke:#9a6b12,stroke-width:1px,color:#3a2a05
    classDef refuse fill:#ffe0dd,stroke:#b4341f,stroke-width:1px,color:#3d0f0a
    classDef honest fill:#e6e2f8,stroke:#5b4bb5,stroke-width:1px,color:#1a1440
    class RO,LE,T live
    class G gate
    class RE,X refuse
    class B,U honest
```

**What it shows.** Why the refusal is the feature and not a limitation. A
grafted seat begins life unmeasured and has to earn its own curve, which is the
only condition under which anyone can later tell whether the graft worked. Copy
the curve as well and the recipient starts out already claiming to be well
calibrated, so the experiment can never fail. The refusal raises rather than
skipping, because a silent skip produces a plan that looks complete and
quietly is not.

**Checkable against.** `polymind/method_graft.py`: `TRANSFERABLE_KINDS`,
`NEVER_TRANSFERABLE_KINDS`, `assert_transferable`, `borrowed_prior`,
`UNMEASURED`, and `tests/test_method_graft.py`.

The borrowed-prior prohibition is metadata in this example. A consuming storage
layer must enforce it; the example does not implement such a layer.
