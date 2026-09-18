<a id="why-fusing-beats-averaging"></a>

# Log-odds pooling and averaging

Two pooling rules produce different results from the same inputs. This diagram
shows their arithmetic, not a ranking of forecast quality.

```mermaid
flowchart TD
    P1["signal A, p = 0.80"] --> L1["logit +1.386"]
    P2["signal B, p = 0.80"] --> L2["logit +1.386"]
    P3["a neutral signal,<br/>p = 0.50"] -.-> L3["logit 0.000"]

    L1 --> SUM["weighted sum of logits"]
    L2 --> SUM
    L3 -. "zero contribution<br/>under this pooling rule" .-> SUM

    SUM --> INV["back through<br/>the logistic"]
    INV --> OUT["fused = 0.941<br/>two agreeing reads compound"]

    AVG["alternative pooling rule:<br/>average the probabilities"] --> BAD["0.800<br/>preserves the common estimate"]

    classDef live fill:#d9f2e6,stroke:#1f7a4d,stroke-width:1px,color:#0b2a1b
    classDef data fill:#e5eaf3,stroke:#4a5b78,stroke-width:1px,color:#141b26
    classDef refuse fill:#ffe0dd,stroke:#b4341f,stroke-width:1px,color:#3d0f0a
    classDef honest fill:#e6e2f8,stroke:#5b4bb5,stroke-width:1px,color:#1a1440
    class P1,P2,P3,AVG data
    class L1,L2,L3,SUM,INV live
    class OUT honest
    class BAD data
```

**What it shows.** With unit weights, summing the logits of two 0.80 inputs
and applying the logistic function produces 0.941. A 0.50 input has zero logit
and contributes nothing under this rule. Averaging two identical 0.80 inputs
preserves their common value instead.

**Limits.** A Bayesian evidence-combination interpretation requires compatible
priors and conditionally independent evidence. Shared priors and overlapping
sources can be counted repeatedly. Neither increased confidence nor a neutral
0.50 contribution establishes calibration or improved accuracy.

**Reproduce it.** `python3 polymind/signal_fusion.py` prints `0.941` for the two
0.80 inputs and `0.800` for a 0.80 input pooled with 0.50.

**Where this is rendered.** The `signal_fusion.py` section of
`polymind/README.md` contains the identical diagram. The root README links to
that section.

**Checkable against.** `polymind/signal_fusion.py` and
`tests/test_signal_fusion.py`. The outputs demonstrate the function's arithmetic,
not returns, predictive accuracy, or realized results.
