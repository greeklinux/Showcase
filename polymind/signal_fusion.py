"""Combine weighted probability estimates by summing their log-odds.

fuse() accepts (probability, weight) pairs and returns the sigmoid of their
weighted logit sum. Inputs must be finite, probabilities must lie in [0, 1],
and endpoint probabilities are clamped before conversion. A 0.50 input
contributes zero, and an empty input returns 0.50.

This is a pooling rule, not a universal replacement for probability averaging.
Its interpretation depends on the evidence and prior assumptions. Correlated
or overlapping sources can be double-counted; source calibration, trust-weight
selection, and correlation adjustment are outside this synthetic example.
"""

import math


def _finite(value: object, name: str) -> float:
    """Accept a real, finite number and refuse everything else by name."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a real number, got {value!r}")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    return value


def logit(p: float, eps: float = 1e-6) -> float:
    """Probability -> log-odds. Clamped so 0 and 1 never blow up to infinity.

    The clamp is for the rails of a real probability. It is not a laundry for
    garbage: a p of 5.0 or of NaN is refused rather than quietly clamped onto
    the rail, because clamping turns a malformed input into a confident output.
    """
    p = _finite(p, "probability")
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"probability must lie in [0, 1], got {p!r}")
    p = min(max(p, eps), 1.0 - eps)
    return math.log(p / (1.0 - p))


def sigmoid(x: float) -> float:
    """Log-odds -> probability. Defined over the whole real line.

    Written in two branches rather than as the one line 1 / (1 + exp(-x)).
    That form raises OverflowError once the evidence passes about -710 nats,
    because exp of a large positive number leaves the range of a double: a
    single distrusted-but-confident signal, fuse([(0.01, 200.0)]), crashed
    instead of returning a probability near zero. Each branch below
    exponentiates a negative number, which underflows smoothly toward zero
    rather than overflowing.
    """
    x = _finite(x, "log-odds")
    if x >= 0.0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


def fuse(signals: list[tuple[float, float]]) -> float:
    """Fuse independent probability estimates in log-odds space.

    signals: list of (probability, weight). A 0.5 signal adds zero evidence,
    so noise cannot wash out conviction. Correlated sources should be
    down-weighted first (handled elsewhere) or their evidence double-counts.

    Every probability and every weight has to be a real finite number. A
    malformed pair is refused by name rather than fused into a `nan` that
    would go on to render as a probability.
    """
    total_evidence = 0.0
    for index, pair in enumerate(signals):
        try:
            p, weight = pair
        except (TypeError, ValueError):
            raise ValueError(
                f"signal {index} must be a (probability, weight) pair, "
                f"got {pair!r}")
        total_evidence += _finite(weight, f"weight of signal {index}") * logit(p)
    return sigmoid(total_evidence)


if __name__ == "__main__":
    # Two independent, equally trusted 0.80 reads of the same outcome.
    naive_average = (0.80 + 0.80) / 2                    # -> 0.800, learns nothing
    fused = fuse([(0.80, 1.0), (0.80, 1.0)])             # -> about 0.941, agreement compounds

    print(f"naive average : {naive_average:.3f}")
    print(f"log-odds fused: {fused:.3f}   <- two agreeing signals raise conviction")

    # A strong read plus a pure-noise read: the noise is ignored, not averaged in.
    print(f"strong + noise: {fuse([(0.80, 1.0), (0.50, 1.0)]):.3f}   <- 0.5 adds nothing")
