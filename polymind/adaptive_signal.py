"""Update a probability estimate from weighted signals and return a sized decision.

AdaptiveEstimator accumulates Beta pseudo-counts from finite signals, clamped
to [0, 1], and non-negative weights. decide() compares the estimate with a
market price and returns buy_yes, buy_no, or hold, with supporting values or a
hold reason. Kelly sizing is capped per position.

This synthetic example illustrates the calculation, not the production
strategy or an investment result. Its confidence value is a pseudo-count
heuristic, and the position cap does not model portfolio-wide risk.
Architecture: https://polymindatlas.greeklinux.dev
"""

import math
import collections
from dataclasses import dataclass, field


def _real(value: object, name: str) -> float:
    """Accept a real, finite number and refuse everything else by name.

    NaN is the input this exists for. It compares False against every
    threshold, so `confidence < min_confidence` and `abs(edge) < min_edge`
    were BOTH false for a belief built out of one NaN signal and the gate that
    is supposed to hold on thin evidence opened instead. A gate that cannot
    refuse an unreadable number is not a gate.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a real number, got {value!r}")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    return value


# How many recent signals the estimator keeps. Enough to look at, and a fixed
# amount of memory for a component that is meant to run for ever.
HISTORY_WINDOW = 512


@dataclass
class AdaptiveEstimator:
    """Online probability estimate that learns from each new signal.

    Uses a Beta(alpha, beta) belief so the estimate self-updates as evidence
    accumulates and naturally grows more confident over time. This is the
    "self-learning" core: no retraining job, it adapts on every observation.
    """

    alpha: float = 1.0            # prior successes
    beta: float = 1.0             # prior failures
    # The most recent signals, bounded. This was an unbounded `list` that
    # `update` appended to and nothing in the repository ever read: the class
    # is sold two lines above as long lived and adapting on every observation,
    # so it is exactly the object that never gets thrown away, and it held
    # 8.4 MB after a million updates and kept going. The belief itself is two
    # numbers and needs no history at all; the window is kept because a recent
    # sample is useful to look at, and it is a `deque` with a maximum so that
    # looking at it costs a fixed amount of memory.
    history: object = field(
        default_factory=lambda: collections.deque(maxlen=HISTORY_WINDOW))

    def __post_init__(self) -> None:
        """Both pseudo-counts must be positive, so alpha + beta is never zero.

        `estimate` and `confidence` both divide by alpha + beta, and a
        Beta(0, 0) belief made every read of the estimate a ZeroDivisionError.

        A history supplied by a caller is re-framed with the same maximum,
        because an unbounded history is the leak whatever supplied it.
        """
        if (not isinstance(self.history, collections.deque)
                or self.history.maxlen is None):
            try:
                self.history = collections.deque(self.history,
                                                 maxlen=HISTORY_WINDOW)
            except TypeError:
                self.history = collections.deque(maxlen=HISTORY_WINDOW)
        self.alpha = _real(self.alpha, "alpha")
        self.beta = _real(self.beta, "beta")
        if self.alpha <= 0.0 or self.beta <= 0.0:
            raise ValueError(
                "alpha and beta are pseudo-counts and must both be positive: "
                f"got alpha={self.alpha!r}, beta={self.beta!r}")

    def update(self, signal: float, weight: float = 1.0) -> None:
        """Fold a new signal in [0, 1] into the belief, scaled by trust.

        A finite signal outside [0, 1] is clamped, which is the documented
        behaviour. A signal that is not a real finite number is refused
        instead: clamping NaN returns NaN, and that NaN then reaches every
        threshold downstream as a comparison that is False in both directions.

        The weight is refused when it is negative as well. A negative weight
        subtracts pseudo-counts, which drove alpha + beta to exactly zero
        (ZeroDivisionError on the next read) or negative, at which point
        `estimate` returned 1.33 and `decide` published a fair value of 133
        percent with the maximum stake attached to it.
        """
        signal = _real(signal, "signal")
        weight = _real(weight, "weight")
        if weight < 0.0:
            raise ValueError(f"weight must not be negative, got {weight!r}")
        signal = min(max(signal, 0.0), 1.0)
        self.alpha += weight * signal
        self.beta += weight * (1.0 - signal)
        self.history.append(signal)

    @property
    def estimate(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def confidence(self) -> float:
        """Shrinks toward 0 when the belief is still wide (little evidence)."""
        n = self.alpha + self.beta
        return 1.0 - (1.0 / n)


def _is_real(value: object) -> bool:
    """True only for a real, finite number. Used where a refusal is a value."""
    return (not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(value))


def kelly_fraction(edge_prob: float, price: float, cap: float = 0.05) -> float:
    """Risk-capped Kelly sizing for a binary market priced in [0, 1].

    Returns the fraction of bankroll to stake. Never exceeds `cap` (default 5%)
    so no single position can dominate the book. Returns 0 when there is no edge.

    Everything is refused by staking nothing rather than by raising, because
    this is the sizing step and a refusal here has an obvious safe answer.
    Three refusals were missing:

    * a probability outside [0, 1]. `kelly_fraction(5.0, 0.5)` and
      `kelly_fraction(float('inf'), 0.5)` both returned the full cap, so a
      corrupt probability produced the largest bet the function can make
      rather than no bet at all.
    * a non-finite price, which made every comparison below False.
    * a cap that is not a real finite number. `min(raw, float('nan'))` returns
      `raw`, so a NaN cap silently removed the risk cap entirely, which is the
      one thing this function exists to guarantee.
    """
    if not _is_real(cap) or not 0.0 <= cap:
        return 0.0
    if not _is_real(edge_prob) or not 0.0 <= edge_prob <= 1.0:
        return 0.0
    if not _is_real(price) or not 0.0 < price < 1.0:
        return 0.0
    b = (1.0 - price) / price           # net odds if the outcome resolves YES
    q = 1.0 - edge_prob
    raw = (b * edge_prob - q) / b        # classic Kelly
    return max(0.0, min(raw, cap))       # clamp: no shorting, respect the cap


def decide(estimator: AdaptiveEstimator, market_price: float,
           min_edge: float = 0.04, min_confidence: float = 0.6) -> dict:
    """Turn the current belief into an actionable, explainable decision.

    The unreadable cases hold and say which one they are, so that a hold
    forced by a broken input is never reported as a hold on thin edge. A
    threshold comparison against NaN is False in both directions, so a gate
    written only as `confidence < min_confidence or abs(edge) < min_edge`
    fails OPEN on exactly the inputs it should refuse hardest.
    """
    for name, value in (("market price", market_price), ("min edge", min_edge),
                        ("min confidence", min_confidence)):
        if not _is_real(value):
            return {"action": "hold", "edge": None,
                    "reason": f"{name} is not a usable number"}
    if not 0.0 <= market_price <= 1.0:
        return {"action": "hold", "edge": None,
                "reason": "market price is outside [0, 1]"}
    fair = estimator.estimate
    confidence = estimator.confidence
    if not _is_real(fair) or not _is_real(confidence):
        return {"action": "hold", "edge": None,
                "reason": "the belief is not a usable number"}
    edge = fair - market_price
    if confidence < min_confidence or abs(edge) < min_edge:
        return {"action": "hold", "edge": round(edge, 4), "reason": "insufficient edge or confidence"}

    side = "buy_yes" if edge > 0 else "buy_no"
    price = market_price if edge > 0 else 1.0 - market_price
    size = kelly_fraction(fair if edge > 0 else 1.0 - fair, price)
    return {
        "action": side,
        "fair_value": round(fair, 4),
        "market_price": market_price,
        "edge": round(edge, 4),
        "stake_fraction": round(size, 4),
        # The confidence that was gated, not a fresh reading of the
        # estimator. `confidence` is a property, so asking twice runs the
        # estimator's own code twice, and an estimator whose second answer
        # differed from its first published 0.010 under a floor of 0.600,
        # with a stake attached. The same rule as
        # `ai_security/llm_output_validator`: the number that was graded
        # is the number that is published.
        "confidence": round(confidence, 3),
    }


if __name__ == "__main__":
    # Synthetic demo: five noisy signals leaning YES, market lagging at 0.55.
    est = AdaptiveEstimator()
    for s in (0.72, 0.68, 0.81, 0.6, 0.77):
        est.update(s, weight=1.0)

    print("learned fair value:", round(est.estimate, 3))
    print("decision:", decide(est, market_price=0.55))
