"""Convert recent binary forecast scores into non-negative ensemble weights.

SourceScorecard records Brier scores for forecast/outcome pairs in a bounded
window. Its weight is positive only when the mean score is below the 0.25
baseline. earned_weights() normalizes positive weights; it returns zeros when
no source has positive weight. Invalid probabilities and outcomes are rejected.

This is a simplified weighting example. Brier score measures probabilistic
forecast error; a favorable score alone does not establish calibration across
all forecast ranges or future predictive performance. Production decay and
shrinkage rules are outside this module.
"""

import math
from collections import deque
from dataclasses import dataclass, field


def brier_score(prob: float, outcome: int) -> float:
    """Lower is better. 0.0 is perfect, 0.25 is a coin flip, 1.0 is confidently wrong.

    prob: the forecast probability of the event. outcome: 1 if it happened, else 0.

    Both arguments are checked, because the range stated in that first line is
    the whole argument for calling this a proper scoring rule. Unchecked, it
    was not bounded by 1.0 at all: brier_score(5.0, 0) returned 25.0 and
    brier_score(0.5, 7) returned 42.25, which then flowed into `mean_brier`
    and read as a source of spectacularly bad skill rather than as malformed
    input. brier_score(float('nan'), 1) returned `nan`, which renders as a
    number on any page that prints a scorecard.
    """
    if isinstance(prob, bool) or not isinstance(prob, (int, float)):
        raise ValueError(f"forecast must be a real number, got {prob!r}")
    try:
        prob = float(prob)
    except OverflowError:
        # `float(10 ** 400)` raises, so an int above the float range would slip
        # past the isfinite check and be scored rather than refused by name.
        raise ValueError("forecast must be finite, got an int too large to represent")
    if not math.isfinite(prob):
        raise ValueError(f"forecast must be finite, got {prob!r}")
    if not 0.0 <= prob <= 1.0:
        raise ValueError(f"forecast must be a probability in [0, 1], got {prob!r}")
    if isinstance(outcome, bool) or not isinstance(outcome, int) or outcome not in (0, 1):
        raise ValueError(
            f"outcome must be 1 if the event happened and 0 if it did not, "
            f"got {outcome!r}")
    return (prob - outcome) ** 2


@dataclass
class SourceScorecard:
    """Tracks one model's recent calibration and turns it into an earned weight."""

    name: str
    window: int = 50
    scores: deque = field(default_factory=lambda: deque(maxlen=50))

    def __post_init__(self) -> None:
        """Make `window` the window.

        The default factory hard-coded maxlen=50, so the constructor argument
        never reached the deque and a caller asking for a five observation
        window silently got fifty. A risk parameter that is accepted, stored,
        displayed and then ignored is the same defect as a control that was
        written and never wired up: everything reads correct except the
        behaviour.
        """
        if isinstance(self.window, bool) or not isinstance(self.window, int):
            raise ValueError(
                f"window must be a whole number of observations, "
                f"got {self.window!r}")
        if self.window < 1:
            raise ValueError(
                f"window must be at least one observation, got {self.window!r}")
        if self.scores.maxlen != self.window:
            self.scores = deque(self.scores, maxlen=self.window)

    def record(self, forecast: float, outcome: int) -> None:
        self.scores.append(brier_score(forecast, outcome))

    @property
    def mean_brier(self) -> float:
        return sum(self.scores) / len(self.scores) if self.scores else 0.25

    @property
    def weight(self) -> float:
        """Convert skill into a non-negative influence weight.

        A source at coin-flip skill (0.25) earns zero weight. Better than that
        earns positive weight; worse earns zero. Nobody gets influence for free.
        """
        edge = 0.25 - self.mean_brier
        return max(0.0, edge * 4.0)          # scale 0..1 over the useful range


def earned_weights(cards: list[SourceScorecard]) -> dict[str, float]:
    """Normalize positive earned weights. Return zero weights when no source has earned influence.

    A roster that cannot be read is refused by name, the way every other
    malformed argument in this module is. It was walked directly, so a `cards`
    that arrived as `None`, which is what a registry lookup for an unknown
    vertical returns, raised TypeError here and an entry that was not a
    scorecard raised AttributeError. Both are the same shape: the caller that
    wraps this in a broad `except` and falls back to an empty mapping gets
    every source at zero weight, which is exactly the answer this function
    gives for a measured roster in which nobody has earned influence. Two
    states that have to stay apart, collapsed by a fallback the traceback
    invited.
    """
    if cards is None or isinstance(cards, (str, bytes)):
        raise ValueError(f"cards must be a sequence of scorecards, got {cards!r}")
    try:
        cards = list(cards)
    except Exception:
        raise ValueError(f"cards must be a sequence of scorecards, got {cards!r}")
    for index, card in enumerate(cards):
        if not isinstance(card, SourceScorecard):
            raise ValueError(
                f"card {index} is not a scorecard, so it has no earned weight: "
                f"got {card!r}")
    raw = {c.name: c.weight for c in cards}
    total = sum(raw.values())
    if total <= 0:
        return {name: 0.0 for name in raw}
    return {name: w / total for name, w in raw.items()}


if __name__ == "__main__":
    sharp = SourceScorecard("stats_model")
    lucky_but_loud = SourceScorecard("hype_model")
    # sharp is well calibrated; the loud one is confidently wrong.
    for outcome in (1, 1, 0, 1, 0):
        sharp.record(0.75 if outcome else 0.30, outcome)
        lucky_but_loud.record(0.95 if not outcome else 0.10, outcome)

    print("earned weights:", earned_weights([sharp, lucky_but_loud]))
    # -> the well-calibrated source keeps almost all the influence
