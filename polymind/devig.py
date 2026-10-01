"""Normalize outcome prices and compare a model probability with a quoted price.

implied_probabilities() accepts finite prices in [0, 1] with a positive total
and divides each by that total. This is proportional de-vigging for an
exhaustive outcome book. realized_edge() returns model probability minus price
paid for a binary outcome.

The normalized probabilities are an estimate under proportional margin
allocation, not known true probabilities. Despite its name, realized_edge()
computes a model-implied difference, not settled profit; fees, slippage, and
model error are outside this synthetic example.
"""

import math


def _probability(value: object, name: str) -> float:
    """Accept a real, finite number in [0, 1] and refuse everything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a real number, got {value!r}")
    try:
        value = float(value)
    except OverflowError:
        # `float(10 ** 400)` raises, so an int above the float range would slip
        # past the isfinite check below and be normalized rather than refused.
        raise ValueError(f"{name} must be finite, got an int too large to represent")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must lie in [0, 1], got {value!r}")
    return value


def implied_probabilities(prices: dict[str, float]) -> dict[str, float]:
    """Normalize outcome prices using proportional margin allocation.

    prices: outcome -> quoted price in (0, 1). For a two-way market these often
    sum to something like 1.05; that 0.05 is the vig. Normalizing by the total
    removes it proportionally (the multiplicative de-vig).

    Every price is checked, not just the total. Checking only the sum let a
    book through whose individual quotes were not probabilities at all:
    {"yes": -0.5, "no": 1.5} sums to a healthy 1.0, passed the guard
    untouched, and was returned verbatim as a de-vigged probability of minus
    50 percent and one of 150 percent. A quote of infinity divided by a total
    of infinity came back as `nan`, and a book containing one NaN made every
    outcome NaN, none of which sum to 1.0 the way the returned value claims to.
    """
    if not isinstance(prices, dict):
        raise ValueError(f"prices must be a mapping of outcome to price, "
                         f"got {type(prices).__name__}")
    for outcome, price in prices.items():
        _probability(price, f"price for {outcome!r}")
    total = sum(prices.values())
    if total <= 0:
        raise ValueError("prices must be positive")
    return {outcome: p / total for outcome, p in prices.items()}


def realized_edge(model_prob: float, price_paid: float) -> float:
    """Return model probability minus price paid, before costs; not realized profit.

    Both sides are probabilities on a binary market, so both are checked.
    Unchecked, realized_edge(5.0, -3.0) returned 8.0: an edge of 800 points on
    a market where the widest real edge is 1.0, which is the number a sizing
    step downstream would have acted on.
    """
    model_prob = _probability(model_prob, "model probability")
    price_paid = _probability(price_paid, "price paid")
    return model_prob - price_paid


if __name__ == "__main__":
    # A two-way market quoting 0.58 / 0.47. They sum to 1.05: a 5 percent vig.
    book = {"yes": 0.58, "no": 0.47}
    fair = implied_probabilities(book)
    print("raw prices      :", book)
    print("de-vigged (true):", {k: round(v, 3) for k, v in fair.items()})

    model = 0.60
    vs_belief = model - fair["yes"]                 # model minus normalized implied estimate
    realized = realized_edge(model, book["yes"])    # model-implied difference before other costs
    vig = book["yes"] - fair["yes"]                  # raw quote minus normalized estimate

    print(f"edge vs market's true belief : {vs_belief:+.3f}")
    print(f"realized edge after the vig  : {realized:+.3f}")
    print(f"the vig you paid             : {vig:+.3f}   <- the cost most people never subtract")
