"""Summarize settled outcomes and resolve a next action through an ordered rule table.

adjudicate() accepts wins, settled rows, and pre-decision favourite hits on the
same rows. It returns a Beta posterior mean, a Wilson lower bound at the
95 percent level, the favourite hit-rate baseline, their margin, and the first
matching rule and action. Missing or invalid counts are rejected rather than
replaced with a 0.50 baseline.

The rule table is explicit data for review. The Wilson bound applies to the
seat's hit rate; this example does not compute uncertainty for the difference
between two paired rates. Production sample floors, corrections, and baseline
reconstruction are outside the module.
"""

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """One row of the ladder. Matches when BOTH floors are met."""

    name: str
    min_settled: int
    min_margin: float
    action: str


#: Ordered, first match wins. Last row is the catch-all and always matches.
RULE_TABLE: tuple[Rule, ...] = (
    Rule("clears the null with room", 40, 0.08, "MINT_AS_WARMING"),
    Rule("ahead of the null, thinly", 40, 0.00, "HOLD_AND_REMEASURE"),
    Rule("measured, nothing beat the null", 40, -1.00, "EVALUATED_NEUTRAL"),
    Rule("below the sample floor", 0, -1.00, "NOT_MEASURED_ENOUGH"),
)


def _count(value: object, name: str) -> float:
    """A count has to be a real, finite, non-negative number.

    NaN is refused here rather than by a comparison, because every comparison
    against NaN is False and a bounds check written as `0 <= x <= n` therefore
    reads a NaN as out of bounds only by accident. Infinity is refused for a
    sharper reason: `settled = float('inf')` satisfied every bound and every
    sample floor in the table at once, so a denominator that does not exist
    resolved to HOLD_AND_REMEASURE on a raw rate of 0.0.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a real number, got {value!r}")
    try:
        value = float(value)
    except OverflowError:
        # An int above the float range, `float(10 ** 400)`, raises rather than
        # returning inf, so it slips past the isfinite check below. This module
        # refuses a count it cannot use by name, and an OverflowError out of the
        # middle of it is the traceback where the refusal belongs.
        raise ValueError(f"{name} must be finite, got an int too large to represent")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    if value < 0.0:
        raise ValueError(f"{name} must not be negative, got {value!r}")
    return value


def posterior_mean(wins: int, losses: int, prior_a: float = 1.0,
                   prior_b: float = 1.0) -> float:
    """Beta posterior mean. The prior is what stops a 3-0 start reading as 1.0.

    The denominator is checked rather than assumed. posterior_mean(-1, -1)
    cancelled the Beta(1, 1) prior exactly and raised ZeroDivisionError, and
    posterior_mean(-10, 0) returned 1.125, a posterior probability above one.
    """
    wins = _count(wins, "wins")
    losses = _count(losses, "losses")
    prior_a = _count(prior_a, "prior_a")
    prior_b = _count(prior_b, "prior_b")
    denominator = prior_a + prior_b + wins + losses
    if denominator <= 0:
        raise ValueError(
            "no prior and no settled rows: a posterior needs a denominator")
    return (prior_a + wins) / denominator


def wilson_lower_bound(wins: int, settled: int, z: float = 1.96) -> float:
    """Worst plausible rate at 95 percent. Quote this, not the raw hit rate.

    The bound on `wins` lives here rather than only at `adjudicate`'s door.
    This is a public function, and called directly with more wins than settled
    rows it reached math.sqrt of a negative number and came back as
    "math domain error", which names neither the invariant nor the argument
    that broke it. A NaN `z` propagated straight through into the returned
    bound, which then rendered as a number.
    """
    settled = _count(settled, "settled")
    wins = _count(wins, "wins")
    z = _count(z, "z")
    if settled <= 0:
        raise ValueError("no settled rows: a rate needs a denominator")
    if wins > settled:
        raise ValueError(
            f"wins cannot exceed settled rows: got {wins} of {settled}")
    p = wins / settled
    denom = 1.0 + z * z / settled
    centre = p + z * z / (2 * settled)
    spread = z * math.sqrt(p * (1 - p) / settled + z * z / (4 * settled * settled))
    bound = (centre - spread) / denom
    # The Wilson interval lies inside [0, 1] analytically. In doubles it does
    # not: on a record with no wins the centre and the spread cancel to a
    # residue of the wrong sign, and wilson_lower_bound(0, 40) came back as
    # -6.33e-18, a negative probability that rounds to "-0.0" on a report.
    return min(max(bound, 0.0), 1.0)


def price_implied_null(favourite_hits: int, settled: int) -> float:
    """Calculate the price-implied null from valid counts. Hits cannot exceed settled rows."""
    settled = _count(settled, "settled")
    favourite_hits = _count(favourite_hits, "favourite_hits")
    if settled <= 0:
        raise ValueError("no settled rows: the null needs the same denominator")
    if favourite_hits > settled:
        raise ValueError(
            "favourite_hits is measured on the same rows and cannot exceed "
            f"settled: got {favourite_hits} of {settled}")
    return favourite_hits / settled


def adjudicate(wins: int, settled: int, favourite_hits: int) -> dict:
    """Score a seat and resolve it through the table. Returns the whole trace.

    The bounds below are checked rather than assumed. Without them a caller
    passing `wins` greater than `settled` reached math.sqrt of a negative
    number and got "math domain error", and a caller passing `favourite_hits`
    greater than `settled` produced a null above 1.0, which drove the margin
    below the catch-all floor of -1.00 so that NO row of the table matched.
    `matched` was then never assigned and the function raised UnboundLocalError
    from a table whose last row is documented as always matching.

    Both are rejected at the door now, with the name of the invariant in the
    message, and `matched` starts on the catch-all row so that the claim made
    about the table is true by construction rather than by argument.

    The third case was an argument that is not a count at all. A `settled` of
    float('inf') is greater than or equal to every sample floor in the table
    and greater than or equal to every `wins` at the same time, so it passed
    both bounds and every rule, and a seat with no denominator whatsoever was
    reported as "ahead of the null, thinly" with a raw rate of 0.0.
    """
    # Validated, deliberately not rebound: the trace reports `settled` back to
    # the caller, and a seat that settled 120 rows reads "120", not "120.0".
    _count(settled, "settled")
    _count(wins, "wins")
    _count(favourite_hits, "favourite_hits")
    if settled <= 0:
        raise ValueError("no settled rows: a rate needs a denominator")
    if not 0 <= wins <= settled:
        raise ValueError(
            f"wins must lie between 0 and settled: got {wins} of {settled}")
    if not 0 <= favourite_hits <= settled:
        raise ValueError(
            "favourite_hits is measured on the same rows and cannot exceed "
            f"settled: got {favourite_hits} of {settled}")
    null = price_implied_null(favourite_hits, settled)
    floor = wilson_lower_bound(wins, settled)
    margin = floor - null
    matched = RULE_TABLE[-1]          # the catch-all, by construction
    for rule in RULE_TABLE:
        if settled >= rule.min_settled and margin >= rule.min_margin:
            matched = rule
            break
    return {
        "settled": settled,
        "raw_rate": round(wins / settled, 4),
        "posterior_mean": round(posterior_mean(wins, settled - wins), 4),
        "wilson_lower_95": round(floor, 4),
        "price_implied_null": round(null, 4),
        "margin_over_null": round(margin, 4),
        "rule": matched.name,
        "action": matched.action,
    }


if __name__ == "__main__":
    print("the rule table, as data:")
    for rule in RULE_TABLE:
        print(f"  n >= {rule.min_settled:<3} margin >= {rule.min_margin:+.2f}"
              f"   {rule.action:<20} {rule.name}")

    print()
    print("A: 74 of 120, in a book where the favourite hit 73 of 120")
    a = adjudicate(wins=74, settled=120, favourite_hits=73)
    for k, v in a.items():
        print(f"  {k:<19} {v}")
    print("  vs a coin flip its lower bound looks like an edge; vs the price it is not")

    print()
    print("B: 57 of 90, in a book where the favourite hit 40 of 90")
    for k, v in adjudicate(wins=57, settled=90, favourite_hits=40).items():
        print(f"  {k:<19} {v}")

    print()
    print("C: 9 of 12, a hot start")
    for k, v in adjudicate(wins=9, settled=12, favourite_hits=5).items():
        print(f"  {k:<19} {v}")
