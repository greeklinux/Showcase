"""Exclude marked fallback rows from evidence while retaining each seat's status.

screen() checks three channels: a persisted placeholder flag, an in-flight
fallback key, and a marker in reasoning text. Any match rejects the row, and
the verdict records every matching channel. seat_report() excludes rejected
rows and unreadable outcomes from the rate calculation and reports their
counts separately.

An all-placeholder seat remains in the report as UNEARNED; a seat with no rows
is NO_ROWS. Detected placeholder counts are lower bounds because an unmarked
fallback is invisible to these checks. This example does not include the
production SQL predicate or provenance ladder.
"""

from dataclasses import dataclass

FALLBACK_MARKER = "coverage fallback"
CHANNEL_FLAG = "persisted_flag"
CHANNEL_KEY = "fallback_key"
CHANNEL_TEXT = "reasoning_marker"


@dataclass(frozen=True)
class Verdict:
    """One row's provenance, and every channel that decided it."""

    admitted: bool
    refused_by: tuple[str, ...] = ()


def _truthy(raw: object) -> bool:
    """A flag may arrive as a bool, as an integer 1, or as the string 'true'."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return raw != 0
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return False


def screen(row: dict) -> Verdict:
    """Apply all three channels. Independent, and any one of them disqualifies.

    Deliberately not a first-match return: every firing channel is collected,
    so an audit can report a row caught by two of them as caught by two.
    """
    fired = []
    if _truthy(row.get("is_placeholder")):
        fired.append(CHANNEL_FLAG)
    if _truthy(row.get("fallback_used")):
        fired.append(CHANNEL_KEY)
    if FALLBACK_MARKER in str(row.get("reasoning") or "").lower():
        fired.append(CHANNEL_TEXT)
    return Verdict(admitted=not fired, refused_by=tuple(fired))


_WON_TRUE = frozenset({"1", "t", "true", "y", "yes", "won", "win"})
_WON_FALSE = frozenset({"0", "f", "false", "n", "no", "lost", "loss"})


def _outcome(row: dict):
    """True, False, or None when the row records no outcome that can be read."""
    value = row.get("won")
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _WON_TRUE:
            return True
        if lowered in _WON_FALSE:
            return False
    return None


def seat_report(seat: str, rows: list[dict]) -> dict:
    """Report one seat honestly, whatever the screening leaves behind.

    Three outcomes, never collapsed: a rate over admitted rows, UNEARNED when
    every row was refused, and NO_ROWS when the seat placed none. A seat absent
    from the ledger entirely is absent from this report, and that absence is
    the fourth, different fact.
    """
    admitted = [r for r in rows if screen(r).admitted]
    refused = len(rows) - len(admitted)
    base = {"seat": seat, "offered": len(rows), "refused": refused,
            "counts_are_a_lower_bound": True}
    if not rows:
        return {**base, "state": "NO_ROWS", "rate": None}
    if not admitted:
        return {**base, "state": "UNEARNED", "rate": None}
    outcomes = [_outcome(r) for r in admitted]
    counted = [o for o in outcomes if o is not None]
    unreadable = len(outcomes) - len(counted)
    base = {**base, "unreadable_outcomes": unreadable}
    if not counted:
        # Rows got through screening but not one of them records a result that
        # can be read. That is not a rate of anything.
        return {**base, "state": "UNEARNED", "rate": None}
    hits = sum(1 for o in counted if o)
    return {**base, "state": "EARNED", "counted": len(counted),
            "rate": round(hits / len(counted), 3)}


if __name__ == "__main__":
    ledger = {
        "seat_north": [{"won": w, "reasoning": "factor read"} for w in
                       (1, 1, 0, 1, 1, 0, 1, 0)] +
                      [{"won": 1, "is_placeholder": 1, "reasoning": "coverage fallback"}],
        "seat_south": [{"won": w, "fallback_used": True} for w in (1, 1, 0, 1, 1, 0)],
        "seat_east": [],
    }
    for seat, rows in ledger.items():
        print(seat_report(seat, rows))

    print()
    print("naive rate for seat_south, placeholders counted:",
          round(sum(r["won"] for r in ledger["seat_south"]) / 6, 3),
          " <- a 0.667 record built entirely out of coin flips")
    print("channels that caught its rows:", screen(ledger["seat_south"][0]).refused_by)
    print("seat_west is not in the report at all, because it does not exist,")
    print("which is a different fact from seat_east having earned nothing.")
