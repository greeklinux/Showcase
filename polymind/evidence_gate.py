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
# The fourth channel, and it is not a fourth detector. A row that cannot be
# read has not been shown to be anything, and a row nothing was shown about is
# not evidence. It is named so an audit can tell "refused because it is marked"
# apart from "refused because it could not be looked at", which are different
# facts about the seat.
CHANNEL_UNREADABLE = "unreadable_row"


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

    A row that is not a mapping is refused rather than raising. It took
    `row.get` straight, so a ledger carrying a JSON `null`, a bare string, or a
    row a driver handed back as `None` raised AttributeError out of the screen
    and took the whole seat report with it. The sibling scorer,
    `blackgate/detection_gap.score`, states the rule this one was missing: an
    entry that cannot be interpreted is an entry nothing was measured about,
    and it counts as unmeasured rather than leaving as a traceback.
    """
    try:
        lookup = row.get
    except AttributeError:
        return Verdict(admitted=False, refused_by=(CHANNEL_UNREADABLE,))
    try:
        lookup("is_placeholder")
    except TypeError:
        # A `.get` that is not a mapping's `.get`, which is any object that
        # happens to carry the name.
        return Verdict(admitted=False, refused_by=(CHANNEL_UNREADABLE,))
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
    """True, False, or None when the row records no outcome that can be read.

    A row that is not a mapping is one of those, not an exception. `screen`
    refuses such a row before it reaches here, so this is the second lock on
    the same door rather than the only one, and it is written because this is a
    module-level function a caller can reach directly.
    """
    try:
        value = row.get("won")
    except (AttributeError, TypeError):
        return None
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

    Four outcomes, never collapsed: a rate over admitted rows, UNEARNED when
    every row was refused, NO_ROWS when the seat placed none, and NOT_MEASURED
    when the seat's rows could not be read at all. A seat absent from the
    ledger entirely is absent from this report, and that absence is the fifth,
    different fact.

    NOT_MEASURED is the state this function was missing, and its absence is
    what made the other four unreliable. A `rows` that is not a sequence, which
    is what a failed ledger read hands back, raised TypeError from the
    comprehension below. The seat then vanished from whatever report was being
    assembled, so a seat whose rows nobody could read was indistinguishable
    from a seat that does not exist, which is the one distinction the docstring
    above promises to keep.
    """
    if rows is None or isinstance(rows, (str, bytes)):
        listed = None
    else:
        try:
            listed = list(rows)
        except TypeError:
            listed = None
    if listed is None:
        return {"seat": seat, "offered": None, "refused": None,
                "counts_are_a_lower_bound": True, "state": "NOT_MEASURED",
                "rate": None}
    rows = listed
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
