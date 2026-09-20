"""Represent metric results with explicit measurement and applicability states.

read_state() checks applicability before reading the metric store and returns
a state with its measurement or error. render() preserves four distinctions:

  NOT_MEASURED   The read failed; the result is unknown.
  MEASURED_NONE  The read completed with no rows in scope.
  MEASURED       The read completed with k of N rows.
  NOT_AVAILABLE The metric does not apply to the subject.

The naive renderer is retained as a comparison: it displays the same zero for
an empty result and a failed read. This synthetic store illustrates the state
contract; the production reporting vocabulary is broader.
"""

import enum
from dataclasses import dataclass


class State(enum.Enum):
    """The four words. Nothing outside this set may reach a renderer."""

    NOT_MEASURED = "not_measured"
    MEASURED_NONE = "measured_none"
    MEASURED = "measured"
    NOT_AVAILABLE = "not_available"


class ReadFailure(Exception):
    """Raised by the store when a read cannot complete."""


@dataclass(frozen=True)
class Reading:
    """A measurement that carries its own epistemic status."""

    state: State
    hits: int = 0
    total: int = 0
    detail: str = ""


class MetricStore:
    """A stand-in backend. Some keys hold rows, some keys are unreadable."""

    def __init__(self, rows: dict[str, list[int]], unreadable: set[str]) -> None:
        self._rows = rows
        self._unreadable = unreadable

    def read(self, key: str) -> list[int]:
        if key in self._unreadable:
            raise ReadFailure(f"backend refused the read for {key!r}")
        return self._rows[key]


def read_state(store: MetricStore, key: str, applicable: set[str]) -> Reading:
    """Return the honest state of one metric. Never guesses, never defaults.

    Order matters. Applicability is decided before the read is attempted,
    because "this subject has no such metric" is a fact you already know and
    must not be discovered as a read failure.

    Every way the read can fail is NOT_MEASURED, and every way means every way.
    This caught `(ReadFailure, KeyError)`, which is the two the stand-in store
    in this file raises, and a real adapter raises neither: a socket read
    raises `OSError`, a cursor past its deadline raises `TimeoutError`, a
    driver handed a bad key raises `TypeError`. Each of those left this
    function as an exception, and the caller that has to catch it writes
    `except Exception: rows = []`, which is `render_naive` below, printing
    "MEASURED, NONE   0 of 0 rows" over a read that never completed. The one
    outcome this module exists to prevent was reachable through the one arm it
    did not cover. The sibling modules already screen the whole surface:
    `ai_security/eval_harness.evaluate` catches `Exception` around the agent,
    `ai_security/differential_consistency._project` around both the decision
    and the projection, and `ai_security/llm_output_validator.validate_tool_call`
    around the validator, each on the same argument.

    An unreadable applicability set is refused the same way rather than being
    read as "the metric does not apply", which would print NOT AVAILABLE for a
    metric nobody had decided about.
    """
    try:
        known = key in applicable
    except TypeError:
        return Reading(State.NOT_MEASURED,
                       detail="the applicable set could not be read, so it is "
                              "not known whether this metric applies")
    if not known:
        return Reading(State.NOT_AVAILABLE, detail="metric does not apply here")
    try:
        rows = store.read(key)
    except Exception as exc:
        return Reading(State.NOT_MEASURED,
                       detail="%s: %s" % (type(exc).__name__, exc))
    if rows is None:
        # A store that answers `None` has not answered zero rows. Most adapters
        # return `None` for a query that did not complete, and `not rows` reads
        # the two the same way.
        return Reading(State.NOT_MEASURED,
                       detail="the store returned no result at all, which is "
                              "not a result of zero rows")
    try:
        counted = list(rows)
    except TypeError:
        return Reading(State.NOT_MEASURED,
                       detail="the store returned something that is not rows")
    if not counted:
        return Reading(State.MEASURED_NONE, 0, 0, detail="ran, zero rows in scope")
    try:
        hits = sum(counted)
    except TypeError:
        return Reading(State.NOT_MEASURED,
                       detail="the rows could not be counted, so nothing was "
                              "measured over them")
    return Reading(State.MEASURED, hits, len(counted), detail="ran, rows counted")


def render(label: str, reading: Reading) -> str:
    """Render each recognized state explicitly. Unknown state values fail closed and cannot appear as a successful measurement."""
    if reading.state is State.NOT_MEASURED:
        return f"{label:<16} NOT MEASURED     unknown ({reading.detail})"
    if reading.state is State.NOT_AVAILABLE:
        return f"{label:<16} NOT AVAILABLE    {reading.detail}"
    if reading.state is State.MEASURED_NONE:
        return f"{label:<16} MEASURED, NONE   0 of 0 rows ({reading.detail})"
    if reading.state is State.MEASURED:
        return f"{label:<16} MEASURED         {reading.hits} of {reading.total} rows"
    return (f"{label:<16} NOT MEASURED     unknown "
            f"(unrecognized state {reading.state!r})")


def render_naive(label: str, store: MetricStore, key: str) -> str:
    """The defect, kept here on purpose so the difference is visible."""
    try:
        rows = store.read(key)
    except Exception:
        rows = []                      # the default arm that tells the lie
    return f"{label:<16} {sum(rows)} of {len(rows)} rows"


if __name__ == "__main__":
    store = MetricStore(
        rows={"alerts": [1, 0, 1, 1], "drift": []},
        unreadable={"integrity"},
    )
    applicable = {"alerts", "drift", "integrity"}

    for key in ("alerts", "drift", "integrity", "latency"):
        print(render(key, read_state(store, key, applicable)))

    print()
    print("the same two reads through the usual default-argument renderer:")
    print(render_naive("drift", store, "drift"))
    print(render_naive("integrity", store, "integrity"))
    print("  <- identical output for 'ran and found nothing' and 'never ran'")
