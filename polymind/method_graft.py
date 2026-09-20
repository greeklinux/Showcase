"""Build a transfer plan that separates reusable methods from earned measurements.

build_plan() accepts donor and recipient aliases plus requested (key, kind)
pairs, returning an item for each transfer or refusal. Reasoning rubrics,
factor weights, and style priors are transferable. Calibration, skill, earned
records, and unknown kinds are refused by assert_transferable(), which raises
UnearnedClaimError. The recipient starts unmeasured.

borrowed_prior() labels a donor curve as borrowed and not earned, retaining its
provenance and prohibited destinations. These are plan metadata, not storage
enforcement. Donor ranking, persistence, and revocation are outside the example.
"""

from dataclasses import dataclass

TRANSFERABLE_KINDS = frozenset({"reasoning_rubric", "factor_weights", "style_prior"})
NEVER_TRANSFERABLE_KINDS = frozenset({"calibration", "skill", "earned_record"})

BASIS_METHOD = "method"
BASIS_REFUSED = "refused"
UNMEASURED = "UNKNOWN_NOT_MEASURED"
BORROWED_LABEL = "borrowed, not earned"


class UnearnedClaimError(ValueError):
    """Raised when something tries to move a measurement between seats."""


@dataclass(frozen=True)
class Item:
    """One line of a graft plan. A refusal is an item, not an omission."""

    key: str
    kind: str
    transferred: bool
    basis: str
    reason: str
    evidence_state: str = UNMEASURED


def assert_transferable(kind: str) -> None:
    """The one gate. Loud, because a quiet one produces a plausible lie.

    Every refusal leaves here as UnearnedClaimError, including the refusal of a
    kind that cannot be looked up at all. A kind that arrived as a list or a
    dict, which is what a JSON request body produces when a field that should
    be a string is not, raised TypeError from the membership test and skipped
    the gate's own vocabulary entirely. `ai_security/provenance_algebra.authorizes`
    and `ai_security/capability_attenuation.exercise` both wrap the same
    membership test for the same reason, and `blackgate/detection_gap.sigma_rule`
    wraps it for an unhashable log source: an unhashable key is an unknown one,
    not an exception type the caller has to have thought of.
    """
    try:
        banned = kind in NEVER_TRANSFERABLE_KINDS
        known = kind in TRANSFERABLE_KINDS
    except TypeError:
        raise UnearnedClaimError(
            f"graft kind {kind!r} cannot be looked up, so it has not been "
            "shown to be a method")
    if banned:
        raise UnearnedClaimError(
            f"kind {kind!r} may never move between seats: it is a measurement "
            "of the donor, not a method"
        )
    if not known:
        raise UnearnedClaimError(f"unknown graft kind {kind!r}")


def borrowed_prior(donor_alias: str, curve: list[tuple[float, float]],
                   settled: int) -> dict:
    """Carry the donor's curve WITHOUT letting anything read it as earned."""
    return {
        "donor": donor_alias,
        "curve": [{"forecast": f, "observed": o} for f, o in curve],
        "settled_rows_behind_it": settled,
        "label": BORROWED_LABEL,
        "earned": False,
        "recipient_calibration_state": UNMEASURED,
        "never_write_to": ["calibration_store", "earned_record"],
    }


def build_plan(donor_alias: str, recipient_alias: str,
               requested: list[tuple[str, str]]) -> dict:
    """Resolve a request into transfers and refusals. Refusals are the point.

    requested: list of (key, kind). Every entry produces an Item, so the plan
    is a complete answer to what was asked rather than a filtered one.

    That promise is only true if a malformed entry also produces an Item. It
    did not: `for key, kind in requested` unpacked every entry directly, so one
    entry that was a bare string, a one-element tuple, or a three-element one
    raised ValueError and destroyed the whole plan, refusals included. A
    request list that cannot be walked at all does the same thing one level
    up. Both come back as refusals now, because the output of this function is
    the record of what was refused and a record that does not exist refuses
    nothing.
    """
    items = []
    if requested is None or isinstance(requested, (str, bytes)):
        entries = None
    else:
        try:
            entries = list(requested)
        except TypeError:
            entries = None
    if entries is None:
        items.append(Item("<unreadable request>", "<unreadable>", False,
                          BASIS_REFUSED,
                          "the request list could not be read, so nothing in "
                          "it has been shown to be a method"))
        entries = []
    for entry in entries:
        try:
            if isinstance(entry, (str, bytes)):
                # A two character string unpacks into two one character names,
                # so the type has to be excluded before the unpacking rather
                # than caught after it.
                raise TypeError("a string is not a pair")
            key, kind = entry
        except (TypeError, ValueError):
            items.append(Item(repr(entry), "<unreadable>", False, BASIS_REFUSED,
                              "the request entry is not a (key, kind) pair, so "
                              "no kind on it has been shown to be a method"))
            continue
        try:
            assert_transferable(kind)
        except UnearnedClaimError as exc:
            items.append(Item(key, kind, False, BASIS_REFUSED, str(exc)))
            continue
        items.append(Item(key, kind, True, BASIS_METHOD,
                          "a procedure, portable by construction"))
    return {
        "donor": donor_alias,
        "recipient": recipient_alias,
        "transferred": [i.key for i in items if i.transferred],
        "refused": [(i.key, i.reason) for i in items if not i.transferred],
        "recipient_record": UNMEASURED,
        "items": items,
    }


if __name__ == "__main__":
    plan = build_plan(
        donor_alias="donor_seat_1",
        recipient_alias="recipient_seat_7",
        requested=[("price_discipline_rubric", "reasoning_rubric"),
                   ("factor_weight_vector", "factor_weights"),
                   ("opening_style_lens", "style_prior"),
                   ("fitted_reliability_curve", "calibration"),
                   ("validated_skill_on_row", "skill"),
                   ("season_win_loss", "earned_record")],
    )
    print("transferred:", plan["transferred"])
    print("recipient record after the graft:", plan["recipient_record"])
    print("refused:")
    for key, reason in plan["refused"]:
        print(f"  {key:<26} {reason}")

    print()
    print("the donor's curve still travels, but only like this:")
    prior = borrowed_prior("donor_seat_1", [(0.55, 0.51), (0.65, 0.63), (0.75, 0.66)], 214)
    for field, value in prior.items():
        print(f"  {field:<30} {value}")

    print()
    try:
        assert_transferable("calibration")
    except UnearnedClaimError as exc:
        print("a direct attempt raises rather than skipping:", exc)
