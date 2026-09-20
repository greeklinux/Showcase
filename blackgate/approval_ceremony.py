"""Track four ordered approval stages and enforce a two-person release condition.

Ceremony accepts operator acknowledgements with caller-supplied integer ticks.
AckResult distinguishes the acknowledgement that changed state from a repeated
or competing acknowledgement and names the recorded decider. Expiry is checked
before stage completion; unnamed operators are refused. The opener and the
first-stage approver cannot release the run.

may_mint rechecks the recorded acknowledgements rather than trusting a cached
completion flag. This synthetic state machine models permission to mint an
attestation; it does not supply production identity or persistence services.

Framework context: OWASP LLM03:2026 Excessive Agency (LLM06:2025), NIST AI RMF
MANAGE 2.4 for abort/expiry controls, and GOVERN 3.2 for the role split.
No MITRE technique mapping is claimed for the approval ceremony.
"""

import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional

# The four questions, in the order they are asked. Each is a separate,
# separately recorded answer, because a single "do you approve" collapses four
# different judgements into one click.
STAGES = ("attack", "target", "path", "execute")

PROMPTS = {
    "attack": "Do you agree with the action and the tool?",
    "target": "Do you agree with the host?",
    "path": "Do you agree with the route it takes to get there?",
    "execute": "Approve and run.",
}

# Terminal states. None of them can be left.
TERMINAL = ("complete", "expired", "aborted")

# Characters that render as nothing and are NOT in category Cf, so a fold that
# tests only for Cf never reaches them.
#
# This set exists because stripping only Cf was a live bypass of the one thing
# this file guarantees. A braille pattern blank is category So; a combining
# grapheme joiner and a variation selector are category Mn; none of the three
# is `isalpha`, so `scripts_of` does not see them either. Append any one of
# them to the name that opened the ceremony and the result reads on screen as
# that same name, compares unequal under `identity`, clears the mixed-script
# check, and releases the run. One person walked all four stages and
# `may_mint` answered "four stages acknowledged by 2 operators".
#
# It is the same set `ai_security/prompt_guard.py` screens for, written out
# again here rather than imported, because each file in this repository runs
# on its own. The hangul fillers are in it for the reason given there: U+3164
# and U+FFA0 both NFKC fold onto U+1160, which is itself a blank letter, so
# normalizing leaves them exactly as invisible as they started.
_BLANK_WIDTH = (
    frozenset(
        "\u034f"                # combining grapheme joiner
        "\u115f\u1160"          # hangul choseong and jungseong filler
        "\u17b4\u17b5"          # khmer inherent vowels
        "\u2800"                # braille pattern blank
        "\u3164"                # hangul filler
        "\uffa0"                # halfwidth hangul filler
    )
    | frozenset(chr(cp) for cp in range(0xFE00, 0xFE10))      # variation selectors
    | frozenset(chr(cp) for cp in range(0xE0100, 0xE01F0))    # and the supplement
)

# Categories that carry no reliable glyph: format characters, control
# characters, and private use, whose rendering depends entirely on the font.
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Cc", "Co"})


def identity(actor) -> str:
    """The comparable identity behind an operator name.

    Two-person control is a string comparison, so it is only as strong as the
    spellings it treats as the same person. It was `actor == self.opened_by` on
    the raw text, and every one of these walked all four stages as one human
    and was reported as two operators:

        'Operator-A'          the same name in a different case
        'operator-a\\u200b'    a zero width space nobody can see
        'operator-a\\u00ad'    a soft hyphen, likewise
        'oper\\u0430tor-a'     a Cyrillic a in place of the ASCII one
        'ope\\uff52ator-a'     the fullwidth r
        'operator\\u2010a'     the Unicode hyphen for the ASCII one

        'operator-a\\u2800'    a braille pattern blank, which is category So
        'operator-a\\u034f'    a combining grapheme joiner, category Mn
        'operator-a\\ufe0f'    a variation selector, likewise category Mn

    So identity is compatibility-normalized (NFKC, which folds the fullwidth
    and compatibility forms together), stripped of every character that renders
    as nothing, stripped of whitespace and trailing dots, and casefolded.
    `str.casefold` rather than `str.lower` because it is the one that folds the
    German sharp s onto `ss`.

    "Renders as nothing" is deliberately wider than category Cf. The last three
    spellings above are the reason: each of them is invisible, none of them is
    a format character, and each of them released a run that one person had
    walked end to end. See `_BLANK_WIDTH`.

    This is the comparison key only. The record keeps the name as it was typed.
    """
    if not isinstance(actor, str):
        return ""
    folded = unicodedata.normalize("NFKC", actor)
    # Pd is every dash there is, and NFKC does not fold the Unicode hyphen
    # U+2010 onto the ASCII hyphen-minus, so 'operator‐a' compared unequal to
    # 'operator-a' and counted as a second person.
    folded = "".join(
        "-" if unicodedata.category(ch) == "Pd" else ch
        for ch in folded
        if unicodedata.category(ch) not in _INVISIBLE_CATEGORIES
        and ch not in _BLANK_WIDTH)
    return folded.strip().strip(".").strip().casefold()


def scripts_of(actor) -> frozenset:
    """The alphabets the letters of a name are drawn from.

    Normalization cannot fold a Cyrillic a onto an ASCII a, because they are
    genuinely different letters that happen to be drawn the same. The signature
    of the substitution is that one word ends up written in two alphabets at
    once, which no real name is, so a mixed-script operator name is refused
    rather than quietly counted as a second person.
    """
    found = set()
    for ch in unicodedata.normalize("NFKC", actor or ""):
        if not ch.isalpha():
            continue
        try:
            found.add(unicodedata.name(ch).split()[0])
        except ValueError:
            found.add("UNNAMED")
    return frozenset(found)


@dataclass(frozen=True)
class Ack:
    stage: str
    actor: str
    tick: int


@dataclass
class AckResult:
    """The answer to one acknowledgement attempt.

    `applied` says whether this call is the one that changed the record.
    `decided_by` always names whoever actually holds the stage, which on a lost
    race is somebody else. Returning success with the caller's own name in it
    was a real defect: the stored decision was correct and atomic, and the
    answer handed back to the loser said they had made it. Every downstream
    record built from that answer then carried the wrong author.
    """
    applied: bool
    state: str
    reason: str
    stage: str = ""
    decided_by: str = ""

    def render(self) -> str:
        head = "APPLIED" if self.applied else "REFUSED"
        who = ("  held by %s" % self.decided_by) if self.decided_by else ""
        return "%-7s %-8s %-10s %s%s" % (head, self.stage or "-", self.state,
                                         self.reason, who)


@dataclass
class Ceremony:
    """One four-stage approval, bound to exactly one proposed action."""
    engagement_id: str
    target_host: str
    action_category: str
    tool_name: str
    opened_by: str
    opened_at: int
    ttl: int = 100
    two_person: bool = True
    acks: List[Ack] = field(default_factory=list)
    state: str = "open"

    def holder(self, stage: str) -> str:
        for ack in self.acks:
            if ack.stage == stage:
                return ack.actor
        return ""

    def next_stage(self) -> Optional[str]:
        for stage in STAGES:
            if not self.holder(stage):
                return stage
        return None

    def window_state(self, now) -> str:
        """Where this tick falls: open, expired, before-opening, unevaluable.

        `expired_at` is the predicate this file has always had, and a predicate
        that returns `bool` has nowhere to put a refusal. Both of its honest
        answers read as an answer, so it raises instead, and both callers in
        this file convert that into an `AckResult` or a `(False, reason)` pair
        the moment they get it. A caller outside this file gets the exception,
        and a caller that wraps it in a broad `except` reads it as whatever
        its fallback says, which is the failure every other gate here is
        written against.

        Making `expired_at` answer True on an unevaluable tick would have been
        worse than raising, not better: `ack` reads True as "past the ttl" and
        burns the ceremony, so a tick nobody could evaluate would destroy an
        approval four people were walking through. The refusal needs its own
        value, which means it needs its own function, and this is it. Four
        states, none of them collapsed into another.
        """
        opened = self.opened_at
        try:
            elapsed = now - opened
            if elapsed != elapsed:
                # NaN. It compares False against every threshold there is, so
                # `elapsed > self.ttl` and `elapsed < 0` were both False and a
                # ceremony with no evaluable window read as an open one. Every
                # numeric gate in `polymind/` refuses NaN by name and says why:
                # a bounds check written as a comparison reads a NaN as in
                # bounds by accident.
                return "unevaluable"
            if elapsed < 0:
                return "before-opening"
            if elapsed > self.ttl:
                return "expired"
        except Exception:
            # `Exception`, for the reason `ack` gives below: a tick is an
            # object somebody else supplied, its `__sub__` and its `__lt__`
            # are code somebody else wrote, and the set of currencies it can
            # refuse in is not this file's to enumerate.
            return "unevaluable"
        return "open"

    def expired_at(self, now: int) -> bool:
        """True when this tick is outside the window, in either direction.

        Two-valued, so a tick it cannot evaluate raises rather than answering.
        `window_state` above is the same question with a refusal in its range,
        and it is the one to call from anywhere that has to keep working.

        A tick before the ceremony opened was inside the window, because
        `now - opened_at` is negative and a negative is never above the ttl.
        That is a window that gets wider the further back the clock goes, and
        it un-expires a ceremony: one that answers "expired before it
        completed" at tick 2000 answered "four stages acknowledged by 2
        operators" at tick 500, on the same record, for a caller whose clock
        rolled back or who passed a stale tick.

        `blackgate/attestation.verify` already refuses this, by name, on the
        other half of the same mechanism: "issued in the future" is a separate
        refusal there precisely because a freshness check against a clock that
        disagrees is not a freshness check. The two files hold one window
        between them and only one of them was reading it in both directions.
        """
        state = self.window_state(now)
        if state == "unevaluable":
            raise TypeError("a tick of %r is not a time" % (now,))
        return state != "open"

    def abort(self, actor: str, reason: str = "aborted by operator") -> AckResult:
        # A completed ceremony is still abortable, and that asymmetry is
        # deliberate. Completion is not execution: between the last
        # acknowledgement and the attestation being spent there is a window in
        # which a client can withdraw, and a control that can only subtract has
        # to be able to subtract there too. Only the states that already
        # withhold authority are refused.
        if self.state in ("aborted", "expired"):
            return AckResult(False, self.state, "already %s" % self.state,
                             decided_by=self.opened_by)
        self.state = "aborted"
        return AckResult(True, "aborted", reason, decided_by=actor)

    def ack(self, stage: str, actor: str, now: int) -> AckResult:
        """Acknowledge one stage. Refuses far more often than it applies."""
        if not isinstance(actor, str):
            # `(actor or "").strip()` accepted b'op' as an operator and raised
            # AttributeError on an int. Neither is a person.
            return AckResult(False, self.state,
                             "acknowledgement carries no operator", stage=str(stage))
        actor = actor.strip()
        if not actor or not identity(actor):
            # An unattributable acknowledgement is not an acknowledgement. The
            # record it would produce cannot answer the only question anyone
            # asks of it later, which is who agreed to this. A name made only
            # of invisible characters is unattributable in the same way.
            return AckResult(False, self.state, "acknowledgement carries no operator",
                             stage=str(stage))

        if len(scripts_of(actor)) > 1:
            return AckResult(False, self.state,
                             "operator name is written in more than one alphabet, "
                             "which is how one person is counted as two",
                             stage=str(stage))

        if self.state in TERMINAL:
            return AckResult(False, self.state, "ceremony is %s" % self.state, stage=stage)

        # Time is checked before the stage is, so an expired ceremony cannot be
        # completed by a fast final acknowledgement. Silence is not consent: a
        # ceremony nobody finished is refused, never carried forward.
        try:
            window = self.window_state(now)
            past_window = window != "open"
        except Exception:
            # A window that cannot be evaluated has not been shown to be open,
            # and an acknowledgement is not applied into one. Raising here put
            # a TypeError where a refusal belongs.
            #
            # The clause named `TypeError`, then `TypeError` and
            # `ArithmeticError`, because a `decimal` signaling NaN raises
            # `decimal.InvalidOperation` on every comparison there is,
            # including the `elapsed != elapsed` that catches the quiet one.
            # Enumerating the ways arithmetic can refuse does not terminate: a
            # tick is an object somebody else supplied, its `__sub__` and its
            # `__lt__` are code somebody else wrote, and an `int` subclass
            # raising `ValueError` from `__sub__` walked straight out of a
            # clause that named the first two. `Exception`, for the reason
            # `args_hash` and `_listed` give for the same clause: a value
            # backed by something real refuses in its own currency, and the
            # currency is not this file's to choose.
            return AckResult(False, self.state,
                             "the ceremony window could not be evaluated at tick %r"
                             % (now,), stage=str(stage))
        if window == "unevaluable":
            return AckResult(False, self.state,
                             "the ceremony window could not be evaluated at tick %r"
                             % (now,), stage=str(stage))
        if past_window:
            # A tick before the opening is not an expiry, it is a clock that
            # cannot be read, so it does not burn the ceremony. A tick past the
            # ttl does.
            if window == "before-opening":
                return AckResult(False, self.state,
                                 "tick %s precedes the opening at %s, so the "
                                 "window could not be evaluated"
                                 % (now, self.opened_at), stage=stage)
            self.state = "expired"
            return AckResult(False, "expired",
                             "opened at %s, ttl %s, now %s" % (self.opened_at, self.ttl, now),
                             stage=stage)

        if stage not in STAGES:
            return AckResult(False, self.state, "not a stage of this ceremony", stage=str(stage))

        held = self.holder(stage)
        if held:
            # The lost race. The stored decision does not change and the caller
            # is told, by name, who actually holds it.
            return AckResult(False, self.state, "stage already acknowledged",
                             stage=stage, decided_by=held)

        expected = self.next_stage()
        if stage != expected:
            return AckResult(False, self.state,
                             "out of order, %s is next" % expected, stage=stage)

        if self.two_person and stage == "execute":
            # Two-person control, at the only stage where it bites. The person
            # who opened the run cannot be the person who releases it, and
            # neither can the person who agreed the action in the first stage.
            #
            # Compared on `identity`, not on the raw text. Fifteen spellings of
            # one operator's own name walked all four stages past the raw
            # comparison and were reported back as two operators.
            if identity(actor) == identity(self.opened_by):
                return AckResult(False, self.state,
                                 "two-person control: the operator who opened this "
                                 "cannot release it", stage=stage,
                                 decided_by=self.opened_by)
            if identity(actor) == identity(self.holder("attack")):
                return AckResult(False, self.state,
                                 "two-person control: the operator who agreed the "
                                 "action cannot release it", stage=stage,
                                 decided_by=self.holder("attack"))

        self.acks.append(Ack(stage, actor, int(now)))
        if self.next_stage() is None:
            self.state = "complete"
        return AckResult(True, self.state, PROMPTS[stage], stage=stage, decided_by=actor)

    def may_mint(self, now: int):
        """May an attestation be issued for this action right now.

        Deliberately re-derived from the recorded acknowledgements rather than
        read from a flag. A completion flag set once and trusted afterwards is
        the same shape of defect as an approval that names a tool and not its
        arguments: the thing that is checked stops being the thing that is true.
        """
        # The recorded state is consulted as well as the clock. `expired_at`
        # answers only the question the caller's `now` asks, so a ceremony that
        # had already entered the expired state minted against a stale tick.
        if self.state == "aborted":
            return False, "ceremony was aborted"
        if self.state == "expired":
            return False, "ceremony expired before it completed"
        try:
            window = self.window_state(now)
            if window == "unevaluable":
                return False, ("the ceremony window could not be evaluated at "
                               "tick %r" % (now,))
            if window == "before-opening":
                return False, ("tick %r precedes the opening at %r, so the "
                               "window could not be evaluated"
                               % (now, self.opened_at))
            if window == "expired":
                return False, "ceremony expired before it completed"
        except Exception:
            # A window that cannot be evaluated has not been shown to be open.
            # `Exception` for the reason given in `ack`: a signaling NaN
            # refuses the comparison itself rather than answering it, and the
            # set of ways a caller-supplied tick can refuse a comparison is
            # not one this file gets to enumerate.
            return False, "the ceremony window could not be evaluated at tick %r" % (now,)
        missing = [s for s in STAGES if not self.holder(s)]
        if missing:
            return False, "stages not acknowledged: %s" % ", ".join(missing)
        # Counted on identity, for the reason in `identity`: a set of raw
        # strings counts 'operator-a' and 'Operator-A' as two people.
        actors = {identity(ack.actor) for ack in self.acks}
        if self.two_person and len(actors) < 2:
            return False, "two-person control: one operator walked every stage"
        return True, "four stages acknowledged by %d operators" % len(actors)

    def ladder(self) -> str:
        rows = []
        for stage in STAGES:
            held = self.holder(stage)
            mark = "[x]" if held else "[ ]"
            rows.append("  %s %-8s %-50s %s" % (mark, stage, PROMPTS[stage], held or "-"))
        return "\n".join(rows)


if __name__ == "__main__":
    def fresh():
        return Ceremony(engagement_id="ENG-2026-014", target_host="shop.example.invalid",
                        action_category="CRED_ACCESS", tool_name="config_probe",
                        opened_by="operator-a", opened_at=1000, ttl=100)

    print("a ceremony walked correctly")
    c = fresh()
    print(c.ack("attack", "operator-a", 1001).render())
    print(c.ack("target", "operator-a", 1002).render())
    print(c.ack("path", "operator-a", 1003).render())
    print(c.ack("execute", "operator-b", 1004).render())
    print(c.ladder())
    print("  may mint: %s" % (c.may_mint(1005),))
    print()

    print("the refusals, one ceremony each")
    c = fresh()
    print(c.ack("execute", "operator-b", 1001).render(), " # skipping to the end")
    print(c.ack("attack", "", 1001).render(), " # nobody signed it")

    c = fresh()
    c.ack("attack", "operator-a", 1001)
    print(c.ack("path", "operator-a", 1002).render(), " # out of order")

    c = fresh()
    c.ack("attack", "operator-a", 1001)
    c.ack("target", "operator-a", 1002)
    c.ack("path", "operator-a", 1003)
    print(c.ack("execute", "operator-a", 1004).render(), " # one person, every stage")
    print("  may mint: %s" % (c.may_mint(1004),))

    c = fresh()
    c.ack("attack", "operator-a", 1001)
    c.ack("target", "operator-a", 1002)
    c.ack("path", "operator-a", 1003)
    print(c.ack("execute", "operator-b", 1200).render(), " # nobody came back in time")
    print("  may mint: %s" % (c.may_mint(1200),))
    print()

    print("two operators acknowledge the same stage")
    c = fresh()
    first = c.ack("attack", "operator-a", 1001)
    second = c.ack("attack", "operator-b", 1001)
    print("  first : %s" % first.render())
    print("  second: %s" % second.render())
    print("  the record says the stage is held by: %s" % c.holder("attack"))
    print()

    print("an aborted ceremony cannot be resumed")
    c = fresh()
    c.ack("attack", "operator-a", 1001)
    print(c.abort("operator-a", "client withdrew the window").render())
    print(c.ack("target", "operator-a", 1002).render())
    print("  may mint: %s" % (c.may_mint(1002),))
