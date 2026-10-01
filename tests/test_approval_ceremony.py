"""Tests for blackgate/approval_ceremony.py.

The property under test throughout is that the ceremony refuses far more often
than it applies, and that every refusal is a named outcome rather than an
exception. Four defects are pinned: a response that told the loser of a race it
had decided, an expired ceremony that could still be completed, one operator
walking all four stages, and a completion flag that outlived the thing it
described.

Deterministic: every tick is an integer supplied by the test, so there is no
clock anywhere.
"""

import decimal
import unittest

from blackgate.approval_ceremony import (
    PROMPTS,
    Ack,
    STAGES,
    TERMINAL,
    AckResult,
    Ceremony,
    identity,
)

# Every one of these renders as nothing and none of them is a format
# character, which is why a fold that tested only for category Cf let them
# through. The literals are written as escapes so that a copy of this file
# through an editor that strips invisible characters still tests what it says.
BLANK_WIDTH_SPELLINGS = (
    ("\u2800", "braille pattern blank, category So"),
    ("\u034f", "combining grapheme joiner, category Mn"),
    ("\ufe0f", "variation selector 16, category Mn"),
    ("\U000e0101", "variation selector supplement, category Mn"),
    ("\u3164", "hangul filler, category Lo, NFKC folds it onto U+1160"),
    ("\uffa0", "halfwidth hangul filler, folds onto U+1160 as well"),
    ("\u115f", "hangul choseong filler, category Lo"),
    ("\u17b4", "khmer inherent vowel aq, category Lo"),
)


def a_ceremony(**over):
    fields = dict(engagement_id="ENG-TEST", target_host="shop.example.invalid",
                  action_category="CRED_ACCESS", tool_name="config_probe",
                  opened_by="operator-a", opened_at=1000, ttl=100)
    fields.update(over)
    return Ceremony(**fields)


def walked(ceremony, first="operator-a", last="operator-b", start=1001):
    ceremony.ack("attack", first, start)
    ceremony.ack("target", first, start + 1)
    ceremony.ack("path", first, start + 2)
    ceremony.ack("execute", last, start + 3)
    return ceremony


class TheFourStagesAreAskedInOrder(unittest.TestCase):
    def test_there_are_exactly_four_stages(self):
        self.assertEqual(len(STAGES), 4)

    def test_the_order_is_action_then_host_then_route_then_release(self):
        self.assertEqual(STAGES, ("attack", "target", "path", "execute"))

    def test_every_stage_has_a_question(self):
        for stage in STAGES:
            self.assertIn(stage, PROMPTS)
            self.assertTrue(PROMPTS[stage].endswith("?") or PROMPTS[stage].endswith("."))

    def test_a_correctly_walked_ceremony_completes(self):
        ceremony = walked(a_ceremony())
        self.assertEqual(ceremony.state, "complete")

    def test_skipping_to_the_last_stage_is_refused(self):
        result = a_ceremony().ack("execute", "operator-b", 1001)
        self.assertFalse(result.applied)
        self.assertIn("out of order", result.reason)

    def test_the_refusal_names_the_stage_that_is_actually_next(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        self.assertIn("target is next", ceremony.ack("path", "operator-a", 1002).reason)

    def test_the_next_stage_is_the_first_one_nobody_holds(self):
        ceremony = a_ceremony()
        self.assertEqual(ceremony.next_stage(), "attack")
        ceremony.ack("attack", "operator-a", 1001)
        self.assertEqual(ceremony.next_stage(), "target")

    def test_a_completed_ceremony_has_no_next_stage(self):
        self.assertIsNone(walked(a_ceremony()).next_stage())

    def test_a_stage_that_is_not_a_stage_is_refused(self):
        result = a_ceremony().ack("deploy", "operator-a", 1001)
        self.assertFalse(result.applied)
        self.assertIn("not a stage", result.reason)

    def test_the_ladder_shows_who_holds_each_stage(self):
        ladder = walked(a_ceremony()).ladder()
        self.assertEqual(ladder.count("[x]"), 4)
        self.assertIn("operator-b", ladder)

    def test_an_unwalked_ladder_shows_four_empty_boxes(self):
        self.assertEqual(a_ceremony().ladder().count("[ ]"), 4)


class TheLoserOfARaceIsToldWhoActuallyDecided(unittest.TestCase):
    """The defect: the stored decision was correct and atomic, and the answer
    handed back to the losing caller reported success and named the loser as
    the decider, so every record built from it carried the wrong author."""

    def test_the_first_acknowledgement_applies(self):
        self.assertTrue(a_ceremony().ack("attack", "operator-a", 1001).applied)

    def test_the_second_acknowledgement_of_the_same_stage_does_not_apply(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        self.assertFalse(ceremony.ack("attack", "operator-b", 1001).applied)

    def test_the_loser_is_told_who_holds_the_stage(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        self.assertEqual(ceremony.ack("attack", "operator-b", 1001).decided_by, "operator-a")

    def test_the_stored_record_is_unchanged_by_the_losing_call(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("attack", "operator-b", 1001)
        self.assertEqual(ceremony.holder("attack"), "operator-a")
        self.assertEqual(len(ceremony.acks), 1)

    def test_the_winner_is_named_as_the_decider_on_its_own_result(self):
        self.assertEqual(a_ceremony().ack("attack", "operator-a", 1001).decided_by,
                         "operator-a")

    def test_a_refused_result_renders_as_refused(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        self.assertTrue(ceremony.ack("attack", "operator-b", 1001).render()
                        .startswith("REFUSED"))

    def test_an_applied_result_renders_as_applied(self):
        self.assertTrue(a_ceremony().ack("attack", "operator-a", 1001).render()
                        .startswith("APPLIED"))

    def test_the_result_is_a_plain_record_with_an_explicit_applied_flag(self):
        self.assertFalse(AckResult(False, "open", "because").applied)


class SilenceIsNotConsent(unittest.TestCase):
    def test_a_ceremony_acknowledged_after_its_window_is_refused(self):
        ceremony = a_ceremony()
        result = ceremony.ack("attack", "operator-a", 1200)
        self.assertFalse(result.applied)
        self.assertEqual(result.state, "expired")

    def test_expiry_is_checked_before_the_stage_is(self):
        # An out-of-order acknowledgement arriving late reports expiry, not
        # ordering, because the window closing is the fact that matters.
        ceremony = a_ceremony()
        self.assertEqual(ceremony.ack("execute", "operator-b", 1200).state, "expired")

    def test_a_late_final_acknowledgement_cannot_complete_a_closed_window(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        ceremony.ack("execute", "operator-b", 1200)
        self.assertNotEqual(ceremony.state, "complete")
        self.assertFalse(ceremony.may_mint(1200)[0])

    def test_expiry_is_a_state_the_ceremony_enters(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1200)
        self.assertEqual(ceremony.state, "expired")
        self.assertIn("expired", TERMINAL)

    def test_the_last_tick_inside_the_window_still_works(self):
        self.assertTrue(a_ceremony().ack("attack", "operator-a", 1100).applied)

    def test_one_tick_past_the_window_does_not(self):
        self.assertFalse(a_ceremony().ack("attack", "operator-a", 1101).applied)

    def test_the_refusal_states_the_window_it_missed(self):
        reason = a_ceremony().ack("attack", "operator-a", 1200).reason
        self.assertIn("1000", reason)
        self.assertIn("100", reason)


class TwoPersonControlIsEnforcedNotDocumented(unittest.TestCase):
    def test_the_operator_who_opened_the_run_cannot_release_it(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        result = ceremony.ack("execute", "operator-a", 1004)
        self.assertFalse(result.applied)
        self.assertIn("two-person control", result.reason)

    def test_the_opener_cannot_release_it_even_having_acknowledged_nothing(self):
        # The two halves of the rule are independent. Here the opener holds no
        # earlier stage at all, so only the opener rule can refuse this.
        ceremony = a_ceremony(opened_by="operator-z")
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        result = ceremony.ack("execute", "operator-z", 1004)
        self.assertFalse(result.applied)
        self.assertIn("opened this", result.reason)

    def test_the_operator_who_agreed_the_action_cannot_release_it(self):
        ceremony = a_ceremony(opened_by="operator-z")
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        result = ceremony.ack("execute", "operator-a", 1004)
        self.assertFalse(result.applied)
        self.assertIn("agreed the action", result.reason)

    def test_a_second_operator_can_release_it(self):
        self.assertEqual(walked(a_ceremony()).state, "complete")

    def test_the_split_only_binds_at_the_release_stage(self):
        ceremony = a_ceremony()
        self.assertTrue(ceremony.ack("attack", "operator-a", 1001).applied)
        self.assertTrue(ceremony.ack("target", "operator-a", 1002).applied)

    def test_the_rule_can_be_turned_off_for_a_single_operator_lab(self):
        ceremony = a_ceremony(two_person=False)
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        self.assertTrue(ceremony.ack("execute", "operator-a", 1004).applied)

    def test_turning_it_off_is_visible_in_the_mint_decision(self):
        ceremony = a_ceremony(two_person=False)
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        ceremony.ack("execute", "operator-a", 1004)
        self.assertTrue(ceremony.may_mint(1005)[0])


class AnAcknowledgementWithNobodyOnItIsNotOne(unittest.TestCase):
    def test_an_empty_operator_is_refused(self):
        result = a_ceremony().ack("attack", "", 1001)
        self.assertFalse(result.applied)
        self.assertIn("no operator", result.reason)

    def test_whitespace_is_not_an_operator(self):
        self.assertFalse(a_ceremony().ack("attack", "   ", 1001).applied)

    def test_a_missing_operator_is_refused(self):
        self.assertFalse(a_ceremony().ack("attack", None, 1001).applied)

    def test_an_operator_name_is_trimmed_rather_than_stored_ragged(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "  operator-a  ", 1001)
        self.assertEqual(ceremony.holder("attack"), "operator-a")


class TheMintDecisionIsRederivedEveryTime(unittest.TestCase):
    """The defect: a completion flag set once and trusted afterwards quietly
    stops being the thing that is true."""

    def test_a_completed_ceremony_may_mint(self):
        ok, reason = walked(a_ceremony()).may_mint(1005)
        self.assertTrue(ok)
        self.assertIn("2 operators", reason)

    def test_an_incomplete_ceremony_may_not_mint(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        ok, reason = ceremony.may_mint(1002)
        self.assertFalse(ok)
        self.assertIn("target", reason)

    def test_the_refusal_lists_every_stage_still_missing(self):
        _, reason = a_ceremony().may_mint(1001)
        for stage in STAGES:
            self.assertIn(stage, reason)

    def test_a_completed_ceremony_that_has_since_expired_may_not_mint(self):
        ceremony = walked(a_ceremony())
        self.assertTrue(ceremony.may_mint(1005)[0])
        self.assertFalse(ceremony.may_mint(1200)[0])

    def test_the_expiry_refusal_says_the_ceremony_expired(self):
        ceremony = walked(a_ceremony())
        self.assertIn("expired", ceremony.may_mint(1200)[1])

    def test_one_operator_across_every_stage_may_not_mint(self):
        ceremony = a_ceremony(two_person=False)
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        ceremony.ack("execute", "operator-a", 1004)
        ceremony.two_person = True
        ok, reason = ceremony.may_mint(1005)
        self.assertFalse(ok)
        self.assertIn("one operator walked every stage", reason)


class ATerminalCeremonyStaysTerminal(unittest.TestCase):
    def test_an_aborted_ceremony_refuses_every_later_stage(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.abort("operator-a", "client withdrew the window")
        result = ceremony.ack("target", "operator-a", 1002)
        self.assertFalse(result.applied)
        self.assertEqual(result.state, "aborted")

    def test_an_aborted_ceremony_may_not_mint(self):
        ceremony = walked(a_ceremony())
        ceremony.abort("operator-a")
        ok, reason = ceremony.may_mint(1005)
        self.assertFalse(ok)
        self.assertIn("aborted", reason)

    def test_a_completed_ceremony_can_still_be_aborted(self):
        # Completion is not execution. Between the last acknowledgement and the
        # approval being spent there is a window, and a control that can only
        # subtract has to be able to subtract there too.
        ceremony = walked(a_ceremony())
        self.assertTrue(ceremony.abort("operator-a", "client withdrew").applied)
        self.assertFalse(ceremony.may_mint(1005)[0])

    def test_an_expired_ceremony_cannot_be_aborted_because_it_grants_nothing(self):
        ceremony = a_ceremony()
        ceremony.ack("attack", "operator-a", 1200)
        self.assertFalse(ceremony.abort("operator-a").applied)

    def test_aborting_twice_applies_once(self):
        ceremony = a_ceremony()
        self.assertTrue(ceremony.abort("operator-a").applied)
        self.assertFalse(ceremony.abort("operator-a").applied)

    def test_the_abort_records_its_reason(self):
        self.assertIn("client withdrew",
                      a_ceremony().abort("operator-a", "client withdrew").reason)

    def test_a_completed_ceremony_cannot_be_acknowledged_again(self):
        ceremony = walked(a_ceremony())
        result = ceremony.ack("execute", "operator-c", 1005)
        self.assertFalse(result.applied)
        self.assertEqual(result.state, "complete")

    def test_every_terminal_state_is_one_the_ceremony_cannot_leave(self):
        self.assertEqual(set(TERMINAL), {"complete", "expired", "aborted"})


class TwoPersonControlIsNotDefeatedByRespellingOneName(unittest.TestCase):
    """The defect found by audit: the two-person rule was `actor ==
    self.opened_by` on the raw text, so one operator walked all four stages
    under any other spelling of their own name and may_mint reported it back as
    two operators. Fifteen spellings did it; these are the classes."""

    SPELLINGS = (
        "Operator-A", "OPERATOR-A", "operator-A",      # case
        "operator-a\u200b", "operator-a\u00ad",        # invisible
        "operator-a\u2060", "\u200boperator-a", "operator-a\ufeff",
        "operator-a\u202e",                            # bidi override
        "ope\uff52ator-a",                             # fullwidth
        "operator\u2010a",                             # Unicode hyphen
        "operator-a.", " operator-a ",                 # punctuation, spacing
    )

    def walk_with(self, releaser):
        ceremony = a_ceremony(opened_by="operator-a")
        ceremony.ack("attack", "operator-a", 1001)
        ceremony.ack("target", "operator-a", 1002)
        ceremony.ack("path", "operator-a", 1003)
        return ceremony, ceremony.ack("execute", releaser, 1004)

    def test_no_respelling_of_the_opener_can_release_the_run(self):
        for spelling in self.SPELLINGS:
            ceremony, result = self.walk_with(spelling)
            self.assertFalse(result.applied, repr(spelling))
            self.assertIn("two-person control", result.reason, repr(spelling))
            self.assertFalse(ceremony.may_mint(1005)[0], repr(spelling))

    def test_a_genuinely_different_operator_still_releases_the_run(self):
        ceremony, result = self.walk_with("operator-b")
        self.assertTrue(result.applied)
        self.assertEqual(ceremony.state, "complete")
        self.assertTrue(ceremony.may_mint(1005)[0])

    def test_may_mint_counts_operators_by_identity_not_by_spelling(self):
        ceremony = a_ceremony(two_person=False, opened_by="operator-z")
        ceremony.acks = [Ack("attack", "operator-a", 1001),
                         Ack("target", "Operator-A", 1002),
                         Ack("path", "operator-a\u200b", 1003),
                         Ack("execute", "OPERATOR-A", 1004)]
        ok, why = ceremony.may_mint(1005)
        self.assertTrue(ok)
        self.assertIn("by 1 operators", why)

    def test_a_name_in_two_alphabets_at_once_is_refused(self):
        # A Cyrillic a in place of the ASCII one is not foldable by any
        # normalization, so the mixed-script name is refused outright.
        result = a_ceremony().ack("attack", "oper\u0430tor-a", 1001)
        self.assertFalse(result.applied)
        self.assertIn("more than one alphabet", result.reason)

    def test_an_ordinary_name_in_one_alphabet_is_not_refused(self):
        for name in ("operator-a", "jos\u00e9", "\u043e\u043f\u0435\u0440\u0430\u0442\u043e\u0440"):
            self.assertTrue(a_ceremony().ack("attack", name, 1001).applied, name)

    def test_a_name_made_only_of_invisible_characters_is_no_operator(self):
        result = a_ceremony().ack("attack", "\u200b\u200c\u2060", 1001)
        self.assertFalse(result.applied)
        self.assertIn("no operator", result.reason)

    def test_an_actor_that_is_not_a_string_is_no_operator(self):
        for actor in (b"op", 1, True, 0, [], {}):
            result = a_ceremony().ack("attack", actor, 1001)
            self.assertFalse(result.applied, repr(actor))
            self.assertIn("no operator", result.reason, repr(actor))


class NoInputMakesTheCeremonyRaiseInsteadOfRefusing(unittest.TestCase):
    def test_a_tick_that_is_not_a_number_refuses(self):
        for now in (None, "1001", [], b"1001"):
            result = a_ceremony().ack("attack", "operator-a", now)
            self.assertFalse(result.applied, repr(now))
            self.assertIn("could not be evaluated", result.reason, repr(now))

    def test_a_ttl_that_is_not_a_number_refuses(self):
        result = a_ceremony(ttl=None).ack("attack", "operator-a", 1001)
        self.assertFalse(result.applied)

    def test_may_mint_over_a_tick_it_cannot_evaluate_is_a_refusal(self):
        ceremony = walked(a_ceremony())
        ok, why = ceremony.may_mint("later")
        self.assertFalse(ok)
        self.assertIn("could not be evaluated", why)


class MayMintHonoursTheRecordedStateAsWellAsTheClock(unittest.TestCase):
    """The defect found by audit: may_mint checked `expired_at(now)` and never
    the recorded state, so a ceremony that had already entered the expired
    state minted against a stale tick supplied by the caller."""

    def test_a_ceremony_recorded_as_expired_does_not_mint_on_an_older_tick(self):
        ceremony = walked(a_ceremony())
        ceremony.state = "expired"
        ok, why = ceremony.may_mint(1005)
        self.assertFalse(ok)
        self.assertIn("expired", why)

    def test_an_aborted_ceremony_still_does_not_mint(self):
        ceremony = walked(a_ceremony())
        ceremony.abort("operator-c")
        self.assertFalse(ceremony.may_mint(1005)[0])

    def test_a_complete_ceremony_inside_its_window_still_mints(self):
        self.assertTrue(walked(a_ceremony()).may_mint(1005)[0])


class AnInvisibleCharacterDoesNotMakeASecondOperator(unittest.TestCase):
    """The defect: two-person control was defeated by a character with no glyph.

    `identity` stripped category Cf and nothing else, and `scripts_of` only
    looks at characters that are `isalpha`. A braille blank is So, a grapheme
    joiner and a variation selector are Mn, and none of the three is alphabetic,
    so appending one to the opener's own name produced a string that renders
    identically, compares unequal, clears the mixed-script check, and released
    the run. One person walked all four stages and `may_mint` reported two.
    """

    def test_every_blank_width_spelling_folds_onto_the_same_operator(self):
        for character, why in BLANK_WIDTH_SPELLINGS:
            with self.subTest(why=why):
                self.assertEqual(identity("operator-a" + character),
                                 identity("operator-a"))

    def test_the_opener_cannot_release_the_run_wearing_one(self):
        for character, why in BLANK_WIDTH_SPELLINGS:
            with self.subTest(why=why):
                ceremony = a_ceremony()
                ceremony.ack("attack", "operator-a", 1001)
                ceremony.ack("target", "operator-a", 1002)
                ceremony.ack("path", "operator-a", 1003)
                result = ceremony.ack("execute", "operator-a" + character, 1004)
                # Either refusal is correct and which one fires depends on the
                # character: the hangul fillers are alphabetic, so the
                # mixed-script check reaches them first, and the rest are
                # refused by two-person control once `identity` folds them.
                # What must never happen is that the stage applies.
                self.assertFalse(result.applied)
                self.assertNotEqual(ceremony.holder("execute"),
                                    "operator-a" + character)

    def test_a_ceremony_walked_that_way_does_not_mint(self):
        for character, why in BLANK_WIDTH_SPELLINGS:
            with self.subTest(why=why):
                ceremony = a_ceremony()
                ceremony.ack("attack", "operator-a", 1001)
                ceremony.ack("target", "operator-a", 1002)
                ceremony.ack("path", "operator-a", 1003)
                ceremony.ack("execute", "operator-a" + character, 1004)
                ok, why_not = ceremony.may_mint(1005)
                self.assertFalse(ok)
                self.assertIn("execute", why_not)

    def test_a_name_made_only_of_them_is_unattributable(self):
        for character, why in BLANK_WIDTH_SPELLINGS:
            with self.subTest(why=why):
                self.assertEqual(identity(character * 4), "")
                result = a_ceremony().ack("attack", character * 4, 1001)
                self.assertFalse(result.applied)
                self.assertIn("no operator", result.reason)

    def test_a_control_character_folds_away_too(self):
        self.assertEqual(identity("operator-a\x01"), identity("operator-a"))

    def test_a_private_use_character_folds_away_too(self):
        self.assertEqual(identity("operator-a\ue000"), identity("operator-a"))

    def test_two_genuinely_different_operators_are_still_two(self):
        self.assertNotEqual(identity("operator-a"), identity("operator-b"))
        ceremony = walked(a_ceremony())
        self.assertTrue(ceremony.may_mint(1005)[0])


class TheWindowIsReadInBothDirections(unittest.TestCase):
    """A window that gets wider the further back the clock goes is not a window.

    `expired_at` was `now - self.opened_at > self.ttl`. A tick before the
    opening makes that difference negative, and a negative is never above the
    ttl, so the ceremony was inside its window at every tick before it existed.
    The same record answered "ceremony expired before it completed" at tick
    2000 and "four stages acknowledged by 2 operators" at tick 500.

    `blackgate/attestation.verify` refuses the other half of this by name,
    "issued in the future", and for the same reason: a freshness check against
    a clock that disagrees is not a freshness check. The two files hold one
    window between them and only one of them was reading it in both directions.
    """

    def walked(self):
        ceremony = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000, ttl=100)
        for stage in ("attack", "target", "path"):
            ceremony.ack(stage, "operator-a", 1001)
        ceremony.ack("execute", "operator-b", 1002)
        return ceremony

    def test_a_tick_before_the_opening_does_not_mint(self):
        ceremony = self.walked()
        self.assertFalse(ceremony.may_mint(500)[0])
        self.assertIn("precedes the opening", ceremony.may_mint(500)[1])

    def test_a_tick_before_the_opening_cannot_revive_an_expired_ceremony(self):
        ceremony = self.walked()
        self.assertFalse(ceremony.may_mint(2000)[0])
        self.assertFalse(ceremony.may_mint(500)[0])
        self.assertFalse(ceremony.may_mint(-10)[0])

    def test_the_window_still_holds_inside_itself(self):
        self.assertTrue(self.walked().may_mint(1050)[0])
        self.assertTrue(self.walked().may_mint(1000)[0])
        self.assertTrue(self.walked().may_mint(1100)[0])

    def test_expired_at_is_true_in_both_directions(self):
        ceremony = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000, ttl=100)
        self.assertTrue(ceremony.expired_at(999))
        self.assertTrue(ceremony.expired_at(1101))
        self.assertFalse(ceremony.expired_at(1000))
        self.assertFalse(ceremony.expired_at(1100))

    def test_an_acknowledgement_before_the_opening_is_refused(self):
        ceremony = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000, ttl=100)
        result = ceremony.ack("attack", "operator-a", 5)
        self.assertFalse(result.applied)
        self.assertIn("precedes the opening", result.reason)

    def test_a_tick_before_the_opening_does_not_burn_the_ceremony(self):
        ceremony = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000, ttl=100)
        ceremony.ack("attack", "operator-a", 5)
        self.assertEqual(ceremony.state, "open")
        self.assertTrue(ceremony.ack("attack", "operator-a", 1001).applied)

    def test_a_tick_past_the_ttl_still_burns_it(self):
        ceremony = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000, ttl=100)
        self.assertFalse(ceremony.ack("attack", "operator-a", 2000).applied)
        self.assertEqual(ceremony.state, "expired")

    def test_a_tick_that_is_not_a_number_is_a_window_that_cannot_be_evaluated(self):
        nan = float("nan")
        ceremony = self.walked()
        self.assertFalse(ceremony.may_mint(nan)[0])
        self.assertIn("could not be evaluated", ceremony.may_mint(nan)[1])
        fresh = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000, ttl=100)
        result = fresh.ack("attack", "operator-a", nan)
        self.assertFalse(result.applied)
        self.assertIn("could not be evaluated", result.reason)
        self.assertEqual(fresh.state, "open")
        for tick in (None, "1050", object(), [1050]):
            self.assertFalse(self.walked().may_mint(tick)[0], repr(tick))


class ATickThatRefusesComparisonIsNotATime(unittest.TestCase):
    """A quiet NaN answers every comparison False; a signaling one raises.

    The window refused `float("nan")` by noticing that `elapsed != elapsed`,
    and it wrapped that in `except TypeError` so the refusal was a refusal.
    `decimal.Decimal("sNaN")` raises `decimal.InvalidOperation` on every
    comparison there is, including that one, so it went straight past a clause
    that named only `TypeError` and out of both `ack` and `may_mint`. There are
    two ways for a tick to be unevaluable and the clause named one.
    """

    def walked(self):
        ceremony = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000)
        for stage in ("attack", "target", "path"):
            ceremony.ack(stage, "operator-a", 1001)
        ceremony.ack("execute", "operator-b", 1002)
        return ceremony

    def unevaluable_ticks(self):
        return (float("nan"), decimal.Decimal("NaN"), decimal.Decimal("sNaN"))

    def test_ack_refuses_rather_than_raising(self):
        for tick in self.unevaluable_ticks():
            ceremony = Ceremony("E", "h", "CAT", "tool", "operator-a", 1000)
            result = ceremony.ack("attack", "operator-a", tick)
            self.assertFalse(result.applied, repr(tick))
            self.assertIn("could not be evaluated", result.reason)

    def test_may_mint_refuses_rather_than_raising(self):
        for tick in self.unevaluable_ticks():
            allowed, reason = self.walked().may_mint(tick)
            self.assertFalse(allowed, repr(tick))
            self.assertIn("could not be evaluated", reason)

    def test_the_window_still_opens_for_a_tick_that_is_a_time(self):
        allowed, _ = self.walked().may_mint(1050)
        self.assertTrue(allowed)


class ATickThatRefusesComparisonInAnyCurrencyIsARefusal(unittest.TestCase):
    """The clause named TypeError, then TypeError and ArithmeticError.

    Neither list terminates. A tick is an object somebody else supplied, its
    `__sub__` and its `__lt__` are code somebody else wrote, and an `int`
    subclass raising `ValueError` from `__sub__` walked straight out of the
    ceremony past both spellings. A caller that wraps this in a broad `except`
    reads the exception as whatever its fallback says.
    """

    class HostileTick(int):
        def __sub__(self, other):
            raise ValueError("no arithmetic")

        def __rsub__(self, other):
            raise ValueError("no arithmetic")

        def __lt__(self, other):
            raise ValueError("no ordering")

        def __gt__(self, other):
            raise ValueError("no ordering")

        def __eq__(self, other):
            raise ValueError("no equality")

        def __ne__(self, other):
            raise ValueError("no equality")

        def __hash__(self):
            return 0

    def fresh(self):
        return Ceremony("E", "h", "CAT", "tool", "operator-a", 1000)

    def walked(self):
        ceremony = self.fresh()
        for stage in ("attack", "target", "path"):
            ceremony.ack(stage, "operator-a", 1001)
        ceremony.ack("execute", "operator-b", 1002)
        return ceremony

    def test_ack_refuses_rather_than_raising(self):
        result = self.fresh().ack("attack", "operator-b",
                                  self.HostileTick(1001))
        self.assertFalse(result.applied)
        self.assertIn("could not be evaluated", result.reason)

    def test_may_mint_refuses_rather_than_raising(self):
        ok, reason = self.walked().may_mint(self.HostileTick(1050))
        self.assertFalse(ok)
        self.assertIn("could not be evaluated", reason)

    def test_an_ordinary_tick_still_walks_the_ceremony(self):
        ok, _ = self.walked().may_mint(1050)
        self.assertTrue(ok)


class AWindowHasARefusalOfItsOwn(unittest.TestCase):
    """`window_state` answers where a tick falls, including "nowhere"."""

    def _fresh(self):
        return Ceremony(engagement_id="ENG-TEST", target_host="h",
                        action_category="CAT", tool_name="tool",
                        opened_by="operator-a", opened_at=1000, ttl=100)

    def test_the_four_answers(self):
        ceremony = self._fresh()
        self.assertEqual(ceremony.window_state(1050), "open")
        self.assertEqual(ceremony.window_state(1200), "expired")
        self.assertEqual(ceremony.window_state(500), "before-opening")
        self.assertEqual(ceremony.window_state(float("nan")), "unevaluable")

    def test_a_tick_that_refuses_in_its_own_currency_is_unevaluable(self):
        # A signalling decimal raises `decimal.InvalidOperation` from the
        # comparison itself, which is an `ArithmeticError` and not a
        # `TypeError`. Enumerating the currencies a caller-supplied tick can
        # refuse in does not terminate, which is why the clause is `Exception`.
        self.assertEqual(self._fresh().window_state(decimal.Decimal("sNaN")),
                         "unevaluable")

    def test_an_int_subclass_that_raises_from_subtraction_is_unevaluable(self):
        class Awkward(int):
            def __rsub__(self, other):
                raise ValueError("this tick refuses to be subtracted")

            def __sub__(self, other):
                raise ValueError("this tick refuses to be subtracted")

        self.assertEqual(self._fresh().window_state(Awkward(1050)), "unevaluable")

    def test_an_unevaluable_tick_is_a_refusal_and_not_an_exception(self):
        for tick in (decimal.Decimal("sNaN"), float("nan"), "x", None):
            ceremony = self._fresh()
            result = ceremony.ack("attack", "operator-a", tick)
            self.assertFalse(result.applied)
            self.assertIn("could not be evaluated", result.reason)
            self.assertEqual(ceremony.state, "open")

    def test_may_mint_refuses_an_unevaluable_tick(self):
        ceremony = self._fresh()
        for stage, actor in (("attack", "operator-a"), ("target", "operator-a"),
                             ("path", "operator-a"), ("execute", "operator-b")):
            ceremony.ack(stage, actor, 1001)
        allowed, why = ceremony.may_mint(decimal.Decimal("sNaN"))
        self.assertFalse(allowed)
        self.assertIn("could not be evaluated", why)

    def test_the_two_valued_predicate_still_raises_rather_than_answering(self):
        with self.assertRaises(TypeError):
            self._fresh().expired_at(float("nan"))



class OneStageIsAcknowledgedOnceHoweverManyCallersArrive(unittest.TestCase):
    """`ack` read the state, the window, the holder and the two-person rule,
    and then wrote, with nothing holding the four readings and the write
    together. Two acknowledgements of one stage were both applied, and in
    some of those the operator who agreed the action also released it.

    Deterministic, the way `test_audit_chain` holds `append`: the list the
    stage holder is read out of blocks the first caller inside the critical
    section, so the second arrives exactly in the window the lock closes.
    """

    def test_a_second_caller_waits_rather_than_reading_a_half_written_stage(self):
        import threading

        ceremony = Ceremony("ENG-1", "shop.example.invalid", "RECON",
                            "port_probe", "operator-a", 1000)
        inside = threading.Event()
        release = threading.Event()

        class Gated(list):
            def __iter__(self):
                if threading.current_thread().name == "first":
                    inside.set()
                    if not release.wait(3):
                        raise AssertionError("the first caller was not released")
                return list.__iter__(self)

        ceremony.acks = Gated()
        answers = []
        guard = threading.Lock()

        def present(actor):
            applied = ceremony.ack("attack", actor, 1001).applied
            with guard:
                answers.append(applied)

        first = threading.Thread(target=present, args=("operator-a",), name="first")
        second = threading.Thread(target=present, args=("operator-b",), name="second")
        first.start()
        try:
            self.assertTrue(inside.wait(3))
            second.start()
            second.join(0.2)
            self.assertTrue(second.is_alive())
        finally:
            release.set()
            first.join(3)
            second.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(sorted(answers), [False, True])
        self.assertEqual(len([a for a in ceremony.acks if a.stage == "attack"]), 1)


class AnAbortIsNotOverwrittenByTheAcknowledgementItLandedIn(unittest.TestCase):
    """`abort`'s docstring: a control that can only subtract has to be able to
    subtract there too. `ack` ended with an unconditional
    `self.state = "complete"`, so an abort that landed inside it was erased."""

    def aborting_ceremony(self):
        ceremony = Ceremony("ENG-1", "shop.example.invalid", "RECON",
                            "port_probe", "operator-a", 1000)

        class AbortMidWindow(int):
            def __sub__(self, other):
                ceremony.abort("client", "client withdrew the window")
                return int.__sub__(self, other)

        for stage in ("attack", "target", "path"):
            ceremony.ack(stage, "operator-a", 1001)
        ceremony.ack("execute", "operator-b", AbortMidWindow(1002))
        return ceremony

    def test_the_ceremony_stays_aborted(self):
        self.assertEqual(self.aborting_ceremony().state, "aborted")

    def test_nothing_may_be_minted_for_it(self):
        allowed, reason = self.aborting_ceremony().may_mint(1005)
        self.assertFalse(allowed)
        self.assertIn("abort", reason)


class TheTickThatIsCheckedIsTheTickThatIsRecorded(unittest.TestCase):
    """`window_state` ran `now.__sub__` and the record ran `now.__int__`."""

    class TwoFacedTick(int):
        def __int__(self):
            return 999999

    def walked(self):
        ceremony = Ceremony("ENG-1", "shop.example.invalid", "RECON",
                            "port_probe", "operator-a", 1000)
        for stage in ("attack", "target", "path"):
            ceremony.ack(stage, "operator-a", 1001)
        ceremony.ack("execute", "operator-b", self.TwoFacedTick(1002))
        return ceremony

    def test_the_record_carries_the_tick_the_window_was_checked_at(self):
        recorded = [a for a in self.walked().acks if a.stage == "execute"]
        self.assertEqual([a.tick for a in recorded], [1002])

    def test_nothing_is_stamped_outside_the_ttl(self):
        ceremony = self.walked()
        for ack in ceremony.acks:
            self.assertLessEqual(ack.tick, ceremony.opened_at + ceremony.ttl)


if __name__ == "__main__":
    unittest.main()
