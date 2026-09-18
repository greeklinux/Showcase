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

import unittest

from blackgate.approval_ceremony import (
    PROMPTS,
    Ack,
    STAGES,
    TERMINAL,
    AckResult,
    Ceremony,
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



if __name__ == "__main__":
    unittest.main()
