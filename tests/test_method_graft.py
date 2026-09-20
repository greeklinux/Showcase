"""Tests for polymind/method_graft.py.

One claim carries the module: a measurement may never move between seats, and
the refusal is a raised error rather than a silent skip. A silent skip would
produce a plan that looks complete and quietly is not, so the tests check that
the refusal is loud, that it is recorded as an item, and that the recipient
still starts unmeasured after a successful graft.
"""

import unittest

from polymind.method_graft import (
    BASIS_METHOD,
    BASIS_REFUSED,
    BORROWED_LABEL,
    NEVER_TRANSFERABLE_KINDS,
    TRANSFERABLE_KINDS,
    UNMEASURED,
    UnearnedClaimError,
    assert_transferable,
    borrowed_prior,
    build_plan,
)


class TheTwoCategoriesDoNotOverlap(unittest.TestCase):
    def test_no_kind_is_both_transferable_and_never_transferable(self):
        self.assertEqual(TRANSFERABLE_KINDS & NEVER_TRANSFERABLE_KINDS, frozenset())

    def test_method_kinds_are_the_three_documented_procedures(self):
        self.assertEqual(sorted(TRANSFERABLE_KINDS),
                         ["factor_weights", "reasoning_rubric", "style_prior"])

    def test_measurement_kinds_are_the_three_documented_measurements(self):
        self.assertEqual(sorted(NEVER_TRANSFERABLE_KINDS),
                         ["calibration", "earned_record", "skill"])

    def test_the_kind_sets_are_frozen_so_the_policy_cannot_be_widened_in_place(self):
        with self.assertRaises(AttributeError):
            NEVER_TRANSFERABLE_KINDS.add("calibration_but_sneaky")


class TheRefusalIsAHardErrorNotASilentSkip(unittest.TestCase):
    def test_grafting_a_calibration_curve_raises(self):
        with self.assertRaises(UnearnedClaimError):
            assert_transferable("calibration")

    def test_grafting_a_skill_claim_raises(self):
        with self.assertRaises(UnearnedClaimError):
            assert_transferable("skill")

    def test_grafting_an_earned_record_raises(self):
        with self.assertRaises(UnearnedClaimError):
            assert_transferable("earned_record")

    def test_an_unknown_kind_raises_rather_than_being_waved_through(self):
        with self.assertRaises(UnearnedClaimError):
            assert_transferable("mystery_kind")

    def test_the_gate_returns_none_rather_than_a_boolean_a_caller_could_ignore(self):
        self.assertIsNone(assert_transferable("reasoning_rubric"))

    def test_the_refusal_explains_that_it_is_a_measurement_of_the_donor(self):
        with self.assertRaises(UnearnedClaimError) as caught:
            assert_transferable("calibration")
        message = str(caught.exception)
        self.assertIn("measurement", message)
        self.assertIn("donor", message)

    def test_the_error_is_a_value_error_so_a_bare_except_value_error_still_stops(self):
        with self.assertRaises(ValueError):
            assert_transferable("skill")

    def test_every_method_kind_passes_the_gate_without_raising(self):
        for kind in TRANSFERABLE_KINDS:
            self.assertIsNone(assert_transferable(kind))


class ARefusalIsAnItemNotAnOmission(unittest.TestCase):
    @staticmethod
    def _full_request():
        return [("price_discipline_rubric", "reasoning_rubric"),
                ("factor_weight_vector", "factor_weights"),
                ("opening_style_lens", "style_prior"),
                ("fitted_reliability_curve", "calibration"),
                ("validated_skill_on_row", "skill"),
                ("season_win_loss", "earned_record")]

    def test_every_requested_line_produces_an_item(self):
        plan = build_plan("donor_a", "recipient_b", self._full_request())
        self.assertEqual(len(plan["items"]), 6)

    def test_the_three_methods_transfer(self):
        plan = build_plan("donor_a", "recipient_b", self._full_request())
        self.assertEqual(sorted(plan["transferred"]),
                         ["factor_weight_vector", "opening_style_lens",
                          "price_discipline_rubric"])

    def test_the_three_measurements_are_refused_with_a_stated_reason(self):
        plan = build_plan("donor_a", "recipient_b", self._full_request())
        refused = dict(plan["refused"])
        self.assertEqual(sorted(refused),
                         ["fitted_reliability_curve", "season_win_loss",
                          "validated_skill_on_row"])
        for reason in refused.values():
            self.assertTrue(reason)

    def test_a_refused_item_is_marked_refused_rather_than_dropped(self):
        plan = build_plan("donor_a", "recipient_b",
                          [("season_win_loss", "earned_record")])
        item = plan["items"][0]
        self.assertFalse(item.transferred)
        self.assertEqual(item.basis, BASIS_REFUSED)
        self.assertEqual(plan["transferred"], [])

    def test_a_transferred_item_records_method_as_its_basis(self):
        plan = build_plan("donor_a", "recipient_b",
                          [("opening_style_lens", "style_prior")])
        self.assertEqual(plan["items"][0].basis, BASIS_METHOD)
        self.assertTrue(plan["items"][0].transferred)

    def test_an_unknown_kind_is_refused_inside_a_plan_rather_than_crashing_it(self):
        plan = build_plan("donor_a", "recipient_b", [("odd_thing", "mystery_kind")])
        self.assertEqual(plan["transferred"], [])
        self.assertEqual(len(plan["refused"]), 1)

    def test_an_empty_request_produces_an_empty_but_well_formed_plan(self):
        plan = build_plan("donor_a", "recipient_b", [])
        self.assertEqual(plan["transferred"], [])
        self.assertEqual(plan["refused"], [])
        self.assertEqual(plan["items"], [])

    def test_the_plan_names_both_seats(self):
        plan = build_plan("donor_a", "recipient_b", [])
        self.assertEqual(plan["donor"], "donor_a")
        self.assertEqual(plan["recipient"], "recipient_b")


class TheRecipientStartsUnmeasured(unittest.TestCase):
    def test_the_recipient_record_is_unmeasured_after_a_full_graft(self):
        plan = build_plan("donor_a", "recipient_b",
                          [(k, k) for k in sorted(TRANSFERABLE_KINDS)])
        self.assertEqual(plan["transferred"], sorted(TRANSFERABLE_KINDS))
        self.assertEqual(plan["recipient_record"], UNMEASURED)

    def test_the_recipient_record_is_unmeasured_even_with_nothing_requested(self):
        self.assertEqual(build_plan("d", "r", [])["recipient_record"], UNMEASURED)

    def test_the_unmeasured_marker_is_a_named_state_not_a_zero(self):
        self.assertIsInstance(UNMEASURED, str)
        self.assertIn("NOT_MEASURED", UNMEASURED)

    def test_every_item_carries_the_unmeasured_evidence_state_by_default(self):
        plan = build_plan("donor_a", "recipient_b",
                          [("opening_style_lens", "style_prior")])
        self.assertEqual(plan["items"][0].evidence_state, UNMEASURED)

    def test_an_item_is_frozen_so_a_refusal_cannot_be_flipped_afterwards(self):
        plan = build_plan("donor_a", "recipient_b",
                          [("season_win_loss", "earned_record")])
        with self.assertRaises(Exception):
            plan["items"][0].transferred = True


class ABorrowedCurveStaysLabelledBorrowed(unittest.TestCase):
    @staticmethod
    def _prior():
        return borrowed_prior("donor_a", [(0.55, 0.51), (0.65, 0.63)], 214)

    def test_a_borrowed_curve_is_never_marked_earned(self):
        self.assertFalse(self._prior()["earned"])

    def test_a_borrowed_curve_carries_the_borrowed_label(self):
        self.assertEqual(self._prior()["label"], BORROWED_LABEL)
        self.assertIn("not earned", BORROWED_LABEL)

    def test_a_borrowed_curve_names_the_donor_it_came_from(self):
        self.assertEqual(self._prior()["donor"], "donor_a")

    def test_a_borrowed_curve_leaves_the_recipient_calibration_unmeasured(self):
        self.assertEqual(self._prior()["recipient_calibration_state"], UNMEASURED)

    def test_a_borrowed_curve_is_barred_from_the_tables_a_reader_would_trust(self):
        barred = self._prior()["never_write_to"]
        self.assertIn("calibration_store", barred)
        self.assertIn("earned_record", barred)

    def test_a_borrowed_curve_keeps_the_sample_size_behind_it(self):
        self.assertEqual(self._prior()["settled_rows_behind_it"], 214)

    def test_the_curve_points_survive_as_named_pairs(self):
        self.assertEqual(self._prior()["curve"],
                         [{"forecast": 0.55, "observed": 0.51},
                          {"forecast": 0.65, "observed": 0.63}])

    def test_an_empty_donor_curve_is_carried_without_inventing_points(self):
        prior = borrowed_prior("donor_a", [], 0)
        self.assertEqual(prior["curve"], [])
        self.assertFalse(prior["earned"])


class AMalformedRequestStillProducesARefusal(unittest.TestCase):
    """`build_plan` promises an Item for every entry. It has to keep that.

    One entry that was a bare string, a one-element tuple or a three-element
    one raised ValueError from the unpacking and destroyed the whole plan,
    refusals included. The output of this function is the record of what was
    refused, and a record that does not exist refuses nothing.
    """

    def test_an_entry_that_is_not_a_pair_is_refused(self):
        plan = build_plan("d", "r", [("ok_key", "style_prior"), "oops"])
        self.assertEqual(plan["transferred"], ["ok_key"])
        self.assertEqual(len(plan["refused"]), 1)
        self.assertIn("not a (key, kind) pair", plan["refused"][0][1])

    def test_a_two_character_string_is_not_a_pair(self):
        # Sharpened deliberately. Without the reason assertion this test passes
        # whether or not the type is excluded: "ab" unpacks into the names "a"
        # and "b", and "b" is refused as an unknown kind, so the plan looks the
        # same from the outside and says something quite different.
        plan = build_plan("d", "r", ["ab"])
        self.assertEqual(plan["transferred"], [])
        self.assertEqual(len(plan["refused"]), 1)
        self.assertIn("not a (key, kind) pair", plan["refused"][0][1])
        self.assertNotIn("unknown graft kind", plan["refused"][0][1])

    def test_a_short_or_long_tuple_is_refused(self):
        for entry in (("only",), ("a", "b", "c"), (), 5):
            plan = build_plan("d", "r", [entry])
            self.assertEqual(plan["transferred"], [], repr(entry))
            self.assertEqual(len(plan["items"]), 1)

    def test_a_request_list_that_cannot_be_read_is_refused(self):
        for requested in (None, 5, "kinds", object()):
            plan = build_plan("d", "r", requested)
            self.assertEqual(plan["transferred"], [], repr(requested))
            self.assertEqual(len(plan["refused"]), 1)
            self.assertIn("could not be read", plan["refused"][0][1])

    def test_an_unhashable_kind_is_an_unearned_claim_not_a_type_error(self):
        with self.assertRaises(UnearnedClaimError):
            assert_transferable(["calibration"])
        with self.assertRaises(UnearnedClaimError):
            assert_transferable({"kind": "calibration"})

    def test_an_unhashable_kind_is_refused_in_a_plan(self):
        plan = build_plan("d", "r", [("k", ["calibration"])])
        self.assertEqual(plan["transferred"], [])
        self.assertIn("cannot be looked up", plan["refused"][0][1])

    def test_the_recipient_record_is_still_unmeasured_after_a_malformed_ask(self):
        self.assertEqual(build_plan("d", "r", None)["recipient_record"], UNMEASURED)


if __name__ == "__main__":
    unittest.main()
