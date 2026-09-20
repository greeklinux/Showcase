"""Tests for polymind/evidence_gate.py.

The gate exists because a placeholder row that reaches the arithmetic
manufactures a record out of coin flips. Three independent channels have to
refuse a row, every firing channel has to be recorded, and a seat whose rows
were all refused has to keep its row in the report rather than vanish from it.
"""

import unittest

from polymind.evidence_gate import (
    CHANNEL_FLAG,
    CHANNEL_KEY,
    CHANNEL_TEXT,
    CHANNEL_UNREADABLE,
    FALLBACK_MARKER,
    screen,
    seat_report,
)


class AnHonestRowIsAdmitted(unittest.TestCase):
    def test_a_row_with_no_placeholder_signal_is_admitted(self):
        verdict = screen({"won": 1, "reasoning": "factor read"})
        self.assertTrue(verdict.admitted)
        self.assertEqual(verdict.refused_by, ())

    def test_a_row_with_no_fields_at_all_is_admitted(self):
        self.assertTrue(screen({}).admitted)

    def test_an_explicitly_false_flag_does_not_refuse_the_row(self):
        self.assertTrue(screen({"is_placeholder": False}).admitted)
        self.assertTrue(screen({"is_placeholder": 0}).admitted)
        self.assertTrue(screen({"is_placeholder": "false"}).admitted)
        self.assertTrue(screen({"is_placeholder": "no"}).admitted)

    def test_a_none_reasoning_field_does_not_refuse_the_row(self):
        self.assertTrue(screen({"reasoning": None}).admitted)


class EachChannelRefusesOnItsOwn(unittest.TestCase):
    def test_the_persisted_flag_alone_refuses_the_row(self):
        verdict = screen({"is_placeholder": True})
        self.assertFalse(verdict.admitted)
        self.assertEqual(verdict.refused_by, (CHANNEL_FLAG,))

    def test_the_in_flight_fallback_key_alone_refuses_the_row(self):
        verdict = screen({"fallback_used": True})
        self.assertFalse(verdict.admitted)
        self.assertEqual(verdict.refused_by, (CHANNEL_KEY,))

    def test_the_reasoning_marker_alone_refuses_the_row(self):
        verdict = screen({"reasoning": "coverage fallback engaged"})
        self.assertFalse(verdict.admitted)
        self.assertEqual(verdict.refused_by, (CHANNEL_TEXT,))

    def test_the_reasoning_marker_is_matched_case_insensitively(self):
        self.assertFalse(screen({"reasoning": "COVERAGE FALLBACK"}).admitted)
        self.assertFalse(screen({"reasoning": "Coverage Fallback"}).admitted)

    def test_the_marker_is_found_anywhere_in_the_reasoning_text(self):
        self.assertFalse(
            screen({"reasoning": "no provider answer, used the %s path"
                                 % FALLBACK_MARKER}).admitted
        )

    def test_a_flag_stored_as_an_integer_one_still_refuses(self):
        self.assertFalse(screen({"is_placeholder": 1}).admitted)

    def test_a_flag_stored_as_a_string_still_refuses(self):
        for raw in ("1", "true", "TRUE", " yes ", "on"):
            self.assertFalse(screen({"is_placeholder": raw}).admitted, raw)

    def test_a_flag_of_an_unexpected_type_is_treated_as_absent_not_as_true(self):
        self.assertTrue(screen({"is_placeholder": ["maybe"]}).admitted)


class EveryFiringChannelIsRecorded(unittest.TestCase):
    def test_two_firing_channels_are_both_reported(self):
        verdict = screen({"is_placeholder": True, "fallback_used": True})
        self.assertEqual(verdict.refused_by, (CHANNEL_FLAG, CHANNEL_KEY))

    def test_all_three_firing_channels_are_reported_in_order(self):
        verdict = screen({"is_placeholder": True, "fallback_used": 1,
                          "reasoning": FALLBACK_MARKER})
        self.assertEqual(verdict.refused_by,
                         (CHANNEL_FLAG, CHANNEL_KEY, CHANNEL_TEXT))

    def test_the_channels_are_three_distinct_names(self):
        self.assertEqual(len({CHANNEL_FLAG, CHANNEL_KEY, CHANNEL_TEXT}), 3)

    def test_screening_is_not_a_first_match_return(self):
        verdict = screen({"is_placeholder": True, "reasoning": FALLBACK_MARKER})
        self.assertEqual(len(verdict.refused_by), 2)


class ASeatIsReportedWhateverScreeningLeaves(unittest.TestCase):
    def test_a_seat_with_only_honest_rows_reports_a_rate(self):
        rows = [{"won": w, "reasoning": "factor read"} for w in (1, 1, 0, 1)]
        report = seat_report("seat_north", rows)
        self.assertEqual(report["state"], "EARNED")
        self.assertEqual(report["rate"], 0.75)
        self.assertEqual(report["counted"], 4)
        self.assertEqual(report["refused"], 0)

    def test_placeholder_rows_are_excluded_from_the_arithmetic(self):
        rows = ([{"won": 1, "reasoning": "factor read"}] * 2
                + [{"won": 1, "is_placeholder": True}] * 6)
        report = seat_report("seat_north", rows)
        self.assertEqual(report["counted"], 2)
        self.assertEqual(report["refused"], 6)
        self.assertEqual(report["rate"], 1.0)

    def test_a_seat_whose_rows_were_all_refused_reports_unearned(self):
        rows = [{"won": w, "fallback_used": True} for w in (1, 1, 0, 1, 1, 0)]
        report = seat_report("seat_south", rows)
        self.assertEqual(report["state"], "UNEARNED")
        self.assertIsNone(report["rate"])

    def test_an_unearned_seat_keeps_its_row_rather_than_being_dropped(self):
        report = seat_report("seat_south", [{"won": 1, "fallback_used": True}])
        self.assertEqual(report["seat"], "seat_south")
        self.assertEqual(report["offered"], 1)
        self.assertEqual(report["refused"], 1)

    def test_an_unearned_seat_reports_none_rather_than_a_rate_of_zero(self):
        report = seat_report("seat_south", [{"won": 1, "fallback_used": True}])
        self.assertIsNone(report["rate"])
        self.assertNotEqual(report["rate"], 0.0)

    def test_a_seat_that_placed_no_rows_reports_no_rows_not_unearned(self):
        report = seat_report("seat_east", [])
        self.assertEqual(report["state"], "NO_ROWS")
        self.assertIsNone(report["rate"])
        self.assertEqual(report["offered"], 0)

    def test_the_three_outcomes_are_never_collapsed_into_one_another(self):
        no_rows = seat_report("a", [])["state"]
        unearned = seat_report("b", [{"won": 1, "is_placeholder": True}])["state"]
        earned = seat_report("c", [{"won": 1}])["state"]
        self.assertEqual(len({no_rows, unearned, earned}), 3)

    def test_every_report_declares_its_counts_are_a_lower_bound(self):
        for rows in ([], [{"won": 1}], [{"won": 1, "is_placeholder": True}]):
            self.assertTrue(seat_report("s", rows)["counts_are_a_lower_bound"])

    def test_offered_always_equals_counted_plus_refused_when_anything_counted(self):
        rows = [{"won": 1}, {"won": 0}, {"won": 1, "fallback_used": True}]
        report = seat_report("s", rows)
        self.assertEqual(report["offered"], report["counted"] + report["refused"])

    def test_a_rate_is_rounded_to_three_places(self):
        rows = [{"won": 1}, {"won": 1}, {"won": 0}]
        self.assertEqual(seat_report("s", rows)["rate"], 0.667)

    def test_the_naive_rate_over_unscreened_rows_is_the_number_the_gate_prevents(self):
        """A seat of pure placeholders reads as a 0.667 record without the gate."""
        rows = [{"won": w, "fallback_used": True} for w in (1, 1, 0, 1, 1, 0)]
        naive = round(sum(r["won"] for r in rows) / len(rows), 3)
        self.assertEqual(naive, 0.667)
        self.assertIsNone(seat_report("seat_south", rows)["rate"])


class AWinIsReadNotGuessedAtByTruthiness(unittest.TestCase):
    """Behavioral checks for a win is read not guessed at by truthiness."""

    def test_text_column_zeros_are_losses_not_wins(self):
        report = seat_report("s", [{"won": "0"}, {"won": "0"}])
        self.assertEqual(report["rate"], 0.0)

    def test_text_column_ones_and_zeros_score_correctly(self):
        rows = [{"won": "1"}, {"won": "0"}, {"won": "1"}, {"won": "0"}]
        self.assertEqual(seat_report("s", rows)["rate"], 0.5)

    def test_the_other_text_spellings_are_read_too(self):
        for won, expected in (("true", 1.0), ("false", 0.0),
                              ("yes", 1.0), ("no", 0.0),
                              ("T", 1.0), ("f", 0.0)):
            with self.subTest(won=won):
                self.assertEqual(seat_report("s", [{"won": won}])["rate"], expected)

    def test_a_row_missing_the_outcome_does_not_raise(self):
        report = seat_report("s", [{"reasoning": "factor read"}])
        self.assertEqual(report["unreadable_outcomes"], 1)

    def test_an_unreadable_outcome_is_neither_a_win_nor_a_loss(self):
        rows = [{"won": 1}, {"won": 0}, {"reasoning": "no outcome"}]
        report = seat_report("s", rows)
        self.assertEqual(report["counted"], 2)
        self.assertEqual(report["rate"], 0.5)
        self.assertEqual(report["unreadable_outcomes"], 1)

    def test_a_value_that_is_neither_true_nor_false_is_not_counted(self):
        for won in (0.0001, 2, -1, [], {}, "maybe"):
            with self.subTest(won=repr(won)):
                report = seat_report("s", [{"won": won}])
                self.assertIsNone(report["rate"])
                self.assertEqual(report["state"], "UNEARNED")

    def test_a_seat_with_no_readable_outcome_at_all_is_unearned(self):
        rows = [{"reasoning": "a"}, {"reasoning": "b"}]
        self.assertEqual(seat_report("s", rows)["state"], "UNEARNED")

    def test_ordinary_integer_and_boolean_rows_are_unaffected(self):
        ints = seat_report("s", [{"won": 1}, {"won": 1}, {"won": 0}, {"won": 1}])
        bools = seat_report("s", [{"won": True}, {"won": True},
                                  {"won": False}, {"won": True}])
        self.assertEqual(ints["rate"], 0.75)
        self.assertEqual(bools["rate"], 0.75)


class ARowThatCannotBeReadIsRefused(unittest.TestCase):
    """The rule `blackgate/detection_gap.score` states, applied here.

    An entry that cannot be interpreted is an entry nothing was measured
    about. `screen` took `row.get` straight, so a ledger carrying a JSON null
    or a row a driver handed back as `None` raised AttributeError and took the
    whole seat report with it: a seat whose rows nobody could read was
    indistinguishable from a seat that does not exist.
    """

    def test_a_row_that_is_not_a_mapping_is_refused_not_raised(self):
        for row in (None, "row", 5, ["won"], object(), 3.5):
            verdict = screen(row)
            self.assertFalse(verdict.admitted, repr(row))
            self.assertEqual(verdict.refused_by, (CHANNEL_UNREADABLE,))

    def test_an_unreadable_row_does_not_destroy_the_seat_report(self):
        report = seat_report("seat_north", [{"won": 1}, None, {"won": 0}])
        self.assertEqual(report["state"], "EARNED")
        self.assertEqual(report["offered"], 3)
        self.assertEqual(report["refused"], 1)
        self.assertEqual(report["counted"], 2)

    def test_a_seat_of_nothing_but_unreadable_rows_is_unearned(self):
        report = seat_report("seat_north", [None, None])
        self.assertEqual(report["state"], "UNEARNED")
        self.assertIsNone(report["rate"])

    def test_rows_that_cannot_be_read_at_all_are_not_measured(self):
        for rows in (None, 5, "rows", object()):
            report = seat_report("seat_north", rows)
            self.assertEqual(report["state"], "NOT_MEASURED", repr(rows))
            self.assertIsNone(report["rate"])
            self.assertIsNone(report["offered"])

    def test_not_measured_is_not_no_rows(self):
        self.assertEqual(seat_report("s", [])["state"], "NO_ROWS")
        self.assertEqual(seat_report("s", None)["state"], "NOT_MEASURED")

    def test_the_outcome_reader_refuses_an_unreadable_row(self):
        from polymind.evidence_gate import _outcome
        for row in (None, "row", 5, object()):
            self.assertIsNone(_outcome(row))


if __name__ == "__main__":
    unittest.main()
