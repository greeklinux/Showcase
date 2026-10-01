"""Tests for polymind/posterior.py.

The discipline the module argues for is that a rate needs its null, and that
the null is the rate the price already implied rather than a coin flip. So the
tests check the refusals as hard as they check the arithmetic, and they pin the
rule table as data.
"""

import unittest

from polymind.posterior import (
    RULE_TABLE,
    adjudicate,
    posterior_mean,
    price_implied_null,
    wilson_lower_bound,
)


class ThePosteriorShrinksTowardThePrior(unittest.TestCase):
    def test_a_three_nil_start_does_not_read_as_a_perfect_forecaster(self):
        self.assertLess(posterior_mean(3, 0), 1.0)
        self.assertAlmostEqual(posterior_mean(3, 0), 4.0 / 5.0, places=12)

    def test_nine_of_twelve_reads_below_its_raw_rate(self):
        self.assertLess(posterior_mean(9, 3), 9 / 12)
        self.assertAlmostEqual(posterior_mean(9, 3), 10.0 / 14.0, places=12)

    def test_no_settled_rows_leaves_the_estimate_at_the_prior(self):
        self.assertEqual(posterior_mean(0, 0), 0.5)

    def test_a_zero_of_twelve_record_does_not_read_as_impossible(self):
        self.assertGreater(posterior_mean(0, 12), 0.0)

    def test_the_prior_weight_is_an_explicit_argument(self):
        self.assertAlmostEqual(posterior_mean(3, 0, prior_a=10.0, prior_b=10.0),
                               13.0 / 23.0, places=12)

    def test_shrinkage_fades_as_the_sample_grows(self):
        small = abs(posterior_mean(6, 2) - 0.75)
        large = abs(posterior_mean(600, 200) - 0.75)
        self.assertLess(large, small)


class TheLowerBoundCollapsesOnSmallSamples(unittest.TestCase):
    def test_a_short_hot_streak_cannot_present_itself_as_an_edge(self):
        self.assertLess(wilson_lower_bound(3, 3), 0.45)

    def test_the_same_rate_on_a_larger_sample_supports_a_higher_floor(self):
        self.assertLess(wilson_lower_bound(9, 12), wilson_lower_bound(90, 120))

    def test_the_bound_never_exceeds_the_observed_rate(self):
        for wins, settled in ((3, 3), (9, 12), (74, 120), (57, 90)):
            self.assertLessEqual(wilson_lower_bound(wins, settled), wins / settled)

    def test_a_perfect_record_still_yields_a_bound_below_one(self):
        self.assertLess(wilson_lower_bound(40, 40), 1.0)

    def test_the_confidence_level_is_an_explicit_argument(self):
        self.assertGreater(wilson_lower_bound(60, 100, z=1.0),
                           wilson_lower_bound(60, 100, z=1.96))

    def test_zero_settled_rows_raises_rather_than_returning_a_number(self):
        with self.assertRaises(ValueError):
            wilson_lower_bound(0, 0)

    def test_the_refusal_names_the_missing_denominator(self):
        with self.assertRaises(ValueError) as caught:
            wilson_lower_bound(0, 0)
        self.assertIn("denominator", str(caught.exception))

    def test_more_wins_than_settled_rows_is_refused_at_this_door_too(self):
        """The bound was guarded at adjudicate and not in the public function.

        Called directly it reached math.sqrt of a negative number and came
        back as "math domain error", which names neither the invariant nor
        the argument that broke it.
        """
        with self.assertRaises(ValueError) as caught:
            wilson_lower_bound(200, 100)
        self.assertIn("wins", str(caught.exception))

    def test_a_negative_win_count_is_refused(self):
        with self.assertRaises(ValueError):
            wilson_lower_bound(-5, 100)

    def test_a_nan_confidence_multiplier_is_refused_rather_than_returned(self):
        with self.assertRaises(ValueError):
            wilson_lower_bound(5, 10, z=float("nan"))

    def test_an_infinite_denominator_is_refused(self):
        with self.assertRaises(ValueError):
            wilson_lower_bound(10, float("inf"))

    def test_the_bound_is_always_a_probability(self):
        for wins, settled in ((0, 1), (1, 1), (0, 40), (40, 40), (57, 90)):
            with self.subTest(wins=wins, settled=settled):
                value = wilson_lower_bound(wins, settled)
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 1.0)


class ARateNeedsItsNull(unittest.TestCase):
    def test_the_null_is_the_favourite_rate_on_the_same_rows(self):
        self.assertAlmostEqual(price_implied_null(73, 120), 73 / 120, places=12)

    def test_a_missing_denominator_raises_rather_than_defaulting_to_a_coin_flip(self):
        with self.assertRaises(ValueError):
            price_implied_null(0, 0)

    def test_the_refusal_never_returns_one_half(self):
        try:
            value = price_implied_null(0, 0)
        except ValueError:
            return
        self.fail("expected a refusal, got %r" % (value,))

    def test_a_book_of_heavy_favourites_produces_a_high_null(self):
        self.assertGreater(price_implied_null(100, 120), 0.8)

    def test_a_null_can_never_come_back_above_one(self):
        """price_implied_null(200, 100) returned 2.0: a 200 percent null."""
        with self.assertRaises(ValueError):
            price_implied_null(200, 100)

    def test_a_negative_favourite_count_is_refused(self):
        with self.assertRaises(ValueError):
            price_implied_null(-1, 100)

    def test_a_posterior_with_no_denominator_is_refused(self):
        """posterior_mean(-1, -1) cancelled the prior and divided by zero."""
        with self.assertRaises(ValueError):
            posterior_mean(-1, -1)

    def test_a_posterior_mean_can_never_come_back_above_one(self):
        """posterior_mean(-10, 0) returned 1.125."""
        with self.assertRaises(ValueError):
            posterior_mean(-10, 0)

    def test_no_prior_and_no_rows_is_refused_rather_than_divided_by_zero(self):
        with self.assertRaises(ValueError) as caught:
            posterior_mean(0, 0, prior_a=0.0, prior_b=0.0)
        self.assertIn("denominator", str(caught.exception))

    def test_an_infinite_sample_is_not_a_sample(self):
        """settled=inf cleared every bound and every sample floor at once, so a
        seat with no denominator resolved to HOLD_AND_REMEASURE on a raw rate
        of 0.0 rather than being refused."""
        with self.assertRaises(ValueError):
            adjudicate(wins=10, settled=float("inf"), favourite_hits=10)

    def test_a_nan_sample_is_refused(self):
        with self.assertRaises(ValueError):
            adjudicate(wins=10, settled=float("nan"), favourite_hits=10)

    def test_a_nan_win_count_is_refused(self):
        with self.assertRaises(ValueError):
            adjudicate(wins=float("nan"), settled=100, favourite_hits=10)

    def test_every_number_in_a_resolved_trace_is_a_real_finite_number(self):
        import math as _math
        for wins, settled, favourite_hits in ((0, 40, 40), (40, 40, 0),
                                              (57, 90, 40), (1, 1, 1)):
            with self.subTest(w=wins, n=settled, f=favourite_hits):
                trace = adjudicate(wins, settled, favourite_hits)
                for key in ("raw_rate", "posterior_mean", "wilson_lower_95",
                            "price_implied_null", "margin_over_null"):
                    self.assertTrue(_math.isfinite(trace[key]), key)

    def test_adjudicating_with_no_settled_rows_raises(self):
        with self.assertRaises(ValueError):
            adjudicate(wins=0, settled=0, favourite_hits=0)


class TheRuleTableIsDataAndOrdered(unittest.TestCase):
    def test_the_table_has_four_rows(self):
        self.assertEqual(len(RULE_TABLE), 4)

    def test_the_actions_are_four_distinct_names(self):
        self.assertEqual(len({r.action for r in RULE_TABLE}), 4)

    def test_the_last_row_is_a_catch_all_that_always_matches(self):
        catch_all = RULE_TABLE[-1]
        self.assertEqual(catch_all.min_settled, 0)
        self.assertEqual(catch_all.min_margin, -1.00)

    def test_the_margin_floors_descend_so_first_match_wins_is_meaningful(self):
        margins = [r.min_margin for r in RULE_TABLE]
        self.assertEqual(margins, sorted(margins, reverse=True))

    def test_the_sample_floor_is_forty_settled_rows(self):
        self.assertEqual([r.min_settled for r in RULE_TABLE], [40, 40, 40, 0])

    def test_a_rule_is_frozen_so_a_threshold_cannot_be_edited_at_runtime(self):
        with self.assertRaises(Exception):
            RULE_TABLE[0].min_margin = 0.0


class ScoringAgainstThePriceRatherThanACoinFlip(unittest.TestCase):
    def test_a_record_that_only_matched_the_favourites_is_not_an_edge(self):
        result = adjudicate(wins=74, settled=120, favourite_hits=73)
        self.assertEqual(result["action"], "EVALUATED_NEUTRAL")
        self.assertLess(result["margin_over_null"], 0.0)

    def test_that_same_record_would_have_cleared_a_coin_flip_comparison(self):
        """Stated for contrast: this is exactly what scoring against 0.50 hides."""
        result = adjudicate(wins=74, settled=120, favourite_hits=73)
        self.assertGreater(result["wilson_lower_95"], 0.50)
        self.assertEqual(result["action"], "EVALUATED_NEUTRAL")

    def test_a_record_well_clear_of_the_null_is_minted(self):
        result = adjudicate(wins=57, settled=90, favourite_hits=40)
        self.assertEqual(result["action"], "MINT_AS_WARMING")
        self.assertGreater(result["margin_over_null"], 0.08)

    def test_a_hot_start_below_the_sample_floor_is_not_measured_enough(self):
        result = adjudicate(wins=9, settled=12, favourite_hits=5)
        self.assertEqual(result["action"], "NOT_MEASURED_ENOUGH")

    def test_the_sample_floor_bites_at_thirty_nine_and_releases_at_forty(self):
        self.assertEqual(adjudicate(30, 39, 10)["action"], "NOT_MEASURED_ENOUGH")
        self.assertNotEqual(adjudicate(31, 40, 10)["action"], "NOT_MEASURED_ENOUGH")

    def test_a_thin_but_positive_margin_is_held_and_remeasured(self):
        result = adjudicate(wins=60, settled=100, favourite_hits=50)
        self.assertEqual(result["action"], "HOLD_AND_REMEASURE")
        self.assertGreater(result["margin_over_null"], 0.0)
        self.assertLess(result["margin_over_null"], 0.08)

    def test_a_seat_that_never_won_still_resolves_to_a_named_action(self):
        self.assertEqual(adjudicate(0, 40, 40)["action"], "EVALUATED_NEUTRAL")

    def test_the_result_carries_the_whole_trace_a_reviewer_needs(self):
        result = adjudicate(wins=57, settled=90, favourite_hits=40)
        for key in ("settled", "raw_rate", "posterior_mean", "wilson_lower_95",
                    "price_implied_null", "margin_over_null", "rule", "action"):
            self.assertIn(key, result)

    def test_the_quoted_lower_bound_is_below_the_raw_rate(self):
        result = adjudicate(wins=57, settled=90, favourite_hits=40)
        self.assertLess(result["wilson_lower_95"], result["raw_rate"])

    def test_the_margin_is_the_lower_bound_minus_the_null(self):
        result = adjudicate(wins=57, settled=90, favourite_hits=40)
        self.assertAlmostEqual(
            result["margin_over_null"],
            round(result["wilson_lower_95"] - result["price_implied_null"], 4),
            places=4,
        )

    def test_the_named_rule_matches_the_named_action(self):
        result = adjudicate(wins=57, settled=90, favourite_hits=40)
        matched = [r for r in RULE_TABLE if r.name == result["rule"]]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].action, result["action"])

    def test_adjudication_is_deterministic(self):
        self.assertEqual(adjudicate(57, 90, 40), adjudicate(57, 90, 40))


class TheCatchAllRowReallyIsOne(unittest.TestCase):
    """The table is documented as always matching. It did not always match.

    `favourite_hits` greater than `settled` makes the null exceed 1.0, which
    drives the margin below the catch-all floor of -1.00, so no row matched,
    `matched` was never assigned and the function raised UnboundLocalError.
    `wins` greater than `settled` reached math.sqrt of a negative number and
    came out as "math domain error". Neither invariant was checked.

    Both are refused at the door now, and `matched` starts on the catch-all so
    the claim holds by construction rather than by argument.
    """

    def test_more_favourite_hits_than_settled_rows_is_refused(self):
        with self.assertRaises(ValueError):
            adjudicate(wins=10, settled=40, favourite_hits=90)

    def test_more_wins_than_settled_rows_is_refused(self):
        with self.assertRaises(ValueError):
            adjudicate(wins=50, settled=40, favourite_hits=10)

    def test_the_refusal_names_the_invariant(self):
        with self.assertRaises(ValueError) as caught:
            adjudicate(wins=50, settled=40, favourite_hits=10)
        self.assertIn("wins", str(caught.exception))

    def test_no_input_inside_the_bounds_fails_to_match_a_rule(self):
        for settled in (1, 2, 5, 39, 40, 41, 120):
            for wins in (0, settled // 2, settled):
                for favourite_hits in (0, settled // 2, settled):
                    with self.subTest(n=settled, w=wins, f=favourite_hits):
                        result = adjudicate(wins, settled, favourite_hits)
                        self.assertIn(result["rule"],
                                      [r.name for r in RULE_TABLE])

    def test_the_worst_legal_margin_still_lands_on_the_catch_all_floor(self):
        # wins 0 against a favourite that hit everything is the widest gap the
        # bounds allow, and it must still resolve rather than raise.
        result = adjudicate(wins=0, settled=40, favourite_hits=40)
        self.assertEqual(result["action"], "EVALUATED_NEUTRAL")

    def test_the_documented_examples_are_unchanged(self):
        self.assertEqual(adjudicate(74, 120, 73)["action"], "EVALUATED_NEUTRAL")
        self.assertEqual(adjudicate(57, 90, 40)["action"], "MINT_AS_WARMING")
        self.assertEqual(adjudicate(9, 12, 5)["action"], "NOT_MEASURED_ENOUGH")


class ACountTooLargeForAFloatIsRefusedByName(unittest.TestCase):
    """`float(10 ** 400)` raises rather than returning infinity, so a very large
    integer count slips past the isfinite guard as an `OverflowError` out of the
    middle of the count rather than the `ValueError` refusal the rest of the
    guard uses. It is a real, finite integer that is not usable here, and the
    guard refuses it by name like every other count it cannot use."""

    def test_a_count_larger_than_the_float_range_is_a_refusal(self):
        with self.assertRaises(ValueError):
            posterior_mean(10 ** 400, 0)


if __name__ == "__main__":
    unittest.main()
