"""Tests for polymind/adaptive_signal.py.

Three properties the module exists to demonstrate: the belief updates online and
grows more confident with evidence, sizing is capped so one read cannot dominate
the book, and a decision with no edge or no confidence is a hold rather than a
small trade.
"""

import math
import unittest

from polymind.adaptive_signal import (
    HISTORY_WINDOW,
    AdaptiveEstimator,
    decide,
    kelly_fraction,
)

NAN = float("nan")
INF = float("inf")


class TheBeliefStartsUninformed(unittest.TestCase):
    def test_a_fresh_estimator_sits_at_one_half(self):
        self.assertEqual(AdaptiveEstimator().estimate, 0.5)

    def test_a_fresh_estimator_has_low_confidence(self):
        self.assertEqual(AdaptiveEstimator().confidence, 0.5)

    def test_a_fresh_estimator_has_an_empty_history(self):
        self.assertEqual(list(AdaptiveEstimator().history), [])

    def test_two_estimators_do_not_share_history(self):
        first = AdaptiveEstimator()
        second = AdaptiveEstimator()
        first.update(0.9)
        self.assertEqual(list(second.history), [])


class TheBeliefLearnsFromEachObservation(unittest.TestCase):
    def test_one_bullish_signal_moves_the_estimate_above_one_half(self):
        est = AdaptiveEstimator()
        est.update(0.72)
        self.assertAlmostEqual(est.estimate, 1.72 / 3.0, places=12)

    def test_one_bearish_signal_moves_the_estimate_below_one_half(self):
        est = AdaptiveEstimator()
        est.update(0.20)
        self.assertLess(est.estimate, 0.5)

    def test_a_neutral_signal_leaves_the_estimate_at_one_half(self):
        est = AdaptiveEstimator()
        est.update(0.5)
        self.assertEqual(est.estimate, 0.5)

    def test_confidence_rises_monotonically_with_every_observation(self):
        est = AdaptiveEstimator()
        seen = [est.confidence]
        for signal in (0.6, 0.7, 0.55, 0.8):
            est.update(signal)
            seen.append(est.confidence)
        self.assertEqual(seen, sorted(seen))
        self.assertGreater(seen[-1], seen[0])

    def test_confidence_approaches_but_never_reaches_one(self):
        est = AdaptiveEstimator()
        for _ in range(500):
            est.update(0.6)
        self.assertGreater(est.confidence, 0.99)
        self.assertLess(est.confidence, 1.0)

    def test_a_heavier_weight_moves_the_belief_further_than_a_lighter_one(self):
        light = AdaptiveEstimator()
        heavy = AdaptiveEstimator()
        light.update(0.9, weight=1.0)
        heavy.update(0.9, weight=5.0)
        self.assertGreater(heavy.estimate, light.estimate)

    def test_a_weight_of_zero_changes_nothing_but_still_records_the_signal(self):
        est = AdaptiveEstimator()
        est.update(0.9, weight=0.0)
        self.assertEqual(est.estimate, 0.5)
        self.assertEqual(est.confidence, 0.5)
        self.assertEqual(list(est.history), [0.9])

    def test_a_signal_above_one_is_clamped_rather_than_accepted(self):
        est = AdaptiveEstimator()
        est.update(4.0)
        self.assertEqual(list(est.history), [1.0])
        self.assertAlmostEqual(est.estimate, 2.0 / 3.0, places=12)

    def test_a_negative_signal_is_clamped_to_zero(self):
        est = AdaptiveEstimator()
        est.update(-3.0)
        self.assertEqual(list(est.history), [0.0])
        self.assertAlmostEqual(est.estimate, 1.0 / 3.0, places=12)

    def test_the_estimate_always_stays_inside_the_unit_interval(self):
        est = AdaptiveEstimator()
        for signal in (0.0, 1.0, 0.0, 1.0, 0.5):
            est.update(signal)
            self.assertGreater(est.estimate, 0.0)
            self.assertLess(est.estimate, 1.0)


class SizingIsCappedAndNeverNegative(unittest.TestCase):
    def test_a_real_edge_is_capped_at_five_percent_of_bankroll(self):
        self.assertEqual(kelly_fraction(0.60, 0.50), 0.05)

    def test_an_enormous_edge_is_still_capped_at_five_percent(self):
        self.assertEqual(kelly_fraction(0.99, 0.10), 0.05)

    def test_the_cap_is_configurable_and_the_raw_kelly_shows_through_below_it(self):
        self.assertAlmostEqual(kelly_fraction(0.60, 0.50, cap=1.0), 0.20, places=12)

    def test_no_edge_stakes_nothing(self):
        self.assertEqual(kelly_fraction(0.50, 0.50), 0.0)

    def test_a_negative_edge_stakes_nothing_rather_than_shorting(self):
        self.assertEqual(kelly_fraction(0.40, 0.50), 0.0)

    def test_a_price_of_zero_stakes_nothing(self):
        self.assertEqual(kelly_fraction(0.90, 0.0), 0.0)

    def test_a_price_of_one_stakes_nothing(self):
        self.assertEqual(kelly_fraction(0.90, 1.0), 0.0)

    def test_a_price_outside_the_unit_interval_stakes_nothing(self):
        self.assertEqual(kelly_fraction(0.90, 1.4), 0.0)
        self.assertEqual(kelly_fraction(0.90, -0.2), 0.0)

    def test_the_stake_is_never_negative_across_a_sweep_of_inputs(self):
        for price in (0.05, 0.25, 0.5, 0.75, 0.95):
            for prob in (0.0, 0.1, 0.5, 0.9, 1.0):
                self.assertGreaterEqual(kelly_fraction(prob, price), 0.0)


class TheDecisionIsExplainableAndRefusesToGuess(unittest.TestCase):
    @staticmethod
    def _estimator_from(signals):
        est = AdaptiveEstimator()
        for signal in signals:
            est.update(signal)
        return est

    def test_the_worked_example_buys_yes_against_a_lagging_market(self):
        est = self._estimator_from((0.72, 0.68, 0.81, 0.6, 0.77))
        result = decide(est, market_price=0.55)
        self.assertEqual(result["action"], "buy_yes")
        self.assertAlmostEqual(result["fair_value"], 0.6543, places=4)
        self.assertEqual(result["stake_fraction"], 0.05)

    def test_a_market_priced_above_the_belief_buys_no(self):
        est = self._estimator_from((0.72, 0.68, 0.81, 0.6, 0.77))
        result = decide(est, market_price=0.90)
        self.assertEqual(result["action"], "buy_no")
        self.assertLess(result["edge"], 0.0)

    def test_an_estimator_with_no_evidence_holds_however_large_the_edge_looks(self):
        est = AdaptiveEstimator()
        self.assertLess(est.confidence, 0.6)
        result = decide(est, market_price=0.10)
        self.assertEqual(result["action"], "hold")

    def test_the_default_confidence_gate_is_cleared_after_a_single_observation(self):
        """Documented, observed behaviour rather than a claim the module makes.

        confidence is 1 - 1/(alpha + beta) and the Beta(1, 1) prior already
        contributes 2, so one unit-weight observation puts it at 0.667 and the
        default min_confidence of 0.6 is satisfied. The gate therefore separates
        zero evidence from some evidence, not thin evidence from thick.
        """
        est = AdaptiveEstimator()
        est.update(0.99)
        self.assertAlmostEqual(est.confidence, 2.0 / 3.0, places=12)
        self.assertEqual(decide(est, market_price=0.10)["action"], "buy_yes")

    def test_a_confident_belief_with_a_thin_edge_is_a_hold(self):
        est = self._estimator_from([0.72, 0.68, 0.81, 0.6, 0.77])
        result = decide(est, market_price=round(est.estimate, 4))
        self.assertEqual(result["action"], "hold")

    def test_an_edge_just_under_the_threshold_is_a_hold(self):
        est = self._estimator_from([0.6] * 20)
        result = decide(est, market_price=est.estimate - 0.039)
        self.assertEqual(result["action"], "hold")

    def test_an_edge_just_over_the_threshold_trades(self):
        est = self._estimator_from([0.6] * 20)
        result = decide(est, market_price=est.estimate - 0.041)
        self.assertEqual(result["action"], "buy_yes")

    def test_a_hold_states_its_reason_rather_than_returning_a_bare_zero(self):
        est = AdaptiveEstimator()
        result = decide(est, market_price=0.10)
        self.assertEqual(result["reason"], "insufficient edge or confidence")

    def test_a_hold_carries_no_stake_key_so_a_caller_cannot_read_a_phantom_size(self):
        est = AdaptiveEstimator()
        result = decide(est, market_price=0.10)
        self.assertNotIn("stake_fraction", result)
        self.assertNotIn("fair_value", result)

    def test_a_trade_reports_every_field_a_reviewer_needs(self):
        est = self._estimator_from((0.72, 0.68, 0.81, 0.6, 0.77))
        result = decide(est, market_price=0.55)
        for key in ("action", "fair_value", "market_price", "edge",
                    "stake_fraction", "confidence"):
            self.assertIn(key, result)

    def test_the_thresholds_are_callable_overrides_not_hard_coded(self):
        est = AdaptiveEstimator()
        est.update(0.99)
        forced = decide(est, market_price=0.10, min_confidence=0.0, min_edge=0.0)
        self.assertEqual(forced["action"], "buy_yes")


class AnUnreadableNumberCannotOpenTheGate(unittest.TestCase):
    """The defect: every comparison against NaN is False, in both directions.

    `decide` held only when `confidence < min_confidence or abs(edge) <
    min_edge`. Fold one NaN signal into the belief and both halves evaluate
    False, so the gate written to hold on thin evidence OPENED on no evidence
    at all and returned a named side with a fair value of `nan` attached,
    which renders as a number in any report that prints it.
    """

    def test_a_nan_signal_is_refused_at_the_update_rather_than_fused(self):
        est = AdaptiveEstimator()
        with self.assertRaises(ValueError):
            est.update(NAN)

    def test_an_infinite_signal_is_refused(self):
        with self.assertRaises(ValueError):
            AdaptiveEstimator().update(INF)

    def test_an_infinite_weight_is_refused(self):
        with self.assertRaises(ValueError):
            AdaptiveEstimator().update(0.9, weight=INF)

    def test_a_string_signal_is_refused_by_name(self):
        with self.assertRaises(ValueError) as caught:
            AdaptiveEstimator().update("0.9")
        self.assertIn("signal", str(caught.exception))

    def test_a_refused_update_leaves_the_belief_exactly_as_it_was(self):
        est = AdaptiveEstimator()
        est.update(0.7)
        before = (est.alpha, est.beta, list(est.history))
        for bad in (NAN, INF, -INF, "x", None):
            with self.assertRaises(ValueError):
                est.update(bad)
        self.assertEqual((est.alpha, est.beta, list(est.history)), before)

    def test_the_belief_can_never_become_unreadable_through_the_public_api(self):
        est = AdaptiveEstimator()
        for signal in (0.0, 1.0, 4.0, -3.0, 0.5):
            est.update(signal)
            self.assertTrue(math.isfinite(est.estimate))
            self.assertTrue(math.isfinite(est.confidence))

    def test_a_market_price_that_is_not_a_number_holds_and_says_so(self):
        est = AdaptiveEstimator()
        est.update(0.9)
        result = decide(est, market_price=NAN)
        self.assertEqual(result["action"], "hold")
        self.assertIn("not a usable number", result["reason"])

    def test_a_market_price_outside_the_unit_interval_holds(self):
        est = AdaptiveEstimator()
        est.update(0.9)
        for price in (1e300, -0.5, 1.4):
            with self.subTest(price=price):
                self.assertEqual(decide(est, market_price=price)["action"], "hold")

    def test_a_none_market_price_holds_rather_than_raising_a_type_error(self):
        est = AdaptiveEstimator()
        est.update(0.9)
        self.assertEqual(decide(est, market_price=None)["action"], "hold")

    def test_a_broken_input_hold_is_distinguishable_from_a_thin_edge_hold(self):
        """A hold forced by garbage must never read as a hold on the merits."""
        est = AdaptiveEstimator()
        est.update(0.9)
        thin = decide(AdaptiveEstimator(), market_price=0.10)["reason"]
        broken = decide(est, market_price=None)["reason"]
        self.assertNotEqual(thin, broken)

    def test_a_broken_input_hold_carries_no_stake_and_no_fair_value(self):
        est = AdaptiveEstimator()
        est.update(0.9)
        result = decide(est, market_price=NAN)
        self.assertNotIn("stake_fraction", result)
        self.assertNotIn("fair_value", result)


class PseudoCountsStayPositive(unittest.TestCase):
    """The defect: a negative weight subtracted pseudo-counts.

    weight=-2 on a 0.5 signal drove alpha + beta to exactly zero, so the next
    read of `estimate` was a ZeroDivisionError. weight=-5 on a 1.0 signal took
    it negative, and `decide` then published fair_value 1.3333, a probability
    of 133 percent, confidence 1.333, and the maximum stake under it.
    """

    def test_a_negative_weight_is_refused(self):
        with self.assertRaises(ValueError):
            AdaptiveEstimator().update(0.5, weight=-2.0)

    def test_a_zero_weight_is_still_allowed(self):
        est = AdaptiveEstimator()
        est.update(0.9, weight=0.0)
        self.assertEqual(est.estimate, 0.5)

    def test_a_belief_constructed_with_zero_pseudo_counts_is_refused(self):
        with self.assertRaises(ValueError):
            AdaptiveEstimator(alpha=0.0, beta=0.0)

    def test_a_belief_constructed_with_a_negative_pseudo_count_is_refused(self):
        with self.assertRaises(ValueError):
            AdaptiveEstimator(alpha=-1.0, beta=1.0)

    def test_the_estimate_can_never_leave_the_unit_interval(self):
        est = AdaptiveEstimator()
        for signal, weight in ((1.0, 5.0), (0.0, 3.0), (1.0, 0.0), (0.5, 2.0)):
            est.update(signal, weight=weight)
            self.assertGreater(est.estimate, 0.0)
            self.assertLess(est.estimate, 1.0)

    def test_confidence_can_never_exceed_one(self):
        est = AdaptiveEstimator()
        for _ in range(50):
            est.update(1.0, weight=3.0)
            self.assertLessEqual(est.confidence, 1.0)


class TheRiskCapCannotBeDisabledByAccident(unittest.TestCase):
    """The cap is the only hard guarantee the sizing function makes."""

    def test_a_nan_cap_stakes_nothing_rather_than_removing_the_cap(self):
        """min(raw, nan) returns raw, so a NaN cap silently removed the cap."""
        self.assertEqual(kelly_fraction(0.90, 0.10, cap=NAN), 0.0)

    def test_a_negative_cap_stakes_nothing(self):
        self.assertEqual(kelly_fraction(0.90, 0.10, cap=-1.0), 0.0)

    def test_a_probability_above_one_stakes_nothing_rather_than_the_full_cap(self):
        """kelly_fraction(5.0, 0.5) returned the cap: the largest bet it makes."""
        self.assertEqual(kelly_fraction(5.0, 0.5), 0.0)

    def test_an_infinite_probability_stakes_nothing_rather_than_the_full_cap(self):
        self.assertEqual(kelly_fraction(INF, 0.5), 0.0)

    def test_a_negative_probability_stakes_nothing(self):
        self.assertEqual(kelly_fraction(-1.0, 0.5), 0.0)

    def test_a_nan_probability_stakes_nothing(self):
        self.assertEqual(kelly_fraction(NAN, 0.5), 0.0)

    def test_a_nan_price_stakes_nothing(self):
        self.assertEqual(kelly_fraction(0.9, NAN), 0.0)

    def test_a_string_price_stakes_nothing_rather_than_raising(self):
        self.assertEqual(kelly_fraction(0.9, "0.5"), 0.0)

    def test_a_none_probability_stakes_nothing(self):
        self.assertEqual(kelly_fraction(None, 0.5), 0.0)

    def test_the_stake_never_exceeds_the_cap_across_a_hostile_sweep(self):
        for prob in (0.0, 0.5, 0.99, 1.0, -1.0, 5.0, NAN, INF):
            for price in (0.01, 0.5, 0.99, 0.0, 1.0, NAN, INF):
                with self.subTest(prob=prob, price=price):
                    stake = kelly_fraction(prob, price)
                    self.assertGreaterEqual(stake, 0.0)
                    self.assertLessEqual(stake, 0.05)



class ThePublishedConfidenceIsTheOneThatWasGated(unittest.TestCase):
    """`decide` gated on `estimator.confidence` and then read the property
    again to publish it, so an estimator whose second answer differed
    published 0.010 under a floor of 0.600 with a stake attached."""

    class Drifting(AdaptiveEstimator):
        def __init__(self):
            AdaptiveEstimator.__init__(self)
            self.reads = 0

        @property
        def confidence(self):
            self.reads += 1
            return 0.99 if self.reads == 1 else 0.01

    def test_the_published_confidence_is_above_the_floor(self):
        decision = decide(self.Drifting(), 0.10, min_confidence=0.6)
        self.assertGreaterEqual(decision["confidence"], 0.6)

    def test_an_ordinary_estimator_still_publishes_its_confidence(self):
        estimator = AdaptiveEstimator()
        for _ in range(60):
            estimator.update(0.9)
        decision = decide(estimator, 0.10, min_confidence=0.6)
        self.assertEqual(decision["confidence"], round(estimator.confidence, 3))


class TheHistoryIsBounded(unittest.TestCase):
    """`history` was an unbounded list that `update` appended to and nothing
    in the repository ever read, on a class sold as running for ever."""

    def test_it_stops_growing_at_the_window(self):
        estimator = AdaptiveEstimator()
        for _ in range(HISTORY_WINDOW * 4):
            estimator.update(0.6)
        self.assertEqual(len(estimator.history), HISTORY_WINDOW)

    def test_it_keeps_the_most_recent_signals(self):
        estimator = AdaptiveEstimator()
        for value in (0.1, 0.2, 0.3):
            estimator.update(value)
        self.assertEqual(list(estimator.history)[-1], 0.3)

    def test_a_history_handed_in_as_a_list_is_bounded_too(self):
        estimator = AdaptiveEstimator(history=[0.5])
        for _ in range(HISTORY_WINDOW * 2):
            estimator.update(0.6)
        self.assertEqual(len(estimator.history), HISTORY_WINDOW)


if __name__ == "__main__":
    unittest.main()
