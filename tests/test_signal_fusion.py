"""Tests for polymind/signal_fusion.py.

The module's whole argument is that evidence is additive in log-odds space and
that averaging probabilities destroys agreement. These tests pin that claim, the
neutral-signal identity, and the behaviour at the clamped rails.
"""

import math
import unittest

from polymind.signal_fusion import fuse, logit, sigmoid


class LogitAndSigmoidAreInverses(unittest.TestCase):
    def test_a_probability_of_one_half_is_zero_log_odds(self):
        self.assertEqual(logit(0.5), 0.0)

    def test_sigmoid_of_zero_is_one_half(self):
        self.assertEqual(sigmoid(0.0), 0.5)

    def test_sigmoid_undoes_logit_across_the_interior(self):
        for p in (0.01, 0.2, 0.5, 0.75, 0.99):
            self.assertAlmostEqual(sigmoid(logit(p)), p, places=9)

    def test_logit_clamps_zero_instead_of_returning_negative_infinity(self):
        value = logit(0.0)
        self.assertTrue(math.isfinite(value))
        self.assertAlmostEqual(value, math.log(1e-6 / (1.0 - 1e-6)), places=9)

    def test_logit_clamps_one_instead_of_returning_positive_infinity(self):
        value = logit(1.0)
        self.assertTrue(math.isfinite(value))
        self.assertAlmostEqual(value, -logit(0.0), places=9)

    def test_the_clamp_epsilon_is_configurable(self):
        self.assertAlmostEqual(logit(0.0, eps=1e-3), math.log(1e-3 / 0.999), places=9)


class TwoAgreeingSignalsCompound(unittest.TestCase):
    """The headline claim: two independent 0.80 reads fuse to about 0.94."""

    def test_two_agreeing_eighty_percent_signals_fuse_to_about_point_nine_four(self):
        self.assertAlmostEqual(fuse([(0.80, 1.0), (0.80, 1.0)]), 0.9412, places=4)

    def test_the_fused_result_beats_the_naive_average_of_the_same_signals(self):
        naive_average = (0.80 + 0.80) / 2
        self.assertGreater(fuse([(0.80, 1.0), (0.80, 1.0)]), naive_average)

    def test_three_agreeing_signals_are_more_confident_than_two(self):
        two = fuse([(0.80, 1.0), (0.80, 1.0)])
        three = fuse([(0.80, 1.0), (0.80, 1.0), (0.80, 1.0)])
        self.assertGreater(three, two)

    def test_agreeing_signals_below_one_half_compound_downward(self):
        self.assertAlmostEqual(fuse([(0.20, 1.0), (0.20, 1.0)]), 1.0 - 0.9412, places=4)


class ANeutralSignalIsTheIdentity(unittest.TestCase):
    """A 0.50 read carries zero evidence, so it must change nothing at all."""

    def test_adding_a_neutral_signal_leaves_a_strong_read_exactly_unchanged(self):
        alone = fuse([(0.80, 1.0)])
        with_noise = fuse([(0.80, 1.0), (0.50, 1.0)])
        self.assertEqual(alone, with_noise)

    def test_a_strong_read_plus_noise_stays_at_eighty_percent(self):
        self.assertAlmostEqual(fuse([(0.80, 1.0), (0.50, 1.0)]), 0.80, places=6)

    def test_ten_neutral_signals_cannot_dilute_one_strong_read(self):
        signals = [(0.80, 1.0)] + [(0.50, 1.0)] * 10
        self.assertAlmostEqual(fuse(signals), 0.80, places=6)

    def test_a_weighted_average_would_have_diluted_that_same_input(self):
        """Stated for contrast: the property under test is what averaging lacks."""
        averaged = (0.80 + 0.50 * 10) / 11
        self.assertLess(averaged, 0.60)
        self.assertAlmostEqual(fuse([(0.80, 1.0)] + [(0.50, 1.0)] * 10), 0.80, places=6)


class WeightsScaleEvidence(unittest.TestCase):
    def test_a_weight_of_zero_removes_a_signal_entirely(self):
        self.assertAlmostEqual(fuse([(0.80, 1.0), (0.99, 0.0)]), 0.80, places=6)

    def test_doubling_a_weight_equals_repeating_the_signal(self):
        self.assertAlmostEqual(
            fuse([(0.80, 2.0)]), fuse([(0.80, 1.0), (0.80, 1.0)]), places=9
        )

    def test_a_negative_weight_inverts_the_evidence(self):
        self.assertAlmostEqual(fuse([(0.80, -1.0)]), 0.20, places=6)

    def test_a_confident_source_outvotes_a_distrusted_contrary_one(self):
        result = fuse([(0.90, 1.0), (0.10, 0.1)])
        self.assertGreater(result, 0.5)


class DegenerateAndEmptyInputs(unittest.TestCase):
    def test_an_empty_signal_list_returns_one_half(self):
        self.assertEqual(fuse([]), 0.5)

    def test_a_single_signal_passes_through_unchanged(self):
        self.assertAlmostEqual(fuse([(0.73, 1.0)]), 0.73, places=6)

    def test_a_certain_signal_is_clamped_below_one(self):
        result = fuse([(1.0, 1.0)])
        self.assertLess(result, 1.0)
        self.assertGreater(result, 0.999)

    def test_an_impossible_signal_is_clamped_above_zero(self):
        result = fuse([(0.0, 1.0)])
        self.assertGreater(result, 0.0)
        self.assertLess(result, 0.001)

    def test_opposing_equal_signals_cancel_to_one_half(self):
        self.assertAlmostEqual(fuse([(0.80, 1.0), (0.20, 1.0)]), 0.5, places=9)

    def test_the_output_never_leaves_the_unit_interval(self):
        for signals in ([(1.0, 50.0)], [(0.0, 50.0)], [(0.999, 10.0), (0.999, 10.0)]):
            result = fuse(signals)
            self.assertGreaterEqual(result, 0.0)
            self.assertLessEqual(result, 1.0)


class MalformedSignalsAreRefusedRatherThanFused(unittest.TestCase):
    """Behavioral checks for malformed signals are refused rather than fused."""

    def test_a_nan_probability_is_refused(self):
        with self.assertRaises(ValueError):
            fuse([(float("nan"), 1.0)])

    def test_a_nan_weight_is_refused_and_named_as_the_weight(self):
        with self.assertRaises(ValueError) as caught:
            fuse([(0.8, float("nan"))])
        self.assertIn("weight of signal 0", str(caught.exception))

    def test_an_infinite_weight_is_refused_and_named_by_position(self):
        with self.assertRaises(ValueError) as caught:
            fuse([(0.8, 1.0), (0.9, float("inf"))])
        self.assertIn("weight of signal 1", str(caught.exception))

    def test_a_probability_above_one_is_refused_rather_than_clamped(self):
        with self.assertRaises(ValueError):
            fuse([(5.0, 1.0)])

    def test_a_negative_probability_is_refused_rather_than_clamped(self):
        with self.assertRaises(ValueError):
            fuse([(-3.0, 1.0)])

    def test_a_string_probability_is_refused_by_name(self):
        with self.assertRaises(ValueError) as caught:
            fuse([("0.8", 1.0)])
        self.assertIn("probability", str(caught.exception))

    def test_a_signal_that_is_not_a_pair_is_refused_by_position(self):
        with self.assertRaises(ValueError) as caught:
            fuse([(0.8, 1.0), 0.7])
        self.assertIn("signal 1", str(caught.exception))

    def test_the_refusal_never_returns_a_nan_that_would_render_as_a_number(self):
        for signals in ([(float("nan"), 1.0)], [(0.8, float("nan"))]):
            try:
                result = fuse(signals)
            except ValueError:
                continue
            self.fail("expected a refusal, got %r" % (result,))


class StrongEvidenceDoesNotOverflow(unittest.TestCase):
    """The defect: sigmoid was 1 / (1 + exp(-x)), and exp of a large positive
    number leaves the range of a double. A single distrusted-but-confident
    signal raised OverflowError from a function documented as clamped so that
    nothing ever blows up.
    """

    def test_a_heavily_weighted_confident_downward_signal_returns_a_probability(self):
        result = fuse([(0.01, 200.0)])
        self.assertGreaterEqual(result, 0.0)
        self.assertLess(result, 1e-6)

    def test_the_same_evidence_pointing_up_still_returns_a_probability(self):
        self.assertEqual(fuse([(0.99, 200.0)]), 1.0)

    def test_sigmoid_is_defined_far_past_the_old_overflow_point(self):
        for x in (-5000.0, -1000.0, -710.0, -709.0, 0.0, 709.0, 5000.0):
            with self.subTest(x=x):
                value = sigmoid(x)
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 1.0)

    def test_sigmoid_stays_monotone_through_the_old_overflow_point(self):
        self.assertLessEqual(sigmoid(-800.0), sigmoid(-700.0))
        self.assertLessEqual(sigmoid(-700.0), sigmoid(-600.0))

    def test_sigmoid_of_zero_is_still_exactly_one_half(self):
        self.assertEqual(sigmoid(0.0), 0.5)


class SaturationAtTheRailsIsAsymmetric(unittest.TestCase):
    """Documented, observed behaviour rather than a claim the module makes.

    The epsilon clamp in logit keeps the log-odds finite, but it does not keep
    the fused probability strictly inside (0, 1). Once the summed evidence
    passes about 36.7 nats, 1 + exp(-x) rounds to 1.0 in double precision and
    the fused value is exactly 1.0. The downward direction underflows smoothly
    instead and stays strictly positive. Anything that later divides by
    (1 - p) needs to know this.
    """

    def test_enough_agreeing_signals_saturate_to_exactly_one(self):
        self.assertEqual(fuse([(0.80, 1.0)] * 27), 1.0)

    def test_one_fewer_agreeing_signal_still_stays_below_one(self):
        self.assertLess(fuse([(0.80, 1.0)] * 26), 1.0)

    def test_the_same_evidence_pointing_down_never_reaches_exactly_zero(self):
        self.assertGreater(fuse([(0.20, 1.0)] * 27), 0.0)
        self.assertGreater(fuse([(0.0, 50.0)]), 0.0)


if __name__ == "__main__":
    unittest.main()
