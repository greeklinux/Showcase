"""Tests for polymind/calibration.py.

The claim is that influence has to be re-earned from verified results: a proper
scoring rule grades direction and confidence together, coin-flip skill earns
zero vote, and confident wrongness is punished harder than a humble hedge.
"""

import unittest

from polymind.calibration import SourceScorecard, brier_score, earned_weights


class TheScoringRuleIsProper(unittest.TestCase):
    def test_a_perfect_confident_forecast_scores_zero(self):
        self.assertEqual(brier_score(1.0, 1), 0.0)
        self.assertEqual(brier_score(0.0, 0), 0.0)

    def test_a_coin_flip_forecast_scores_one_quarter_either_way(self):
        self.assertEqual(brier_score(0.5, 1), 0.25)
        self.assertEqual(brier_score(0.5, 0), 0.25)

    def test_a_confidently_wrong_forecast_scores_the_maximum_of_one(self):
        self.assertEqual(brier_score(1.0, 0), 1.0)
        self.assertEqual(brier_score(0.0, 1), 1.0)

    def test_confidence_without_accuracy_is_punished_harder_than_a_hedge(self):
        humble_hedge = brier_score(0.55, 0)
        loud_and_wrong = brier_score(0.95, 0)
        self.assertLess(humble_hedge, loud_and_wrong)

    def test_the_score_is_never_negative(self):
        for prob in (0.0, 0.25, 0.5, 0.75, 1.0):
            for outcome in (0, 1):
                self.assertGreaterEqual(brier_score(prob, outcome), 0.0)

    def test_the_score_is_bounded_by_one_which_is_what_makes_it_a_scoring_rule(self):
        for prob in (0.0, 0.25, 0.5, 0.75, 1.0):
            for outcome in (0, 1):
                self.assertLessEqual(brier_score(prob, outcome), 1.0)


class TheScoringRuleRefusesWhatIsNotAForecast(unittest.TestCase):
    """The defect: neither argument was checked, so the documented range of
    0.0 to 1.0 did not hold. brier_score(5.0, 0) returned 25.0 and
    brier_score(0.5, 7) returned 42.25, and both flowed into mean_brier as if
    they were spectacularly bad skill rather than malformed input. A NaN
    forecast returned `nan`, which renders as a number on a scorecard.
    """

    def test_a_forecast_above_one_is_refused(self):
        with self.assertRaises(ValueError):
            brier_score(5.0, 0)

    def test_a_negative_forecast_is_refused(self):
        with self.assertRaises(ValueError):
            brier_score(-1.0, 0)

    def test_a_nan_forecast_is_refused_rather_than_returning_nan(self):
        with self.assertRaises(ValueError):
            brier_score(float("nan"), 1)

    def test_an_outcome_that_is_not_zero_or_one_is_refused(self):
        with self.assertRaises(ValueError):
            brier_score(0.5, 7)

    def test_a_string_forecast_is_refused_by_name(self):
        with self.assertRaises(ValueError) as caught:
            brier_score("0.5", 1)
        self.assertIn("forecast", str(caught.exception))

    def test_a_none_forecast_is_a_value_error_not_a_type_error(self):
        with self.assertRaises(ValueError):
            brier_score(None, 1)

    def test_a_refused_record_never_reaches_the_window(self):
        card = SourceScorecard("guarded")
        card.record(0.9, 1)
        for bad_forecast in (float("nan"), 5.0, -1.0, "0.5", None):
            with self.assertRaises(ValueError):
                card.record(bad_forecast, 1)
        self.assertEqual(len(card.scores), 1)

    def test_a_poisoned_window_can_no_longer_report_a_nan_mean(self):
        card = SourceScorecard("guarded")
        with self.assertRaises(ValueError):
            card.record(float("nan"), 1)
        self.assertEqual(card.mean_brier, 0.25)


class AnUntestedSourceHasNoVote(unittest.TestCase):
    def test_a_scorecard_with_no_history_reports_coin_flip_skill(self):
        self.assertEqual(SourceScorecard("fresh").mean_brier, 0.25)

    def test_a_scorecard_with_no_history_earns_zero_weight(self):
        self.assertEqual(SourceScorecard("fresh").weight, 0.0)

    def test_a_source_at_exactly_coin_flip_skill_earns_zero_weight(self):
        card = SourceScorecard("noise")
        for outcome in (1, 0, 1, 0):
            card.record(0.5, outcome)
        self.assertEqual(card.mean_brier, 0.25)
        self.assertEqual(card.weight, 0.0)

    def test_a_source_worse_than_a_coin_flip_earns_zero_rather_than_a_negative_vote(self):
        card = SourceScorecard("anti_signal")
        for outcome in (1, 1, 0):
            card.record(0.05 if outcome else 0.95, outcome)
        self.assertGreater(card.mean_brier, 0.25)
        self.assertEqual(card.weight, 0.0)

    def test_a_flawless_source_earns_the_full_weight_of_one(self):
        card = SourceScorecard("oracle")
        for outcome in (1, 0, 1, 1):
            card.record(float(outcome), outcome)
        self.assertEqual(card.mean_brier, 0.0)
        self.assertEqual(card.weight, 1.0)

    def test_a_single_good_call_already_moves_the_weight_off_zero(self):
        card = SourceScorecard("one_shot")
        card.record(0.75, 1)
        self.assertAlmostEqual(card.mean_brier, 0.0625, places=12)
        self.assertAlmostEqual(card.weight, 0.75, places=12)

    def test_weight_is_a_linear_map_of_skill_over_the_useful_range(self):
        card = SourceScorecard("linear")
        card.record(0.5, 1)
        card.record(1.0, 1)
        self.assertAlmostEqual(card.mean_brier, 0.125, places=12)
        self.assertAlmostEqual(card.weight, (0.25 - 0.125) * 4.0, places=12)


class NormalizingEarnedInfluence(unittest.TestCase):
    def test_the_well_calibrated_source_takes_essentially_all_the_influence(self):
        sharp = SourceScorecard("stats_model")
        loud = SourceScorecard("hype_model")
        for outcome in (1, 1, 0, 1, 0):
            sharp.record(0.75 if outcome else 0.30, outcome)
            loud.record(0.95 if not outcome else 0.10, outcome)
        weights = earned_weights([sharp, loud])
        self.assertAlmostEqual(weights["stats_model"], 1.0, places=12)
        self.assertEqual(weights["hype_model"], 0.0)

    def test_normalized_weights_sum_to_one(self):
        good = SourceScorecard("good")
        fair = SourceScorecard("fair")
        good.record(0.9, 1)
        fair.record(0.6, 1)
        weights = earned_weights([good, fair])
        self.assertAlmostEqual(sum(weights.values()), 1.0, places=12)

    def test_the_better_calibrated_of_two_earners_gets_the_larger_share(self):
        good = SourceScorecard("good")
        fair = SourceScorecard("fair")
        good.record(0.9, 1)
        fair.record(0.6, 1)
        weights = earned_weights([good, fair])
        self.assertGreater(weights["good"], weights["fair"])

    def test_two_identically_skilled_sources_split_influence_evenly(self):
        a = SourceScorecard("a")
        b = SourceScorecard("b")
        a.record(0.8, 1)
        b.record(0.8, 1)
        self.assertEqual(earned_weights([a, b]), {"a": 0.5, "b": 0.5})

    def test_when_nobody_has_earned_anything_nobody_gets_anything(self):
        """The defect: this fell back to `1.0 / len(raw)`, equal influence.

        That is the one thing the module argues against. A roster of sources
        that have never been scored, and a roster every member of which scored
        worse than a coin flip, both received a full normalized set of votes
        summing to one. Influence for free, from the function whose docstring
        says nobody gets influence for free.
        """
        weights = earned_weights([SourceScorecard("a"), SourceScorecard("b")])
        self.assertEqual(weights, {"a": 0.0, "b": 0.0})

    def test_a_roster_that_earned_nothing_does_not_sum_to_a_distribution(self):
        weights = earned_weights([SourceScorecard("a"), SourceScorecard("b")])
        self.assertEqual(sum(weights.values()), 0.0)

    def test_every_source_still_appears_so_the_refusal_is_visible(self):
        """Measured, none found is not the same fact as absent from the roster."""
        weights = earned_weights([SourceScorecard("a"), SourceScorecard("b")])
        self.assertEqual(sorted(weights), ["a", "b"])

    def test_sources_measured_and_found_useless_earn_nothing_not_a_half_each(self):
        bad = SourceScorecard("bad")
        worse = SourceScorecard("worse")
        for outcome in (1, 0):
            bad.record(0.4 if outcome else 0.6, outcome)
            worse.record(0.05 if outcome else 0.95, outcome)
        self.assertGreater(bad.mean_brier, 0.25)
        self.assertGreater(worse.mean_brier, 0.25)
        self.assertEqual(earned_weights([bad, worse]), {"bad": 0.0, "worse": 0.0})

    def test_ten_confidently_wrong_calls_do_not_buy_half_the_ensemble(self):
        loud = SourceScorecard("loud")
        louder = SourceScorecard("louder")
        for _ in range(10):
            loud.record(0.99, 0)
            louder.record(0.99, 0)
        self.assertEqual(earned_weights([loud, louder]),
                         {"loud": 0.0, "louder": 0.0})

    def test_one_earner_among_non_earners_still_takes_all_the_influence(self):
        fresh = SourceScorecard("fresh")
        proven = SourceScorecard("proven")
        for _ in range(10):
            proven.record(0.9, 1)
        weights = earned_weights([fresh, proven])
        self.assertEqual(weights["fresh"], 0.0)
        self.assertAlmostEqual(weights["proven"], 1.0, places=12)

    def test_a_single_earning_source_holds_all_of_the_influence(self):
        only = SourceScorecard("only")
        only.record(0.9, 1)
        self.assertEqual(earned_weights([only]), {"only": 1.0})

    def test_an_empty_roster_returns_an_empty_mapping(self):
        self.assertEqual(earned_weights([]), {})

    def test_duplicate_source_names_collapse_into_one_entry(self):
        """Names are the key, so a duplicated name is a silent overwrite."""
        first = SourceScorecard("same")
        second = SourceScorecard("same")
        first.record(0.9, 1)
        second.record(0.6, 1)
        weights = earned_weights([first, second])
        self.assertEqual(list(weights), ["same"])
        self.assertEqual(weights["same"], 1.0)


class TheWindowArgumentIsHonored(unittest.TestCase):
    """The defect: `window` was accepted, stored, and then ignored.

    `scores` was built by a default factory hard-coding maxlen=50, so the
    constructor argument never reached the deque and a caller asking for a
    five observation window silently got fifty. A risk parameter that is
    accepted and displayed and not in effect is the same bug as a control that
    was written and never wired to anything: everything reads correct except
    the behaviour.
    """

    def test_the_deque_caps_at_the_requested_window(self):
        card = SourceScorecard("narrow", window=5)
        self.assertEqual(card.scores.maxlen, 5)
        self.assertEqual(card.window, 5)

    def test_no_more_observations_are_retained_than_the_requested_window(self):
        card = SourceScorecard("narrow", window=5)
        for _ in range(10):
            card.record(0.5, 1)
        self.assertEqual(len(card.scores), 5)

    def test_a_short_window_forgets_the_old_record_it_was_asked_to_forget(self):
        card = SourceScorecard("narrow", window=4)
        for _ in range(4):
            card.record(1.0, 0)
        self.assertEqual(card.mean_brier, 1.0)
        for _ in range(4):
            card.record(1.0, 1)
        self.assertEqual(card.mean_brier, 0.0)
        self.assertEqual(len(card.scores), 4)

    def test_the_default_window_is_still_fifty(self):
        self.assertEqual(SourceScorecard("default").scores.maxlen, 50)

    def test_a_window_of_zero_is_refused_rather_than_kept_forever(self):
        with self.assertRaises(ValueError):
            SourceScorecard("nothing", window=0)

    def test_a_negative_window_is_refused(self):
        with self.assertRaises(ValueError):
            SourceScorecard("backwards", window=-5)

    def test_a_non_integer_window_is_refused_by_name(self):
        with self.assertRaises(ValueError) as caught:
            SourceScorecard("fractional", window=2.5)
        self.assertIn("window", str(caught.exception))

    def test_the_fifty_first_observation_evicts_the_oldest(self):
        card = SourceScorecard("rolling")
        for _ in range(50):
            card.record(1.0, 0)
        self.assertEqual(card.mean_brier, 1.0)
        for _ in range(50):
            card.record(1.0, 1)
        self.assertEqual(len(card.scores), 50)
        self.assertEqual(card.mean_brier, 0.0)


class TheRosterIsRefusedByNameToo(unittest.TestCase):
    """An unreadable roster and a roster nobody has earned anything on are two
    different facts, and a traceback collapses them.

    `earned_weights` walked `cards` directly, so a registry lookup that
    returned `None` raised TypeError and an entry that was not a scorecard
    raised AttributeError. The caller that wraps this in a broad `except` and
    falls back to an empty mapping gets every source at zero weight, which is
    what this function returns for a measured roster in which nobody has
    earned influence.
    """

    def test_a_roster_that_cannot_be_walked_is_a_value_error(self):
        for cards in (None, 42, object(), 3.5, True):
            with self.assertRaises(ValueError):
                earned_weights(cards)

    def test_a_string_is_not_a_roster(self):
        for cards in ("ab", b"ab"):
            with self.assertRaises(ValueError):
                earned_weights(cards)

    def test_an_entry_that_is_not_a_scorecard_is_a_value_error(self):
        card = SourceScorecard("stats_model")
        for entry in (None, "stats_model", 42, object(), {"name": "x"}):
            with self.assertRaises(ValueError):
                earned_weights([card, entry])

    def test_the_refusal_names_the_argument(self):
        with self.assertRaises(ValueError) as caught:
            earned_weights(None)
        self.assertIn("cards", str(caught.exception))

    def test_an_empty_roster_is_still_an_empty_mapping(self):
        self.assertEqual(earned_weights([]), {})

    def test_a_measured_roster_with_no_skill_is_still_all_zeros(self):
        flat = SourceScorecard("flat")
        for outcome in (1, 0, 1, 0):
            flat.record(0.5, outcome)
        self.assertEqual(earned_weights([flat]), {"flat": 0.0})


class ARosterThatRefusesToBeWalkedIsRefusedByName(unittest.TestCase):

    class RaisingSequence(object):
        def __iter__(self):
            raise RuntimeError("the driver went away mid-read")

    def test_earned_weights_refuses_by_name(self):
        with self.assertRaises(ValueError):
            earned_weights(self.RaisingSequence())


if __name__ == "__main__":
    unittest.main()
