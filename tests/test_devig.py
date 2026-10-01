"""Tests for polymind/devig.py.

The module exists to separate two numbers people conflate: the market's true
belief after the overround is stripped, and the padded price you actually pay.
These tests pin that separation and the arithmetic that produces it.
"""

import unittest

from polymind.devig import implied_probabilities, realized_edge


class StrippingTheOverround(unittest.TestCase):
    def test_de_vigged_probabilities_sum_to_one(self):
        fair = implied_probabilities({"yes": 0.58, "no": 0.47})
        self.assertAlmostEqual(sum(fair.values()), 1.0, places=12)

    def test_the_worked_example_from_the_module_docstring(self):
        fair = implied_probabilities({"yes": 0.58, "no": 0.47})
        self.assertAlmostEqual(fair["yes"], 0.58 / 1.05, places=12)
        self.assertAlmostEqual(fair["no"], 0.47 / 1.05, places=12)

    def test_every_de_vigged_price_is_lower_than_its_quote_when_a_vig_exists(self):
        book = {"yes": 0.58, "no": 0.47}
        fair = implied_probabilities(book)
        for outcome, quote in book.items():
            self.assertLess(fair[outcome], quote)

    def test_the_de_vig_preserves_the_ordering_of_the_outcomes(self):
        fair = implied_probabilities({"a": 0.10, "b": 0.30, "c": 0.65})
        self.assertLess(fair["a"], fair["b"])
        self.assertLess(fair["b"], fair["c"])

    def test_a_book_with_no_overround_is_returned_unchanged(self):
        fair = implied_probabilities({"yes": 0.40, "no": 0.60})
        self.assertAlmostEqual(fair["yes"], 0.40, places=12)
        self.assertAlmostEqual(fair["no"], 0.60, places=12)

    def test_a_three_way_market_normalizes_the_same_way(self):
        fair = implied_probabilities({"home": 0.50, "draw": 0.30, "away": 0.28})
        self.assertAlmostEqual(sum(fair.values()), 1.0, places=12)
        self.assertAlmostEqual(fair["home"], 0.50 / 1.08, places=12)

    def test_normalization_is_proportional_so_the_price_ratio_survives(self):
        book = {"yes": 0.58, "no": 0.47}
        fair = implied_probabilities(book)
        self.assertAlmostEqual(
            fair["yes"] / fair["no"], book["yes"] / book["no"], places=12
        )

    def test_a_single_outcome_book_de_vigs_to_certainty(self):
        self.assertEqual(implied_probabilities({"yes": 0.80}), {"yes": 1.0})

    def test_an_underround_book_is_scaled_up_rather_than_rejected(self):
        fair = implied_probabilities({"yes": 0.40, "no": 0.50})
        self.assertAlmostEqual(sum(fair.values()), 1.0, places=12)
        self.assertGreater(fair["yes"], 0.40)


class RefusingImpossibleBooks(unittest.TestCase):
    def test_an_empty_book_raises_rather_than_dividing_by_zero(self):
        with self.assertRaises(ValueError):
            implied_probabilities({})

    def test_an_all_zero_book_raises_rather_than_dividing_by_zero(self):
        with self.assertRaises(ValueError):
            implied_probabilities({"yes": 0.0, "no": 0.0})

    def test_a_book_summing_to_a_negative_total_raises(self):
        with self.assertRaises(ValueError):
            implied_probabilities({"yes": -0.20, "no": -0.30})

    def test_the_refusal_names_the_reason(self):
        with self.assertRaises(ValueError) as caught:
            implied_probabilities({})
        self.assertIn("positive", str(caught.exception))

    def test_a_negative_quote_inside_a_healthy_total_is_refused(self):
        """The defect: only the total was checked, never the individual quotes.

        {"yes": -0.5, "no": 1.5} sums to exactly 1.0, sailed past the guard
        untouched, and came back verbatim as a de-vigged probability of minus
        50 percent alongside one of 150 percent.
        """
        with self.assertRaises(ValueError):
            implied_probabilities({"yes": -0.5, "no": 1.5})

    def test_a_quote_above_one_is_refused(self):
        with self.assertRaises(ValueError):
            implied_probabilities({"yes": 1.5, "no": 0.2})

    def test_an_infinite_quote_is_refused_rather_than_returning_nan(self):
        """inf / inf came back as nan for one outcome and 0.0 for the other."""
        with self.assertRaises(ValueError) as caught:
            implied_probabilities({"yes": float("inf"), "no": 1.0})
        self.assertIn("finite", str(caught.exception))

    def test_a_nan_quote_is_refused_rather_than_poisoning_every_outcome(self):
        """One NaN quote made every outcome NaN, none of which sum to 1.0."""
        with self.assertRaises(ValueError) as caught:
            implied_probabilities({"yes": float("nan"), "no": 1.0})
        self.assertIn("finite", str(caught.exception))

    def test_the_refusal_names_the_outcome_that_broke_it(self):
        with self.assertRaises(ValueError) as caught:
            implied_probabilities({"yes": 0.5, "draw": -0.2, "no": 0.5})
        self.assertIn("draw", str(caught.exception))

    def test_a_string_quote_is_refused_as_a_value_error_not_a_type_error(self):
        with self.assertRaises(ValueError):
            implied_probabilities({"yes": "0.5"})

    def test_a_non_mapping_is_refused_as_a_value_error(self):
        for bad in (None, [], "0.5", 0.5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    implied_probabilities(bad)

    def test_whatever_comes_back_is_always_a_probability_distribution(self):
        books = ({"yes": 0.58, "no": 0.47}, {"yes": 0.40, "no": 0.50},
                 {"a": 0.10, "b": 0.30, "c": 0.65}, {"yes": 0.8},
                 {"yes": 0.0, "no": 1.0}, {"yes": 1.0, "no": 1.0})
        for book in books:
            with self.subTest(book=book):
                fair = implied_probabilities(book)
                for value in fair.values():
                    self.assertGreaterEqual(value, 0.0)
                    self.assertLessEqual(value, 1.0)
                self.assertAlmostEqual(sum(fair.values()), 1.0, places=12)


class TheEdgeYouActuallyPocket(unittest.TestCase):
    def test_realized_edge_is_measured_against_the_vigged_price_you_pay(self):
        self.assertAlmostEqual(realized_edge(0.60, 0.58), 0.02, places=12)

    def test_realized_edge_is_smaller_than_edge_against_the_true_belief(self):
        book = {"yes": 0.58, "no": 0.47}
        fair = implied_probabilities(book)
        against_belief = 0.60 - fair["yes"]
        pocketed = realized_edge(0.60, book["yes"])
        self.assertGreater(against_belief, pocketed)

    def test_the_gap_between_those_two_edges_is_exactly_the_vig_you_paid(self):
        book = {"yes": 0.58, "no": 0.47}
        fair = implied_probabilities(book)
        against_belief = 0.60 - fair["yes"]
        pocketed = realized_edge(0.60, book["yes"])
        self.assertAlmostEqual(against_belief - pocketed, book["yes"] - fair["yes"], places=12)

    def test_edge_against_the_true_belief_can_be_positive_while_the_trade_loses(self):
        """The trap the module was written to prevent: the vig ate the edge."""
        book = {"yes": 0.58, "no": 0.47}
        fair = implied_probabilities({k: v for k, v in book.items()})
        model = 0.56
        self.assertGreater(model - fair["yes"], 0.0)
        self.assertLess(realized_edge(model, book["yes"]), 0.0)

    def test_paying_exactly_your_model_price_leaves_zero_edge(self):
        self.assertEqual(realized_edge(0.60, 0.60), 0.0)

    def test_a_degenerate_model_probability_of_one_is_still_reduced_by_the_price(self):
        self.assertAlmostEqual(realized_edge(1.0, 0.58), 0.42, places=12)

    def test_a_model_probability_of_zero_gives_a_fully_negative_edge(self):
        self.assertAlmostEqual(realized_edge(0.0, 0.58), -0.58, places=12)

    def test_an_edge_can_never_come_back_wider_than_the_market_allows(self):
        """realized_edge(5.0, -3.0) returned 8.0, on a market whose widest
        real edge is 1.0, and that is the number a sizing step acts on."""
        with self.assertRaises(ValueError):
            realized_edge(5.0, -3.0)

    def test_a_model_probability_above_one_is_refused(self):
        with self.assertRaises(ValueError):
            realized_edge(1.5, 0.5)

    def test_a_negative_price_is_refused(self):
        with self.assertRaises(ValueError):
            realized_edge(0.5, -0.2)

    def test_a_nan_model_probability_is_refused(self):
        with self.assertRaises(ValueError):
            realized_edge(float("nan"), 0.5)

    def test_a_none_input_is_a_value_error_not_a_type_error(self):
        with self.assertRaises(ValueError):
            realized_edge(None, 0.5)

    def test_the_edge_always_lands_inside_minus_one_to_one(self):
        for model in (0.0, 0.25, 0.5, 1.0):
            for price in (0.01, 0.5, 0.99, 1.0):
                with self.subTest(model=model, price=price):
                    edge = realized_edge(model, price)
                    self.assertGreaterEqual(edge, -1.0)
                    self.assertLessEqual(edge, 1.0)


class APriceTooLargeForAFloatIsRefusedByName(unittest.TestCase):
    """`float(10 ** 400)` raises rather than returning infinity, so a very large
    integer price slips past the isfinite guard as an `OverflowError` rather than
    the `ValueError` refusal a price outside the unit interval already gets."""

    def test_a_price_larger_than_the_float_range_is_refused(self):
        with self.assertRaises(ValueError):
            implied_probabilities({"yes": 10 ** 400, "no": 0.5})


if __name__ == "__main__":
    unittest.main()
