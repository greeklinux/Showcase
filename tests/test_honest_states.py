"""Tests for polymind/honest_states.py.

This is the module the rest of the repository leans on, so it gets the
strictest tests. Two properties have to hold no matter what: a failed read can
never render as a zero, and a key that was never measured can never fall
through to the reassuring arm of a renderer.
"""

import unittest

from polymind.honest_states import (
    MetricStore,
    ReadFailure,
    Reading,
    State,
    read_state,
    render,
    render_naive,
)

APPLICABLE = {"alerts", "drift", "integrity"}


def store():
    return MetricStore(rows={"alerts": [1, 0, 1, 1], "drift": []},
                       unreadable={"integrity"})


class TheFourStatesAreDistinct(unittest.TestCase):
    def test_there_are_exactly_four_states_and_no_more(self):
        self.assertEqual(len(State), 4)

    def test_the_four_states_are_the_documented_vocabulary(self):
        self.assertEqual(
            sorted(s.value for s in State),
            ["measured", "measured_none", "not_available", "not_measured"],
        )

    def test_no_two_states_compare_equal(self):
        members = list(State)
        for i, left in enumerate(members):
            for right in members[i + 1:]:
                self.assertNotEqual(left, right)

    def test_a_reading_is_frozen_so_a_state_cannot_be_rewritten_downstream(self):
        reading = Reading(State.NOT_MEASURED)
        with self.assertRaises(Exception):
            reading.state = State.MEASURED_NONE


class AFailedReadIsNeverAZero(unittest.TestCase):
    def test_an_unreadable_key_reports_not_measured(self):
        self.assertIs(read_state(store(), "integrity", APPLICABLE).state,
                      State.NOT_MEASURED)

    def test_an_unreadable_key_keeps_the_backend_reason(self):
        reading = read_state(store(), "integrity", APPLICABLE)
        self.assertIn("refused the read", reading.detail)

    def test_a_key_missing_from_the_backend_reports_not_measured_not_empty(self):
        missing = MetricStore(rows={}, unreadable=set())
        reading = read_state(missing, "alerts", {"alerts"})
        self.assertIs(reading.state, State.NOT_MEASURED)
        self.assertIsNot(reading.state, State.MEASURED_NONE)

    def test_a_failed_read_renders_as_unknown_rather_than_as_a_count(self):
        line = render("integrity", read_state(store(), "integrity", APPLICABLE))
        self.assertIn("NOT MEASURED", line)
        self.assertIn("unknown", line)

    def test_a_failed_read_and_an_empty_result_render_differently(self):
        failed = render("x", read_state(store(), "integrity", APPLICABLE))
        empty = render("x", read_state(store(), "drift", APPLICABLE))
        self.assertNotEqual(failed, empty)

    def test_the_naive_renderer_makes_those_two_facts_identical(self):
        """The defect the module was written against, pinned so it stays visible."""
        failed = render_naive("x", store(), "integrity")
        empty = render_naive("x", store(), "drift")
        self.assertEqual(failed, empty)
        self.assertIn("0 of 0 rows", failed)

    def test_the_two_states_carry_the_same_numbers_so_only_the_state_separates_them(self):
        failed = read_state(store(), "integrity", APPLICABLE)
        empty = read_state(store(), "drift", APPLICABLE)
        self.assertEqual((failed.hits, failed.total), (empty.hits, empty.total))
        self.assertIsNot(failed.state, empty.state)


class MeasuredNoneIsAResultNotAnAbsence(unittest.TestCase):
    def test_an_empty_but_readable_key_reports_measured_none(self):
        self.assertIs(read_state(store(), "drift", APPLICABLE).state,
                      State.MEASURED_NONE)

    def test_measured_none_says_the_check_actually_ran(self):
        reading = read_state(store(), "drift", APPLICABLE)
        self.assertIn("ran", reading.detail)

    def test_measured_none_renders_as_a_measurement_not_as_unknown(self):
        line = render("drift", read_state(store(), "drift", APPLICABLE))
        self.assertIn("MEASURED, NONE", line)
        self.assertNotIn("unknown", line)

    def test_a_populated_key_reports_measured_with_its_k_of_n(self):
        reading = read_state(store(), "alerts", APPLICABLE)
        self.assertIs(reading.state, State.MEASURED)
        self.assertEqual((reading.hits, reading.total), (3, 4))

    def test_a_measured_key_renders_its_counts(self):
        self.assertIn("3 of 4 rows",
                      render("alerts", read_state(store(), "alerts", APPLICABLE)))

    def test_a_key_of_all_zero_rows_is_measured_not_measured_none(self):
        zeros = MetricStore(rows={"alerts": [0, 0, 0]}, unreadable=set())
        reading = read_state(zeros, "alerts", {"alerts"})
        self.assertIs(reading.state, State.MEASURED)
        self.assertEqual((reading.hits, reading.total), (0, 3))


class ApplicabilityIsDecidedBeforeTheRead(unittest.TestCase):
    def test_a_key_outside_the_applicable_set_reports_not_available(self):
        self.assertIs(read_state(store(), "latency", APPLICABLE).state,
                      State.NOT_AVAILABLE)

    def test_an_inapplicable_key_is_not_available_even_when_it_is_unreadable(self):
        """Not applicable is a fact about the subject, not a discovered failure."""
        reading = read_state(store(), "integrity", applicable={"alerts"})
        self.assertIs(reading.state, State.NOT_AVAILABLE)

    def test_an_inapplicable_key_is_not_available_even_when_it_holds_rows(self):
        reading = read_state(store(), "alerts", applicable=set())
        self.assertIs(reading.state, State.NOT_AVAILABLE)
        self.assertEqual(reading.hits, 0)

    def test_not_available_renders_distinctly_from_not_measured(self):
        unavailable = render("x", read_state(store(), "latency", APPLICABLE))
        unmeasured = render("x", read_state(store(), "integrity", APPLICABLE))
        self.assertIn("NOT AVAILABLE", unavailable)
        self.assertNotEqual(unavailable, unmeasured)


class TheRendererHasNoReassuringFallthrough(unittest.TestCase):
    def test_all_four_states_render_to_four_different_lines(self):
        lines = {
            render("x", Reading(State.NOT_MEASURED, detail="d")),
            render("x", Reading(State.NOT_AVAILABLE, detail="d")),
            render("x", Reading(State.MEASURED_NONE, 0, 0, detail="d")),
            render("x", Reading(State.MEASURED, 0, 0)),
        }
        self.assertEqual(len(lines), 4)

    def test_a_zero_of_zero_measurement_never_reads_the_same_as_a_failed_read(self):
        self.assertNotEqual(render("x", Reading(State.MEASURED, 0, 0)),
                            render("x", Reading(State.NOT_MEASURED)))

    def test_every_state_reaches_a_branch_that_names_it(self):
        expected = {
            State.NOT_MEASURED: "NOT MEASURED",
            State.NOT_AVAILABLE: "NOT AVAILABLE",
            State.MEASURED_NONE: "MEASURED, NONE",
            State.MEASURED: "MEASURED",
        }
        for state, marker in expected.items():
            self.assertIn(marker, render("x", Reading(state)))

    def test_the_label_is_always_present_in_the_rendered_line(self):
        for state in State:
            self.assertIn("integrity", render("integrity", Reading(state)))

    def test_rendering_is_deterministic(self):
        reading = read_state(store(), "alerts", APPLICABLE)
        self.assertEqual(render("alerts", reading), render("alerts", reading))


class TheStoreItselfFailsLoudly(unittest.TestCase):
    def test_an_unreadable_key_raises_rather_than_returning_an_empty_list(self):
        with self.assertRaises(ReadFailure):
            store().read("integrity")

    def test_a_missing_key_raises_rather_than_returning_an_empty_list(self):
        with self.assertRaises(KeyError):
            store().read("nothing_here")

    def test_a_readable_empty_key_returns_an_empty_list_without_raising(self):
        self.assertEqual(store().read("drift"), [])


class TheFallThroughGoesToTheWorstReadingNotTheBest(unittest.TestCase):
    """Behavioral checks for the fall through goes to the worst reading not the best."""

    UNRECOGNIZED = ("not_measured", "MEASURED", None, 0, "", object())

    def test_an_unrecognized_state_never_renders_as_measured(self):
        for state in self.UNRECOGNIZED:
            with self.subTest(state=repr(state)):
                line = render("integrity", Reading(state=state))
                status = line.split(maxsplit=1)[1]
                self.assertFalse(status.startswith("MEASURED"), line)
                self.assertTrue(status.startswith("NOT MEASURED"), line)

    def test_an_unrecognized_state_never_prints_a_count(self):
        for state in self.UNRECOGNIZED:
            with self.subTest(state=repr(state)):
                line = render("integrity", Reading(state=state))
                self.assertNotIn(" of ", line.split("unrecognized state")[0])

    def test_a_reading_that_has_been_through_json_is_not_a_measurement(self):
        # State.NOT_MEASURED survives json.dumps only as its value, a string.
        revived = Reading(state=State.NOT_MEASURED.value)
        self.assertIn("NOT MEASURED", render("integrity", revived))

    def test_the_unrecognized_state_is_named_in_the_line(self):
        self.assertIn("unrecognized state", render("x", Reading(state="nope")))

    def test_every_real_state_still_renders_as_before(self):
        self.assertIn("MEASURED         3 of 4 rows",
                      render("x", Reading(State.MEASURED, 3, 4)))
        self.assertIn("NOT MEASURED", render("x", Reading(State.NOT_MEASURED)))
        self.assertIn("NOT AVAILABLE", render("x", Reading(State.NOT_AVAILABLE)))
        self.assertIn("MEASURED, NONE", render("x", Reading(State.MEASURED_NONE, 0, 0)))


if __name__ == "__main__":
    unittest.main()
