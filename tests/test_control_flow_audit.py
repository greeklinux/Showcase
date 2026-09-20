"""Tests for ai_security/control_flow_audit.py.

The module exists for one bug class: a control that was written, reviewed,
merged and is not in effect. The property under test throughout is that a
verdict counts as governing a decision only when it actually reaches it, and
that the three ways a naive analyzer reports a connection that is not there are
each reported by name instead.

Every fixture here is a synthetic function body given as a string. No file in
the repository is edited, and the two tests that read a real module read it to
pin that the shipped code still wires its gates to its decisions.
"""

import os
import sys
import unittest

from ai_security import control_flow_audit
from ai_security.control_flow_audit import (
    BOTH,
    DATA,
    GUARD,
    UNGUARDED_REVIEWER_EXAMPLE,
    OVERWRITTEN_DECISION,
    PASSED_NOT_GUARDED,
    ENFORCED_REVIEWER_EXAMPLE,
    ControlReport,
    ControlSpec,
    Origin,
    audit_file,
    audit_source,
)

SOC_SPEC = ControlSpec(
    verdict_calls=frozenset({"validate_tool_call", "review_action"}),
    decision_names=frozenset({"auto_execute", "blocked"}),
    decision_calls=frozenset({"runner"}),
)

GATE_SPEC = ControlSpec(
    verdict_calls=frozenset({"validate_tool_call"}),
    decision_calls=frozenset({"runner"}),
)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_SECURITY = os.path.join(HERE, "ai_security")


def states(report):
    return sorted(f.state for f in report.findings)


def subjects(report):
    return sorted(f.subject for f in report.findings)


def in_effect_subjects(report):
    return sorted(item.subject for item in report.in_effect)


class AUseIsNotADecision(unittest.TestCase):
    """The flagship case: an unused-variable check is clean on this bug."""

    def test_the_unguarded_reviewer_example_is_reported(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, SOC_SPEC)
        self.assertFalse(report.ok)

    def test_the_verdict_stored_in_the_response_is_named_as_recorded(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, SOC_SPEC)
        self.assertIn("recorded, not decided on", states(report))

    def test_both_verdicts_in_the_unguarded_example_are_reported(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, SOC_SPEC)
        recorded = [f for f in report.findings
                    if f.state == "recorded, not decided on"]
        self.assertEqual(len(recorded), 2)

    def test_the_decision_itself_is_reported_as_reading_no_verdict(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, SOC_SPEC)
        decision = [f for f in report.findings if f.subject == "auto_execute"]
        self.assertEqual(len(decision), 1)
        self.assertEqual(decision[0].state, "no verdict reaches it")

    def test_the_detail_says_an_unused_variable_check_is_satisfied(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, SOC_SPEC)
        recorded = [f for f in report.findings
                    if f.state == "recorded, not decided on"]
        for finding in recorded:
            self.assertIn("unused-variable check", finding.detail)

    def test_the_same_function_with_the_gates_wired_passes(self):
        report = audit_source(ENFORCED_REVIEWER_EXAMPLE, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_the_fixed_function_reports_the_decision_in_effect(self):
        report = audit_source(ENFORCED_REVIEWER_EXAMPLE, SOC_SPEC)
        self.assertIn("auto_execute", in_effect_subjects(report))

    def test_a_verdict_written_only_into_a_dict_literal_is_recorded(self):
        source = """
def triage(alert, proposal):
    review = review_action(proposal, alert)
    out = {"review": review}
    auto_execute = True
    return out, auto_execute
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("recorded, not decided on", states(report))

    def test_a_verdict_written_only_onto_an_attribute_is_recorded(self):
        source = """
def triage(alert, proposal, record):
    review = review_action(proposal, alert)
    record.review = review
    auto_execute = alert.severity < 3
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("recorded, not decided on", states(report))

    def test_a_verdict_only_logged_is_recorded_not_decided_on(self):
        source = """
def triage(alert, proposal, log):
    review = review_action(proposal, alert)
    log.info(review)
    auto_execute = alert.severity < 3
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("recorded, not decided on", states(report))

    def test_binding_a_verdict_to_its_own_name_is_not_called_recording(self):
        """The line that computes a verdict is not the line that buries it."""
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    auto_execute = decision.allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertEqual(report.findings, [])

    def test_a_verdict_nothing_reads_at_all_is_still_reported(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    auto_execute = alert.severity < 3
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("computed, never used", states(report))

    def test_a_verdict_only_branched_on_is_named_as_branched_on(self):
        source = """
def triage(alert, proposal, log):
    decision = validate_tool_call(proposal)
    if decision.allowed:
        log.info("fine")
    auto_execute = alert.severity < 3
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("branched on, not decided on", states(report))


class TheReachingDefinitionIsWhatDecides(unittest.TestCase):
    """A flow-insensitive analyzer credits an assignment that is dead."""

    def test_an_overwritten_decision_is_reported(self):
        report = audit_source(OVERWRITTEN_DECISION, SOC_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("overwritten", states(report))

    def test_the_overwrite_finding_names_both_lines(self):
        report = audit_source(OVERWRITTEN_DECISION, SOC_SPEC)
        finding = [f for f in report.findings if f.state == "overwritten"][0]
        self.assertIn("line 4", finding.detail)
        self.assertIn("line 7", finding.detail)

    def test_the_overwrite_finding_says_the_first_assignment_is_dead(self):
        report = audit_source(OVERWRITTEN_DECISION, SOC_SPEC)
        finding = [f for f in report.findings if f.state == "overwritten"][0]
        self.assertIn("dead", finding.detail)

    def test_an_overwritten_verdict_is_not_also_reported_as_never_used(self):
        """Two findings that contradict each other are worse than one."""
        report = audit_source(OVERWRITTEN_DECISION, SOC_SPEC)
        self.assertNotIn("computed, never used", states(report))

    def test_reassigning_from_another_verdict_is_not_an_overwrite(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    auto_execute = decision.allowed
    review = review_action(proposal, alert)
    auto_execute = review.get("verdict") == "APPROVE"
"""
        report = audit_source(source, SOC_SPEC)
        self.assertEqual(report.findings, [])

    def test_a_verdict_name_reassigned_from_nothing_stops_carrying_it(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    decision = alert.severity
    auto_execute = decision
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("no verdict reaches it", states(report))

    def test_the_decision_that_survives_is_reported_in_effect(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    auto_execute = alert.severity < 3
    auto_execute = decision.allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())
        self.assertIn("auto_execute", in_effect_subjects(report))


class DataFlowIsNotControlDependence(unittest.TestCase):
    """Handing a verdict to the call it is supposed to gate is not gating it."""

    def test_a_verdict_passed_as_an_argument_is_not_accepted_as_a_gate(self):
        report = audit_source(PASSED_NOT_GUARDED, GATE_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("passed the verdict but not guarded by it", states(report))

    def test_the_finding_says_removing_the_gate_would_not_move_the_flow(self):
        report = audit_source(PASSED_NOT_GUARDED, GATE_SPEC)
        finding = report.findings[0]
        self.assertIn("removing every gate would not change", finding.detail)

    def test_a_data_flow_only_analyzer_reports_the_same_source_clean(self):
        """This is the whole point: the naive report is a pass."""
        loose = ControlSpec(verdict_calls=GATE_SPEC.verdict_calls,
                            decision_calls=GATE_SPEC.decision_calls,
                            require_guard=False)
        report = audit_source(PASSED_NOT_GUARDED, loose)
        self.assertTrue(report.ok)
        self.assertEqual([i.via for i in report.in_effect], [DATA])

    def test_an_early_return_in_front_of_the_call_counts_as_a_guard(self):
        source = """
def run(proposed, runner):
    decision = validate_tool_call(proposed)
    if not decision.allowed:
        return "REFUSED"
    return runner(decision.tool, proposed)
"""
        report = audit_source(source, GATE_SPEC)
        self.assertTrue(report.ok, report.render())
        self.assertEqual([i.via for i in report.in_effect], [BOTH])

    def test_a_guard_clause_that_raises_also_counts(self):
        source = """
def run(proposed, runner):
    decision = validate_tool_call(proposed)
    if not decision.allowed:
        raise ValueError("refused")
    return runner(proposed)
"""
        report = audit_source(source, GATE_SPEC)
        self.assertTrue(report.ok, report.render())
        self.assertEqual([i.via for i in report.in_effect], [GUARD])

    def test_an_enclosing_branch_counts_as_a_guard(self):
        source = """
def run(proposed, runner):
    decision = validate_tool_call(proposed)
    if decision.allowed:
        return runner(proposed)
    return "REFUSED"
"""
        report = audit_source(source, GATE_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_an_if_that_does_not_terminate_does_not_guard_what_follows(self):
        """Falling through an `if` is not the same as returning out of it."""
        source = """
def run(proposed, runner, log):
    decision = validate_tool_call(proposed)
    if not decision.allowed:
        log.info("would refuse")
    return runner(proposed)
"""
        report = audit_source(source, GATE_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("no verdict reaches it", states(report))

    def test_an_if_with_an_else_does_not_guard_what_follows_it(self):
        source = """
def run(proposed, runner, log):
    decision = validate_tool_call(proposed)
    if not decision.allowed:
        return "REFUSED"
    else:
        log.info("allowed")
    return runner(proposed)
"""
        report = audit_source(source, GATE_SPEC)
        self.assertFalse(report.ok)

    def test_a_decision_call_reached_by_neither_route_is_reported(self):
        source = """
def run(proposed, runner):
    decision = validate_tool_call(proposed)
    return runner(proposed)
"""
        report = audit_source(source, GATE_SPEC)
        self.assertIn("no verdict reaches it", states(report))
        self.assertIn("runner()", subjects(report))


class DeadBranchesAreNotFlows(unittest.TestCase):
    def test_a_decision_only_inside_a_constant_false_branch_is_absent(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    if False:
        auto_execute = decision.allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("no decision in this function", states(report))

    def test_a_constant_branch_is_noted_in_the_report(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    if False:
        auto_execute = decision.allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(any("constant test" in note for note in report.notes))

    def test_the_live_side_of_a_constant_branch_is_still_analyzed(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    if False:
        auto_execute = alert.severity
    else:
        auto_execute = decision.allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_constant_true_branch_takes_the_body_not_the_else(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    if True:
        auto_execute = decision.allowed
    else:
        auto_execute = alert.severity
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())


class AccumulatorGatesAreUnderstood(unittest.TestCase):
    """`blocked = []` then `blocked.append(verdict)` is how real gates are written."""

    def test_an_empty_list_filled_by_appends_is_reported_in_effect(self):
        report = audit_source(ENFORCED_REVIEWER_EXAMPLE, SOC_SPEC)
        self.assertIn("blocked", in_effect_subjects(report))

    def test_reading_only_assignments_would_have_reported_it_absent(self):
        """The last assignment to `blocked` is the empty list literal."""
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    blocked = []
    blocked.append(decision.reason)
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("blocked", in_effect_subjects(report))

    def test_an_accumulator_nobody_adds_a_verdict_to_is_reported(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    blocked = []
    blocked.append("severity")
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("no verdict reaches it", states(report))

    def test_an_append_inside_a_branch_still_connects_the_verdict(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    blocked = []
    if not decision.allowed:
        blocked.append(decision.reason)
    auto_execute = not blocked
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_log_call_is_not_treated_as_an_accumulator(self):
        """Only named mutating methods write into their receiver."""
        source = """
def triage(alert, proposal, blocked):
    decision = validate_tool_call(proposal)
    blocked.info(decision.reason)
    auto_execute = not blocked
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("no verdict reaches it", states(report))


class VerdictsTravelThroughOrdinaryPython(unittest.TestCase):
    def test_a_verdict_read_through_a_conditional_expression_is_carried(self):
        source = """
def triage(alert, proposal):
    review = review_action(proposal, alert) if alert else {}
    auto_execute = review.get("verdict") == "APPROVE"
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_verdict_carried_through_an_intermediate_name_still_reaches(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    ok = decision.allowed
    auto_execute = ok
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_verdict_reaching_the_decision_on_one_branch_only_still_counts(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    if alert.severity > 2:
        flag = decision.allowed
    else:
        flag = False
    auto_execute = flag
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_verdict_inside_a_try_body_is_carried(self):
        source = """
def triage(alert, proposal):
    try:
        decision = validate_tool_call(proposal)
    except Exception:
        decision = None
    auto_execute = decision
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_verdict_inside_a_loop_body_is_carried(self):
        source = """
def triage(alert, proposals):
    blocked = []
    for proposal in proposals:
        decision = validate_tool_call(proposal)
        blocked.append(decision.reason)
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_verdict_called_through_a_module_qualifier_is_recognized(self):
        source = """
def triage(alert, proposal, guard):
    decision = guard.validate_tool_call(proposal)
    auto_execute = decision.allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())
        self.assertIn("auto_execute", in_effect_subjects(report))

    def test_an_attribute_decision_target_matches_its_final_component(self):
        source = """
def triage(alert, proposal, record):
    decision = validate_tool_call(proposal)
    record.auto_execute = decision.allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_an_async_function_is_audited_like_any_other(self):
        source = """
async def triage(alert, proposal):
    review = review_action(proposal, alert)
    record = {"review": review}
    auto_execute = alert.severity < 3
    return record, auto_execute
"""
        report = audit_source(source, SOC_SPEC)
        self.assertIn("recorded, not decided on", states(report))

    def test_each_function_is_audited_in_its_own_scope(self):
        source = """
def compute(proposal, record):
    decision = validate_tool_call(proposal)
    record.decision = decision

def decide(alert):
    auto_execute = alert.severity < 3
    return auto_execute
"""
        report = audit_source(source, SOC_SPEC)
        # `compute` buries a verdict and has no decision. `decide` has a
        # decision and no verdict. Neither borrows the other's wiring, so the
        # decision in the second function does not launder the first.
        self.assertIn("no decision in this function", states(report))
        self.assertEqual({f.function for f in report.findings}, {"compute"})

    def test_a_verdict_returned_to_the_caller_is_neither_credited_nor_faulted(self):
        """The analysis is intraprocedural and says so instead of guessing."""
        source = """
def compute(proposal):
    return validate_tool_call(proposal)
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())
        self.assertEqual(report.in_effect, [])

    def test_a_verdict_bound_then_returned_is_also_left_alone(self):
        source = """
def compute(proposal):
    decision = validate_tool_call(proposal)
    return decision
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_a_function_with_no_verdict_at_all_produces_no_findings(self):
        source = """
def unrelated(a, b):
    total = a + b
    return total
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.in_effect, [])


class TheAnalyzerFailsClosed(unittest.TestCase):
    def test_source_that_will_not_parse_is_a_finding_not_a_pass(self):
        report = audit_source("def broken(:\n    pass\n", SOC_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("unparseable", states(report))

    def test_a_non_string_input_is_a_finding_not_a_pass(self):
        report = audit_source(12345, SOC_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("unreadable", states(report))

    def test_a_file_that_cannot_be_read_is_a_finding(self):
        report = audit_file(os.path.join(AI_SECURITY, "no_such_file.py"), SOC_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("unreadable", states(report))

    def test_an_empty_source_produces_no_finding_and_no_claim(self):
        report = audit_source("", SOC_SPEC)
        self.assertTrue(report.ok)
        self.assertEqual(report.in_effect, [])

    def test_a_spec_naming_no_verdict_calls_finds_nothing_and_claims_nothing(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, ControlSpec())
        self.assertTrue(report.ok)
        self.assertEqual(report.in_effect, [])


class TheReportIsReadable(unittest.TestCase):
    def test_a_clean_report_renders_as_pass(self):
        report = audit_source(ENFORCED_REVIEWER_EXAMPLE, SOC_SPEC)
        self.assertIn("PASS", report.render())

    def test_a_dirty_report_renders_as_fail(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, SOC_SPEC)
        self.assertIn("FAIL", report.render())

    def test_the_render_names_every_finding_and_its_state(self):
        report = audit_source(UNGUARDED_REVIEWER_EXAMPLE, SOC_SPEC)
        text = report.render()
        for finding in report.findings:
            self.assertIn(finding.subject, text)
            self.assertIn(finding.state, text)

    def test_the_render_names_what_is_in_effect_and_how_it_got_there(self):
        report = audit_source(ENFORCED_REVIEWER_EXAMPLE, SOC_SPEC)
        text = report.render()
        self.assertIn("IN EFFECT", text)
        self.assertIn("via", text)

    def test_an_origin_prints_the_call_and_the_line(self):
        self.assertEqual(str(Origin("review_action", 12)),
                         "review_action() at line 12")

    def test_an_empty_report_is_ok_by_default(self):
        self.assertTrue(ControlReport().ok)


class TheShippedModulesStillWireTheirGates(unittest.TestCase):
    """A regression test on this repository, using its own analyzer.

    These two modules are the ones whose gates were rebuilt after the audit.
    If a later change reintroduces the shape, this is where it shows up.
    """

    def test_agentic_soc_triage_has_its_verdicts_reaching_the_decision(self):
        report = audit_file(os.path.join(AI_SECURITY, "agentic_soc.py"), SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_agentic_soc_reports_auto_execute_in_effect(self):
        report = audit_file(os.path.join(AI_SECURITY, "agentic_soc.py"), SOC_SPEC)
        self.assertIn("auto_execute", in_effect_subjects(report))

    def test_the_output_validator_gate_is_control_dependent_not_just_passed(self):
        report = audit_file(os.path.join(AI_SECURITY, "llm_output_validator.py"),
                            GATE_SPEC)
        self.assertTrue(report.ok, report.render())
        self.assertTrue(all(item.via in (GUARD, BOTH) for item in report.in_effect),
                        report.render())


class StoringAVerdictIsNotReadingIt(unittest.TestCase):
    """Behavioral checks for storing a verdict is not reading it."""

    LAUNDERED_THROUGH_A_DICT = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    record = {"decision": decision}
    auto_execute = alert.severity < 3 and record is not None
    return auto_execute
"""

    LAUNDERED_THROUGH_A_LOG_LINE = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    note = "verdict=%s" % decision
    auto_execute = alert.severity < 3 or bool(note)
    return auto_execute
"""

    LAUNDERED_THROUGH_AN_FSTRING = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    note = f"verdict={decision}"
    auto_execute = alert.severity < 3 or bool(note)
    return auto_execute
"""

    LAUNDERED_THROUGH_A_GUARD = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    record = {"decision": decision}
    if not record:
        return False
    auto_execute = alert.severity < 3
    return auto_execute
"""

    def test_a_verdict_filed_into_a_dict_does_not_govern_what_reads_the_dict(self):
        report = audit_source(self.LAUNDERED_THROUGH_A_DICT, SOC_SPEC)
        self.assertFalse(report.ok, report.render())
        self.assertEqual(report.in_effect, [], report.render())

    def test_the_dict_case_is_named_as_recording_not_deciding(self):
        report = audit_source(self.LAUNDERED_THROUGH_A_DICT, SOC_SPEC)
        self.assertIn("recorded, not decided on", states(report))

    def test_a_verdict_rendered_into_a_percent_format_does_not_govern(self):
        report = audit_source(self.LAUNDERED_THROUGH_A_LOG_LINE, SOC_SPEC)
        self.assertFalse(report.ok, report.render())
        self.assertEqual(report.in_effect, [], report.render())

    def test_a_verdict_rendered_into_an_fstring_does_not_govern(self):
        report = audit_source(self.LAUNDERED_THROUGH_AN_FSTRING, SOC_SPEC)
        self.assertFalse(report.ok, report.render())
        self.assertEqual(report.in_effect, [], report.render())

    def test_a_guard_that_tests_the_container_is_not_a_guard(self):
        """The same laundering by the control dependence route rather than data."""
        report = audit_source(self.LAUNDERED_THROUGH_A_GUARD, SOC_SPEC)
        self.assertFalse(report.ok, report.render())
        self.assertEqual(report.in_effect, [], report.render())

    def test_reading_the_verdict_back_out_of_the_container_is_not_regressed(self):
        """The cost of the rule above, pinned rather than left to be found.

        The decision here really does read the verdict back, and the analyzer
        still reports it as not in effect, because it does not model what a
        subscript returns. A false positive in a gate auditor is the right
        direction to be wrong in, and this test exists so that the limitation
        is a recorded decision rather than a surprise.
        """
        source = """
def triage(alert, proposal):
    review = review_action(proposal, alert)
    record = {"review": review}
    auto_execute = record["review"].get("verdict") == "APPROVE"
"""
        report = audit_source(source, SOC_SPEC)
        self.assertFalse(report.ok, report.render())

    def test_unpacking_a_tuple_still_carries_the_verdict_to_its_own_name(self):
        """Pairing the two sides up, rather than tainting both names with both."""
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    allowed, severity = decision.allowed, alert.severity
    auto_execute = allowed
"""
        report = audit_source(source, SOC_SPEC)
        self.assertTrue(report.ok, report.render())

    def test_unpacking_does_not_smear_a_verdict_onto_the_other_name(self):
        source = """
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    allowed, severity = decision.allowed, alert.severity
    auto_execute = severity < 3
"""
        report = audit_source(source, SOC_SPEC)
        self.assertFalse(report.ok, report.render())


class TheParserIsNotAllowedToThrowPastTheReport(unittest.TestCase):
    """Behavioral checks for the parser is not allowed to throw past the report."""

    def test_a_null_byte_in_the_source_is_a_finding_not_an_exception(self):
        report = audit_source("def f():\n    pass\n\x00", SOC_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("unparseable", states(report))

    def test_source_nested_past_the_parser_limit_is_a_finding(self):
        source = "def f():\n    x = " + "(" * 2000 + "1" + ")" * 2000 + "\n"
        report = audit_source(source, SOC_SPEC)
        self.assertFalse(report.ok)
        self.assertIn("unparseable", states(report))

    def test_a_deeply_nested_return_does_not_exhaust_the_stack(self):
        source = ("def f():\n    d = validate_tool_call(p)\n    return "
                  + "(" * 90 + "d" + ",)" * 90 + "\n")
        report = audit_source(source, SOC_SPEC)
        self.assertIsInstance(report, ControlReport)



class AGuardThatCanNeverFireIsNotAGuard(unittest.TestCase):
    """The defect this module exists to find, reached through the fix for it.

    `_literal_test` asked whether the test was an `ast.Constant`, which catches
    `if False:` and nothing else. A boolean operator with a false operand, an
    empty container display and a comparison between two literals are all fixed
    by the source text and all read as live branches, so a `runner()` call
    behind one of them was credited with control dependence and the audit came
    back PASS over a control that cannot run.
    """

    DEAD_GUARDS = (
        ("not decision.allowed and False", "a boolean operator"),
        ("False and not decision.allowed", "the same, the other way round"),
        ("[]", "an empty list display"),
        ("()", "an empty tuple display"),
        ("{}", "an empty dict display"),
        ("not True", "not of a constant"),
        ("1 == 2", "a comparison between two literals"),
        ("3 < 2", "an ordering between two literals"),
        ("0", "the constant this module already caught"),
    )

    LIVE_GUARDS = (
        ("not decision.allowed", "the real gate"),
        ("not decision.allowed or False", "or, with a dead second arm"),
        ("decision.allowed is None", "an identity test is not decided here"),
    )

    def source(self, test):
        return ("\ndef run(proposed, runner):\n"
                "    decision = validate_tool_call(proposed)\n"
                "    if %s:\n"
                "        return 'refused'\n"
                "    return runner(decision.tool, proposed)\n" % test)

    def test_no_dead_guard_is_credited_as_control_dependence(self):
        for test, why in self.DEAD_GUARDS:
            with self.subTest(why=why):
                report = audit_source(self.source(test), GATE_SPEC, "dead")
                self.assertFalse(report.ok)
                self.assertEqual(report.in_effect, [])
                self.assertIn("not guarded", report.findings[0].state)

    def test_a_live_guard_is_still_credited(self):
        for test, why in self.LIVE_GUARDS:
            with self.subTest(why=why):
                report = audit_source(self.source(test), GATE_SPEC, "live")
                self.assertTrue(report.ok, report.render())
                self.assertEqual(len(report.in_effect), 1)
                self.assertIn(report.in_effect[0].via, (GUARD, BOTH))

    def test_an_always_true_guard_is_not_control_dependence_either(self):
        # `if [decision]: return 'refused'` refuses on every path, so the call
        # after it is unreachable rather than gated. Either way nothing is
        # governed by the verdict and the report must not say it is.
        report = audit_source(self.source("[decision]"), GATE_SPEC, "always")
        self.assertFalse(report.ok)
        self.assertEqual(report.in_effect, [])

    def test_a_dead_branch_is_named_in_the_notes(self):
        report = audit_source(self.source("1 == 2"), GATE_SPEC, "dead")
        self.assertTrue(any("constant test" in note for note in report.notes))


class AWalrusIsAnAssignmentLikeAnyOther(unittest.TestCase):
    """The defect: `:=` never passed through the assignment path at all.

    `_stmt` dispatches on statements and a walrus is an expression, so
    `if (auto_execute := alert.severity < 3):` reassigned the decision from a
    value carrying no verdict and the line above it was still reported as
    IN EFFECT. That is the same burial a plain reassignment is caught for.
    """

    OVERWRITE_IN_A_TEST = (
        "\ndef triage(alert, proposal):\n"
        "    decision = validate_tool_call(proposal)\n"
        "    auto_execute = decision.allowed\n"
        "    if (auto_execute := alert.severity < 3):\n"
        "        pass\n"
        "    return auto_execute\n")

    OVERWRITE_IN_A_WHILE = (
        "\ndef triage(alert, proposal):\n"
        "    decision = validate_tool_call(proposal)\n"
        "    auto_execute = decision.allowed\n"
        "    while (auto_execute := alert.next()):\n"
        "        pass\n"
        "    return auto_execute\n")

    BINDS_THE_VERDICT = (
        "\ndef run(proposed, runner):\n"
        "    if not (decision := validate_tool_call(proposed)).allowed:\n"
        "        return 'refused'\n"
        "    return runner(decision.tool, proposed)\n")

    def test_a_walrus_over_the_decision_is_reported_as_an_overwrite(self):
        report = audit_source(self.OVERWRITE_IN_A_TEST, SOC_SPEC, "walrus")
        self.assertFalse(report.ok)
        self.assertEqual(report.findings[0].state, "overwritten")

    def test_the_same_inside_a_while_test(self):
        report = audit_source(self.OVERWRITE_IN_A_WHILE, SOC_SPEC, "walrus")
        self.assertFalse(report.ok)
        self.assertEqual(report.findings[0].state, "overwritten")

    def test_a_walrus_that_binds_the_verdict_still_wires_the_gate(self):
        report = audit_source(self.BINDS_THE_VERDICT, GATE_SPEC, "walrus")
        self.assertTrue(report.ok, report.render())
        self.assertEqual(len(report.in_effect), 1)


class AStatementTypeTheWalkCannotReadIsNotAPass(unittest.TestCase):
    """The defect: `_stmt` returned unchanged for anything it did not model.

    `match` and `except*` both arrived in the language after this file was
    written, and both landed on that silent default arm, so every case body and
    every star handler was skipped without a word. A decision overwritten
    inside one is this module's own OVERWRITTEN_DECISION example, and the
    report said IN EFFECT and PASS.
    """

    MATCH_OVERWRITE = (
        "\ndef triage(alert, proposal):\n"
        "    decision = validate_tool_call(proposal)\n"
        "    auto_execute = decision.allowed\n"
        "    match alert.severity:\n"
        "        case 1:\n"
        "            auto_execute = True\n"
        "    return auto_execute\n")

    MATCH_GUARD = (
        "\ndef run(proposed, runner):\n"
        "    decision = validate_tool_call(proposed)\n"
        "    match decision.allowed:\n"
        "        case False:\n"
        "            return 'refused'\n"
        "        case _:\n"
        "            return runner(decision.tool, proposed)\n")

    TRYSTAR_OVERWRITE = (
        "\ndef triage(alert, proposal):\n"
        "    decision = validate_tool_call(proposal)\n"
        "    auto_execute = decision.allowed\n"
        "    try:\n"
        "        pass\n"
        "    except* ValueError:\n"
        "        auto_execute = True\n"
        "    return auto_execute\n")

    @unittest.skipIf(sys.version_info < (3, 10), "match arrived in 3.10")
    def test_an_overwrite_inside_a_match_case_is_reported(self):
        report = audit_source(self.MATCH_OVERWRITE, SOC_SPEC, "match")
        self.assertFalse(report.ok)
        self.assertEqual(report.findings[0].state, "overwritten")

    @unittest.skipIf(sys.version_info < (3, 10), "match arrived in 3.10")
    def test_a_match_on_the_verdict_is_credited_as_control_dependence(self):
        report = audit_source(self.MATCH_GUARD, GATE_SPEC, "match")
        self.assertTrue(report.ok, report.render())
        self.assertEqual(len(report.in_effect), 1)

    @unittest.skipIf(sys.version_info < (3, 11), "except star arrived in 3.11")
    def test_an_overwrite_inside_a_star_handler_is_reported(self):
        report = audit_source(self.TRYSTAR_OVERWRITE, SOC_SPEC, "trystar")
        self.assertFalse(report.ok)
        self.assertEqual(report.findings[0].state, "overwritten")

    TRY_OVERWRITE = (
        "\ndef triage(alert, proposal):\n"
        "    decision = validate_tool_call(proposal)\n"
        "    auto_execute = decision.allowed\n"
        "    try:\n"
        "        auto_execute = True\n"
        "    except ValueError:\n"
        "        pass\n"
        "    return auto_execute\n")

    def test_an_unmodelled_statement_type_becomes_a_finding(self):
        # The next statement type the language adds will reach the default arm
        # the way `match` did, and what has to happen then is a finding rather
        # than a silence. `try` stands in for it: unmodelling it for the length
        # of this test measures the default arm on every interpreter, including
        # the floor, where no statement type is genuinely unmodelled.
        saved = control_flow_audit._TRY_TYPES
        control_flow_audit._TRY_TYPES = ()
        try:
            report = audit_source(self.TRY_OVERWRITE, SOC_SPEC, "unmodelled")
        finally:
            control_flow_audit._TRY_TYPES = saved
        self.assertFalse(report.ok)
        states = [finding.state for finding in report.findings]
        self.assertIn("not analyzed", states)

    def test_the_same_source_with_try_modelled_is_read_properly(self):
        # And with the handler in place the burial inside the `try` is seen for
        # what it is, so the stand-in above is measuring the arm and not the
        # source.
        report = audit_source(self.TRY_OVERWRITE, SOC_SPEC, "modelled")
        self.assertFalse(report.ok)
        self.assertEqual([f.state for f in report.findings], ["overwritten"])

    def test_an_inert_statement_is_not_reported_as_unanalyzed(self):
        # The default arm must not fire on statements that carry no body and
        # write no name, or every gate in the repository reports a finding.
        source = ("\nimport os\n"
                  "\n"
                  "def run(proposed, runner):\n"
                  "    global CACHE\n"
                  "    assert proposed\n"
                  "    decision = validate_tool_call(proposed)\n"
                  "    if not decision.allowed:\n"
                  "        raise ValueError('refused')\n"
                  "    del proposed\n"
                  "    return runner(decision.tool, {})\n")
        report = audit_source(source, GATE_SPEC, "inert")
        self.assertTrue(report.ok, report.render())



import textwrap
import sys
from unittest.mock import patch
from ai_security.control_flow_audit import ControlSpec, audit_source

_REMEDIATION_SPEC = ControlSpec(verdict_calls=frozenset({"validate"}), decision_calls=frozenset({"runner"}))
def remediation_audit(body):
    return audit_source("def f():\n" + textwrap.indent(body, "    "), _REMEDIATION_SPEC)


class ExecutableCoverage(unittest.TestCase):
    def test_unguarded_expression_sites_survive_guarded_sibling(self):
        sites = ('result = runner()', 'result: object = runner()', 'result += runner()',
                 'if runner():\n    pass', 'while runner():\n    break',
                 'for x in runner():\n    pass', 'with runner():\n    pass',
                 'assert runner()', 'raise runner()', 'items[runner()] = 1',
                 'match runner():\n    case _:\n        pass',
                 'match x:\n    case _ if runner():\n        pass',
                 'try:\n    pass\nexcept runner():\n    pass')
        for site in sites:
            if site.startswith("match ") and sys.version_info < (3, 10):
                continue
            for before in (True, False):
                with self.subTest(site=site, before=before):
                    sibling = 'if decision.allowed:\n    runner()\n'
                    body = 'decision = validate()\n' + (site + '\n' + sibling if before else sibling + site + '\n')
                    self.assertFalse(remediation_audit(body).ok, body)

    def test_unsupported_statement_cannot_hide_all_origins(self):
        with patch("ai_security.control_flow_audit._TRY_TYPES", ()):
            report = remediation_audit("try:\n    decision = validate()\n    runner()\nfinally:\n    pass\n")
        self.assertFalse(report.ok)
        self.assertTrue(any(f.state == "not analyzed" for f in report.findings))

    def test_guarded_assignment_and_direct_guard_remain_supported(self):
        self.assertTrue(remediation_audit('decision = validate()\nif decision.allowed:\n    result = runner()\n').ok)

    @unittest.skipIf(sys.version_info < (3, 10), "match requires Python 3.10")
    def test_match_body_is_not_hidden(self):
        self.assertFalse(remediation_audit('match x:\n    case 1:\n        decision = validate()\n        runner()\n').ok)

    def test_returned_verdict_does_not_hide_local_runner(self):
        for returned in ('decision', '(decision,)', '[decision]'):
            self.assertFalse(remediation_audit(f'decision = validate()\nrunner()\nreturn {returned}\n').ok)
        self.assertTrue(remediation_audit('decision = validate()\nreturn decision\n').ok)
        self.assertTrue(remediation_audit('decision = validate()\nif decision.allowed:\n    runner()\nreturn decision\n').ok)

    def test_contained_and_rendered_verdicts_are_not_guards(self):
        for condition in ('{"d": decision}', 'f"verdict={decision}"', 'str(decision)'):
            for site in (f'if {condition}:\n    runner()', f'if not {condition}:\n    return\nrunner()', f'while {condition}:\n    runner()\n    break'):
                with self.subTest(site=site):
                    self.assertFalse(remediation_audit('decision = validate()\n' + site + '\n').ok)
        self.assertFalse(remediation_audit('decision = validate()\nfor item in [decision]:\n    runner()\n').ok)




class DefinitionTimeCallsAreExecutable(unittest.TestCase):
    def test_nested_defaults_decorators_bases_and_class_bodies_are_audited(self):
        definitions = (
            "def inner(x=runner()):\n    pass",
            "def inner(*, x=runner()):\n    pass",
            "@runner()\ndef inner():\n    pass",
            "class C(runner()):\n    pass",
            "class C(metaclass=runner()):\n    pass",
            "class C:\n    runner()",
        )
        for definition in definitions:
            source = "decision = validate()\n" + definition + "\nif decision.allowed:\n    runner()\n"
            self.assertFalse(remediation_audit(source).ok, definition)
        self.assertTrue(remediation_audit("decision = validate()\nif decision.allowed:\n    def inner(x=runner()):\n        pass\n").ok)

if __name__ == "__main__":
    unittest.main()
