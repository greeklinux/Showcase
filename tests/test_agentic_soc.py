"""Tests for ai_security/agentic_soc.py.

Three properties carry the design. Model choice scales with severity so spend
follows blast radius. Every gate in front of an action can only subtract, so an
action executes on its own only when the allowlist, the reviewer, the impact of
the tool and the severity of the alert all say yes. And the record keeps
"nothing needed doing" distinct from "something needed doing and is waiting for
a person", because a dashboard that only tracks whether an action ran reads
those two as the same row and they are opposites.

Nothing here executes anything. Entities are `example.invalid` and addresses
are the RFC 5737 documentation range.
"""

import unittest

from ai_security.agentic_soc import (
    HUMAN_REQUIRED_AT,
    MODEL_BY_SEVERITY,
    REVIEWER_MODEL,
    AgenticSOC,
    Alert,
    Severity,
    TriageRecord,
    call_model,
    propose_action,
    review_action,
)
from ai_security.llm_output_validator import call_digest

DOCUMENTATION_ADDRESS = "203.0.113.9"


def make_alert(severity, alert_id="INC-0001"):
    """An alert whose proposal is a high impact containment action."""
    return Alert(
        id=alert_id,
        title="Impossible travel sign-in",
        severity=severity,
        entity="user@example.invalid",
        raw={"country_a": "AA", "country_b": "BB", "minutes_apart": 12,
             "device_id": "HOST-42"},
    )


def make_lookup_alert(severity, alert_id="INC-0002"):
    """An alert whose proposal is a read only, low impact enrichment step."""
    return Alert(
        id=alert_id,
        title="Sign-in from a new device",
        severity=severity,
        entity="user@example.invalid",
        raw={"ip": DOCUMENTATION_ADDRESS},
    )


def make_over_broad_alert(severity, alert_id="INC-0003"):
    """An alert whose proposal is deliberately over broad, for the allowlist."""
    return Alert(
        id=alert_id,
        title="Mass mailbox export",
        severity=severity,
        entity="user@example.invalid",
        raw={"items": 40000},
    )


def make_disproportionate_alert(severity, alert_id="INC-0004"):
    """An alert whose proposal validates but is disproportionate, for the reviewer."""
    return Alert(
        id=alert_id,
        title="Endpoint malware detection",
        severity=severity,
        entity="user@example.invalid",
        raw={"device_id": "HOST-42"},
    )


def make_quiet_alert(severity, alert_id="INC-0005"):
    """An alert that needs no action at all."""
    return Alert(
        id=alert_id,
        title="Informational policy notice",
        severity=severity,
        entity="user@example.invalid",
        raw={},
    )


class SeverityIsOrdered(unittest.TestCase):
    def test_the_four_levels_rank_from_low_to_critical(self):
        self.assertLess(Severity.LOW, Severity.MEDIUM)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)
        self.assertLess(Severity.HIGH, Severity.CRITICAL)

    def test_a_severity_compares_against_a_plain_integer(self):
        self.assertEqual(int(Severity.HIGH), 3)
        self.assertTrue(Severity.CRITICAL >= 3)


class ModelChoiceScalesWithBlastRadius(unittest.TestCase):
    def test_routine_alerts_use_the_cheap_model(self):
        self.assertEqual(MODEL_BY_SEVERITY[Severity.LOW], "tier1-fast")
        self.assertEqual(MODEL_BY_SEVERITY[Severity.MEDIUM], "tier1-fast")

    def test_a_high_severity_alert_escalates_to_the_larger_model(self):
        self.assertEqual(AgenticSOC().triage(make_alert(Severity.HIGH)).model_used,
                         "tier2-large")

    def test_a_critical_alert_escalates_to_the_reasoning_model(self):
        self.assertEqual(AgenticSOC().triage(make_alert(Severity.CRITICAL)).model_used,
                         "tier3-reasoning")

    def test_a_low_severity_alert_never_reaches_the_expensive_model(self):
        self.assertEqual(AgenticSOC().triage(make_alert(Severity.LOW)).model_used,
                         "tier1-fast")

    def test_every_severity_has_a_route_so_triage_cannot_fall_through(self):
        for severity in Severity:
            self.assertIn(severity, MODEL_BY_SEVERITY)

    def test_the_routes_name_capability_tiers_rather_than_vendors(self):
        """The routing decision outlives any particular model."""
        for model in MODEL_BY_SEVERITY.values():
            self.assertTrue(model.startswith("tier"), model)


class TheHumanGateFollowsImpactAndThenSeverity(unittest.TestCase):

    def test_a_high_impact_action_is_held_for_a_human_even_at_low_severity(self):
        for severity in (Severity.LOW, Severity.MEDIUM):
            record = AgenticSOC().triage(make_alert(severity))
            self.assertFalse(record.auto_execute, severity)
            self.assertTrue(record.requires_human, severity)
            self.assertIn("human approval: high impact action", record.blocked_by)

    def test_high_and_critical_alerts_require_a_human(self):
        for severity in (Severity.HIGH, Severity.CRITICAL):
            record = AgenticSOC().triage(make_alert(severity))
            self.assertTrue(record.requires_human)
            self.assertFalse(record.auto_execute)

    def test_a_low_impact_action_may_execute_unattended_at_routine_severity(self):
        for severity in (Severity.LOW, Severity.MEDIUM):
            record = AgenticSOC().triage(make_lookup_alert(severity))
            self.assertTrue(record.auto_execute, severity)
            self.assertFalse(record.requires_human, severity)
            self.assertEqual(record.blocked_by, [])

    def test_the_severity_boundary_sits_between_medium_and_high(self):
        self.assertEqual(HUMAN_REQUIRED_AT, Severity.HIGH)
        self.assertTrue(AgenticSOC().triage(make_lookup_alert(Severity.MEDIUM)).auto_execute)
        self.assertFalse(AgenticSOC().triage(make_lookup_alert(Severity.HIGH)).auto_execute)

    def test_severity_alone_holds_the_same_low_impact_action_at_high(self):
        record = AgenticSOC().triage(make_lookup_alert(Severity.HIGH))
        self.assertTrue(record.requires_human)
        self.assertEqual(record.blocked_by, ["human approval: severity HIGH"])

    def test_auto_execute_is_not_merely_the_negation_of_the_human_flag(self):
        record = AgenticSOC().triage(make_quiet_alert(Severity.LOW))
        self.assertFalse(record.auto_execute)
        self.assertFalse(record.requires_human)

    def test_a_refused_action_is_also_neither_automatic_nor_pending_on_severity(self):
        record = AgenticSOC().triage(make_over_broad_alert(Severity.LOW))
        self.assertFalse(record.auto_execute)
        self.assertTrue(any(b.startswith("allowlist:") for b in record.blocked_by))


class TheReviewersVerdictActuallyGatesExecution(unittest.TestCase):

    def test_a_rejected_proposal_does_not_execute_and_the_rejection_is_named(self):
        record = AgenticSOC().triage(make_disproportionate_alert(Severity.MEDIUM))
        self.assertFalse(record.auto_execute)
        self.assertTrue(any(b.startswith("review:") for b in record.blocked_by))

    def test_the_rejection_carries_the_reviewers_own_words(self):
        record = AgenticSOC().triage(make_disproportionate_alert(Severity.MEDIUM))
        self.assertIn("review: disabling an account is disproportionate at this severity",
                      record.blocked_by)

    def test_an_approval_from_the_reviewer_is_necessary_but_not_sufficient(self):
        alert = make_alert(Severity.LOW)
        self.assertEqual(review_action(propose_action(alert), alert)["verdict"], "APPROVE")
        self.assertFalse(AgenticSOC().triage(alert).auto_execute)

    def test_the_reviewer_is_never_consulted_about_a_proposal_the_allowlist_refused(self):
        record = AgenticSOC().triage(make_over_broad_alert(Severity.CRITICAL))
        self.assertTrue(any(b.startswith("allowlist:") for b in record.blocked_by))
        self.assertFalse(any(b.startswith("review:") for b in record.blocked_by))

    def test_anything_that_is_not_an_explicit_approve_is_a_rejection(self):
        alert = make_alert(Severity.LOW)
        self.assertEqual(review_action({}, alert)["verdict"], "REJECT")
        self.assertEqual(review_action({"tool": "unknown_tool"}, alert)["verdict"], "REJECT")

    def test_the_reviewer_approves_only_proportionate_reversible_actions(self):
        alert = make_alert(Severity.LOW)
        for tool in ("lookup_ip_reputation", "isolate_endpoint"):
            self.assertEqual(review_action({"tool": tool}, alert)["verdict"], "APPROVE")

    def test_the_reviewer_rejects_disabling_an_account_at_routine_severity(self):
        for severity in (Severity.LOW, Severity.MEDIUM):
            alert = make_disproportionate_alert(severity)
            verdict = review_action({"tool": "disable_user"}, alert)["verdict"]
            self.assertEqual(verdict, "REJECT", severity)

    def test_the_reviewer_is_an_independent_and_stronger_model(self):
        self.assertEqual(REVIEWER_MODEL, MODEL_BY_SEVERITY[Severity.CRITICAL])
        self.assertNotEqual(REVIEWER_MODEL, MODEL_BY_SEVERITY[Severity.LOW])


class GatesOnlySubtract(unittest.TestCase):
    def test_the_allowlist_gate_stops_an_over_broad_proposal(self):
        record = AgenticSOC().triage(make_over_broad_alert(Severity.CRITICAL))
        self.assertIn("allowlist: arguments failed schema or safety bounds",
                      record.blocked_by)

    def test_a_proposal_stopped_by_two_gates_names_both(self):
        record = AgenticSOC().triage(make_disproportionate_alert(Severity.MEDIUM))
        self.assertEqual(len(record.blocked_by), 2)
        self.assertTrue(record.blocked_by[0].startswith("review:"))
        self.assertTrue(record.blocked_by[1].startswith("human approval:"))

    def test_the_same_proposal_auto_executes_at_low_and_is_held_at_high(self):
        low = AgenticSOC().triage(make_lookup_alert(Severity.LOW))
        high = AgenticSOC().triage(make_lookup_alert(Severity.HIGH))
        self.assertEqual(low.proposed, high.proposed)
        self.assertTrue(low.auto_execute)
        self.assertFalse(high.auto_execute)

    def test_an_action_executes_on_its_own_only_when_no_gate_objected(self):
        for severity in Severity:
            for alert in (make_alert(severity), make_lookup_alert(severity),
                          make_over_broad_alert(severity),
                          make_disproportionate_alert(severity)):
                record = AgenticSOC().triage(alert)
                self.assertEqual(record.auto_execute, not record.blocked_by)

    def test_the_record_carries_the_digest_of_the_exact_proposed_call(self):
        alert = make_alert(Severity.LOW)
        record = AgenticSOC().triage(alert)
        self.assertEqual(record.call_id, call_digest(propose_action(alert)))


class TheRecordKeepsNothingNeededDistinctFromWaitingOnAPerson(unittest.TestCase):
    def test_an_alert_needing_no_action_reports_so_rather_than_reporting_a_hold(self):
        record = AgenticSOC().triage(make_quiet_alert(Severity.LOW))
        self.assertFalse(record.action_needed)
        self.assertEqual(record.proposed, {})
        self.assertEqual(record.blocked_by, [])

    def test_an_alert_needing_no_action_renders_as_no_action_needed(self):
        self.assertIn("NO ACTION NEEDED",
                      AgenticSOC().triage(make_quiet_alert(Severity.LOW)).render())

    def test_an_action_that_cleared_every_gate_renders_as_auto_execute(self):
        self.assertIn("AUTO EXECUTE",
                      AgenticSOC().triage(make_lookup_alert(Severity.LOW)).render())

    def test_an_action_waiting_on_a_person_renders_as_held_for_human(self):
        self.assertIn("HELD FOR HUMAN",
                      AgenticSOC().triage(make_alert(Severity.LOW)).render())

    def test_a_refused_action_renders_as_refused_rather_than_as_pending_work(self):
        """A queue of rejections read as a queue of work is how the queue lies."""
        rendered = AgenticSOC().triage(make_over_broad_alert(Severity.CRITICAL)).render()
        self.assertIn("REFUSED", rendered)
        self.assertNotIn("HELD FOR HUMAN", rendered)

    def test_a_reviewer_rejection_also_renders_as_refused(self):
        rendered = AgenticSOC().triage(make_disproportionate_alert(Severity.MEDIUM)).render()
        self.assertIn("REFUSED", rendered)

    def test_the_rendered_line_names_the_alert_the_model_and_the_blocking_gate(self):
        record = AgenticSOC().triage(make_alert(Severity.LOW, alert_id="INC-7777"))
        rendered = record.render()
        self.assertIn("INC-7777", rendered)
        self.assertIn("tier1-fast", rendered)
        self.assertIn("human approval: high impact action", rendered)

    def test_an_unblocked_record_renders_a_placeholder_rather_than_an_empty_column(self):
        self.assertTrue(
            AgenticSOC().triage(make_lookup_alert(Severity.LOW)).render().endswith("-")
        )


class TriageProposesAndNeverExecutes(unittest.TestCase):
    def test_triage_returns_a_record_rather_than_a_loose_dictionary(self):
        self.assertIsInstance(AgenticSOC().triage(make_alert(Severity.LOW)), TriageRecord)

    def test_the_specialist_proposes_a_tool_call_and_runs_nothing(self):
        alert = make_alert(Severity.HIGH)
        proposal = propose_action(alert)
        self.assertEqual(proposal["tool"], "isolate_endpoint")
        self.assertEqual(AgenticSOC().triage(alert).proposed, proposal)

    def test_the_result_carries_the_alert_identifier_for_the_audit_trail(self):
        record = AgenticSOC().triage(make_alert(Severity.LOW, alert_id="INC-9999"))
        self.assertEqual(record.alert_id, "INC-9999")

    def test_the_proposal_reads_the_alert_payload_for_its_arguments(self):
        alert = make_alert(Severity.HIGH)
        self.assertEqual(propose_action(alert)["args"]["device_id"],
                         alert.raw["device_id"])

    def test_a_missing_payload_field_falls_back_rather_than_raising(self):
        alert = Alert("INC-0006", "Impossible travel sign-in", Severity.LOW,
                      "user@example.invalid", {})
        self.assertEqual(propose_action(alert)["args"]["device_id"], "HOST-000")

    def test_the_classification_call_informs_the_proposal_and_authorizes_nothing(self):
        """The analysis is not carried on the record, so nothing can read it as consent."""
        record = AgenticSOC().triage(make_alert(Severity.HIGH))
        self.assertFalse(hasattr(record, "analysis"))
        self.assertFalse(hasattr(record, "review"))

    def test_triage_is_deterministic_for_the_same_alert(self):
        alert = make_alert(Severity.HIGH)
        self.assertEqual(AgenticSOC().triage(alert), AgenticSOC().triage(alert))

    def test_the_stand_in_model_call_returns_its_inputs_and_calls_nothing(self):
        echoed = call_model("any-model", "any system prompt", {"k": "v"})
        self.assertEqual(echoed,
                         {"_model": "any-model", "_system": "any system prompt",
                          "input": {"k": "v"}})


if __name__ == "__main__":
    unittest.main()
