"""
agentic_soc.py

Demonstrate SOC triage with proposal validation and independent review.

A manager routes synthetic alerts to specialist model stand-ins. Automatic
execution requires an allowlisted, valid proposal and an explicit APPROVE from
the reviewer. Unparseable review responses are rejected. High-impact actions
and high or critical alerts require human handling.

Each gate can restrict the decision but cannot override a preceding refusal.
The record names the blocking gate and distinguishes no action from an action
waiting for human review. call_model is deterministic; this module does not
establish the effectiveness of real models or deploy a production SOC pipeline.
See README.md for examples and framework mappings.
"""

from dataclasses import dataclass, field
from enum import IntEnum

try:                                            # works as a package or flat
    from .llm_output_validator import validate_tool_call, call_digest
except ImportError:                             # pragma: no cover
    from llm_output_validator import validate_tool_call, call_digest


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Route by cost and capability: a small model for routine alerts, the strongest
# one only when the blast radius justifies it. This keeps spend flat without
# capping quality where it matters. Tier names, not vendor names, because the
# routing decision outlives any particular model.
MODEL_BY_SEVERITY = {
    Severity.LOW: "tier1-fast",
    Severity.MEDIUM: "tier1-fast",
    Severity.HIGH: "tier2-large",
    Severity.CRITICAL: "tier3-reasoning",
}
REVIEWER_MODEL = "tier3-reasoning"

# Any alert at or above this severity routes to a human regardless of what the
# agents concluded.
HUMAN_REQUIRED_AT = Severity.HIGH


@dataclass
class Alert:
    id: str
    title: str
    severity: Severity
    entity: str                       # the user, host, or address the alert centers on
    raw: dict = field(default_factory=dict)


@dataclass
class TriageRecord:
    alert_id: str
    model_used: str
    proposed: dict
    auto_execute: bool
    requires_human: bool
    action_needed: bool               # False means nothing needed doing
    blocked_by: list = field(default_factory=list)
    call_id: str = ""

    def render(self) -> str:
        refused = any(b.startswith(("allowlist:", "review:")) for b in self.blocked_by)
        if not self.action_needed:
            outcome = "HELD FOR HUMAN" if self.requires_human else "NO ACTION NEEDED"
        elif self.auto_execute:
            outcome = "AUTO EXECUTE"
        elif refused:
            # A refused action is not a pending one. Collapsing the two is how
            # a queue of rejections gets read as a queue of work.
            outcome = "REFUSED"
        else:
            outcome = "HELD FOR HUMAN"
        blocked = ("; ".join(self.blocked_by)) or "-"
        return (f"{self.alert_id:<9} {self.model_used:<16} {outcome:<16} "
                f"{str(self.proposed.get('tool', '-')):<21} {blocked}")


def call_model(model: str, system: str, payload: dict) -> dict:
    """Deterministic stand-in for a provider call. Replace with your client.

    A real implementation asks the model for structured output and validates
    that structure before reading it. The stand-in keeps the demo reproducible:
    same input, same answer, no network and no clock.
    """
    return {"_model": model, "_system": system, "input": payload}


def propose_action(alert: Alert) -> dict:
    """Specialist stand-in: propose the minimal containment step, never run it."""
    title = alert.title.lower()
    if "mass" in title or "export" in title:
        # Deliberately over-broad, to show the allowlist catching it.
        return {"tool": "disable_user", "args": {"user": "*", "reason": "mass export"}}
    if "impossible travel" in title:
        return {"tool": "isolate_endpoint",
                "args": {"device_id": alert.raw.get("device_id", "HOST-000"),
                         "reason": "impossible travel pending verification"}}
    if "malware" in title:
        # Disproportionate for the severity, to show the reviewer catching it.
        return {"tool": "disable_user",
                "args": {"user": alert.entity, "reason": "endpoint flagged by antivirus"}}
    if "new device" in title:
        return {"tool": "lookup_ip_reputation", "args": {"ip": alert.raw.get("ip", "")}}
    return {}


def review_action(proposal: dict, alert: Alert) -> dict:
    """Reviewer stand-in: approve only proportionate, reversible actions."""
    tool = proposal.get("tool")
    if tool == "disable_user" and alert.severity < Severity.HIGH:
        return {"verdict": "REJECT",
                "why": "disabling an account is disproportionate at this severity"}
    if tool in ("lookup_ip_reputation", "isolate_endpoint"):
        return {"verdict": "APPROVE", "why": "proportionate and reversible"}
    return {"verdict": "REJECT", "why": "no proportionate reversible action identified"}


class AgenticSOC:
    """Manager, then specialists, then a reviewer that actually decides."""

    def triage(self, alert: Alert) -> TriageRecord:
        model = MODEL_BY_SEVERITY.get(alert.severity, REVIEWER_MODEL)

        # 1) Enrich and classify. Analysis informs the proposal; it authorizes
        #    nothing on its own.
        call_model(model, "Classify the alert and map it to MITRE ATT&CK.",
                   {"title": alert.title, "entity": alert.entity, "raw": alert.raw})

        # 2) Propose, never execute.
        proposal = propose_action(alert)
        record = TriageRecord(alert.id, model, proposal, False, False,
                              action_needed=bool(proposal),
                              call_id=call_digest(proposal))
        if not proposal:
            record.requires_human = alert.severity >= HUMAN_REQUIRED_AT
            if record.requires_human:
                record.blocked_by.append(f"human approval: severity {alert.severity.name}")
            return record

        blocked = []

        # 3) Schema and allowlist, before any model is asked to bless it.
        decision = validate_tool_call(proposal)
        if not decision.allowed:
            blocked.append(f"allowlist: {decision.reason}")

        # 4) Independent review. Anything that is not an explicit APPROVE,
        #    including an unreadable answer, is a rejection.
        review = review_action(proposal, alert) if decision.allowed else {}
        if decision.allowed and review.get("verdict") != "APPROVE":
            blocked.append(f"review: {review.get('why', 'no verdict returned')}")

        # 5) Impact and severity can only add a human, never remove one.
        requires_human = decision.requires_human or alert.severity >= HUMAN_REQUIRED_AT
        if requires_human:
            blocked.append(
                "human approval: high impact action" if decision.requires_human
                else f"human approval: severity {alert.severity.name}")

        record.blocked_by = blocked
        record.requires_human = requires_human
        record.auto_execute = not blocked
        return record


if __name__ == "__main__":
    soc = AgenticSOC()
    alerts = [
        Alert("INC-1001", "Sign-in from a new device", Severity.LOW,
              "analyst@example.com", {"ip": "203.0.113.9"}),
        Alert("INC-1002", "Endpoint malware detection", Severity.MEDIUM,
              "analyst@example.com", {"device_id": "HOST-42"}),
        Alert("INC-1003", "Impossible travel sign-in", Severity.HIGH,
              "analyst@example.com", {"device_id": "HOST-42", "minutes_apart": 12}),
        Alert("INC-1004", "Mass mailbox export", Severity.CRITICAL,
              "analyst@example.com", {"items": 40000}),
        Alert("INC-1005", "Informational policy notice", Severity.LOW,
              "analyst@example.com", {}),
    ]
    print(f"{'alert':<9} {'model':<16} {'outcome':<16} {'proposed':<21} blocked by")
    for a in alerts:
        print(soc.triage(a).render())
