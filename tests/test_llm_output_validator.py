"""Tests for ai_security/llm_output_validator.py.

The property under test is default deny: a proposed tool call runs only if the
tool is on the allowlist, its arguments are exactly the keys that tool declares,
and those arguments pass that tool's own bounds. On top of that sit two
guarantees the module enforces rather than merely reports. The human gate lives
inside `execute()`, so a caller cannot skip it by forgetting an `if`, and an
approval names a digest of one exact call, so approving a lookup once cannot
wave through a later account disable.

Addresses in these fixtures are the RFC 5737 and RFC 3849 documentation ranges
or RFC 1918 private space. Nothing here is routable and no host is real.
"""

import hashlib
import json
import unittest
from unittest.mock import patch

from ai_security import llm_output_validator
from ai_security.llm_output_validator import (
    CALL_DIGEST_BITS,
    MAX_CALL_NESTING,
    TOOL_ALLOWLIST,
    UNCANONICAL_DIGEST,
    call_digest,
    execute,
    validate_tool_call,
)

# RFC 5737 TEST-NET-3. External, documentation only, belongs to nobody.
EXTERNAL_V4 = "203.0.113.9"
# RFC 3849 documentation prefix.
EXTERNAL_V6 = "2001:db8::1"


class Runner:
    """A tool runner that records whether it was ever reached."""

    def __init__(self):
        self.calls = []

    def __call__(self, tool, args):
        self.calls.append((tool, dict(args)))
        return "RAN %s" % tool


class AnythingOffTheAllowlistIsRefused(unittest.TestCase):
    def test_an_unknown_tool_is_refused(self):
        decision = validate_tool_call({"tool": "delete_everything", "args": {}})
        self.assertFalse(decision.allowed)

    def test_the_refusal_names_default_deny_as_the_reason(self):
        decision = validate_tool_call({"tool": "delete_everything", "args": {}})
        self.assertIn("allowlist", decision.reason)
        self.assertIn("default deny", decision.reason)

    def test_a_refused_unknown_tool_still_demands_a_human(self):
        decision = validate_tool_call({"tool": "delete_everything", "args": {}})
        self.assertTrue(decision.requires_human)

    def test_a_missing_tool_field_is_refused_rather_than_defaulting_to_anything(self):
        decision = validate_tool_call({"args": {"ip": EXTERNAL_V4}})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.tool, "None")

    def test_an_empty_proposal_is_refused(self):
        self.assertFalse(validate_tool_call({}).allowed)

    def test_a_tool_name_differing_only_in_case_is_refused(self):
        self.assertFalse(validate_tool_call({"tool": "Disable_User", "args": {}}).allowed)

    def test_the_allowlist_holds_only_the_three_reviewed_tools(self):
        self.assertEqual(
            sorted(TOOL_ALLOWLIST),
            ["disable_user", "isolate_endpoint", "lookup_ip_reputation"],
        )


class EveryToolDeclaresItsCompleteArgumentSet(unittest.TestCase):
    def test_each_entry_declares_args_a_validator_and_its_impact(self):
        for name, spec in TOOL_ALLOWLIST.items():
            self.assertIsInstance(spec["args"], set, name)
            self.assertTrue(callable(spec["validate"]), name)
            self.assertIsInstance(spec["requires_human"], bool, name)
            self.assertIsInstance(spec["mutating"], bool, name)

    def test_the_lookup_takes_exactly_one_argument(self):
        self.assertEqual(TOOL_ALLOWLIST["lookup_ip_reputation"]["args"], {"ip"})

    def test_isolating_an_endpoint_takes_a_device_and_a_reason_and_nothing_else(self):
        self.assertEqual(TOOL_ALLOWLIST["isolate_endpoint"]["args"],
                         {"device_id", "reason"})

    def test_disabling_a_user_takes_a_target_and_a_reason_and_nothing_else(self):
        self.assertEqual(TOOL_ALLOWLIST["disable_user"]["args"], {"user", "reason"})

    def test_every_mutating_tool_requires_a_human(self):
        for name, spec in TOOL_ALLOWLIST.items():
            if spec["mutating"]:
                self.assertTrue(spec["requires_human"], name)

    def test_the_only_non_mutating_tool_is_the_read_only_lookup(self):
        read_only = sorted(n for n, s in TOOL_ALLOWLIST.items() if not s["mutating"])
        self.assertEqual(read_only, ["lookup_ip_reputation"])


class ArgumentsAreBoundedPerTool(unittest.TestCase):
    def test_a_well_formed_address_lookup_is_allowed(self):
        decision = validate_tool_call(
            {"tool": "lookup_ip_reputation", "args": {"ip": EXTERNAL_V4}}
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "ok")

    def test_a_lookup_with_a_malformed_address_is_refused(self):
        decision = validate_tool_call(
            {"tool": "lookup_ip_reputation", "args": {"ip": "not-an-address"}}
        )
        self.assertFalse(decision.allowed)
        self.assertIn("bounds", decision.reason)

    def test_a_lookup_with_a_missing_address_is_refused(self):
        self.assertFalse(
            validate_tool_call({"tool": "lookup_ip_reputation", "args": {}}).allowed
        )

    def test_a_lookup_with_an_over_long_address_is_refused(self):
        self.assertEqual(len("10.111.113.77777"), 16)
        self.assertFalse(
            validate_tool_call(
                {"tool": "lookup_ip_reputation", "args": {"ip": "10.111.113.77777"}}
            ).allowed
        )

    def test_an_address_is_parsed_rather_than_measured_by_length(self):
        long_but_valid = "2001:0db8:0000:0000:0000:0000:0000:0001"
        self.assertEqual(len(long_but_valid), 39)
        self.assertTrue(
            validate_tool_call(
                {"tool": "lookup_ip_reputation", "args": {"ip": long_but_valid}}
            ).allowed
        )
        self.assertEqual(len("203.0.113.1133"), 14)
        self.assertFalse(
            validate_tool_call(
                {"tool": "lookup_ip_reputation", "args": {"ip": "203.0.113.1133"}}
            ).allowed
        )

    def test_a_lookup_with_a_non_string_address_is_refused(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "lookup_ip_reputation", "args": {"ip": ["203", "0", "113", "9"]}}
            ).allowed
        )

    def test_an_isolate_call_needs_a_device_identifier(self):
        self.assertTrue(
            validate_tool_call(
                {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
            ).allowed
        )
        self.assertFalse(
            validate_tool_call({"tool": "isolate_endpoint", "args": {}}).allowed
        )

    def test_an_empty_device_identifier_is_refused_rather_than_treated_as_present(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "isolate_endpoint", "args": {"device_id": ""}}
            ).allowed
        )

    def test_an_over_long_device_identifier_is_refused(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "isolate_endpoint", "args": {"device_id": "H" * 65}}
            ).allowed
        )
        self.assertTrue(
            validate_tool_call(
                {"tool": "isolate_endpoint", "args": {"device_id": "H" * 64}}
            ).allowed
        )

    def test_a_well_formed_disable_request_is_allowed(self):
        decision = validate_tool_call(
            {
                "tool": "disable_user",
                "args": {"user": "analyst@example.invalid",
                         "reason": "confirmed credential compromise"},
            }
        )
        self.assertTrue(decision.allowed)

    def test_a_wildcard_target_is_refused_even_with_a_good_reason(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "disable_user",
                 "args": {"user": "*@example.invalid",
                          "reason": "confirmed credential compromise"}}
            ).allowed
        )

    def test_a_short_reason_is_refused_even_with_a_valid_target(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "disable_user",
                 "args": {"user": "analyst@example.invalid", "reason": "bad"}}
            ).allowed
        )

    def test_the_reason_floor_is_exactly_ten_characters(self):
        target = "analyst@example.invalid"
        self.assertFalse(
            validate_tool_call(
                {"tool": "disable_user", "args": {"user": target, "reason": "x" * 9}}
            ).allowed
        )
        self.assertTrue(
            validate_tool_call(
                {"tool": "disable_user", "args": {"user": target, "reason": "x" * 10}}
            ).allowed
        )

    def test_a_target_without_an_at_sign_is_refused(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "disable_user",
                 "args": {"user": "analyst", "reason": "confirmed compromise"}}
            ).allowed
        )


class TheAddressCheckIsARealParseNotAShapeCheck(unittest.TestCase):

    def test_an_out_of_range_octet_string_is_refused(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "lookup_ip_reputation", "args": {"ip": "999.999.999.999"}}
            ).allowed
        )

    def test_a_non_numeric_but_dotted_string_is_refused(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "lookup_ip_reputation", "args": {"ip": "a.b.c.d"}}
            ).allowed
        )

    def test_a_string_of_only_dots_is_refused(self):
        self.assertFalse(
            validate_tool_call(
                {"tool": "lookup_ip_reputation", "args": {"ip": "..."}}
            ).allowed
        )

    def test_private_space_is_refused_rather_than_enriched(self):
        for address in ("10.0.0.7", "172.16.4.4", "192.168.1.1"):
            self.assertFalse(
                validate_tool_call(
                    {"tool": "lookup_ip_reputation", "args": {"ip": address}}
                ).allowed,
                address,
            )

    def test_loopback_link_local_and_carrier_space_are_refused(self):
        for address in ("127.0.0.1", "169.254.1.1", "100.64.0.1"):
            self.assertFalse(
                validate_tool_call(
                    {"tool": "lookup_ip_reputation", "args": {"ip": address}}
                ).allowed,
                address,
            )

    def test_the_internal_refusal_covers_the_version_six_equivalents(self):
        for address in ("::1", "fc00::1", "fe80::1"):
            self.assertFalse(
                validate_tool_call(
                    {"tool": "lookup_ip_reputation", "args": {"ip": address}}
                ).allowed,
                address,
            )

    def test_multicast_and_the_unspecified_address_are_refused(self):
        for address in ("224.0.0.1", "ff02::1", "0.0.0.0", "::"):
            self.assertFalse(
                validate_tool_call(
                    {"tool": "lookup_ip_reputation", "args": {"ip": address}}
                ).allowed,
                address,
            )

    def test_the_documentation_ranges_every_honest_example_uses_are_allowed(self):
        for address in ("192.0.2.1", "198.51.100.7", EXTERNAL_V4, EXTERNAL_V6):
            self.assertTrue(
                validate_tool_call(
                    {"tool": "lookup_ip_reputation", "args": {"ip": address}}
                ).allowed,
                address,
            )


class MalformedProposalsFailClosed(unittest.TestCase):
    def test_a_list_where_arguments_belong_is_refused_without_raising(self):
        decision = validate_tool_call({"tool": "lookup_ip_reputation", "args": []})
        self.assertFalse(decision.allowed)
        self.assertIn("not an object", decision.reason)

    def test_a_string_where_arguments_belong_is_refused_without_raising(self):
        self.assertFalse(
            validate_tool_call({"tool": "disable_user", "args": "everyone"}).allowed
        )

    def test_an_explicit_none_for_arguments_is_refused_without_raising(self):
        self.assertFalse(
            validate_tool_call({"tool": "isolate_endpoint", "args": None}).allowed
        )

    def test_an_allowed_tool_with_no_arguments_key_falls_back_to_validation(self):
        self.assertFalse(validate_tool_call({"tool": "disable_user"}).allowed)

    def test_a_proposal_that_is_not_an_object_at_all_is_refused(self):
        decision = validate_tool_call("drop table alerts")
        self.assertFalse(decision.allowed)
        self.assertIn("default deny", decision.reason)
        self.assertTrue(decision.requires_human)

    def test_a_validator_that_raises_has_not_said_yes(self):
        def explode(args):
            raise ValueError("no opinion")

        spec = {"args": {"a"}, "validate": explode,
                "requires_human": False, "mutating": False}
        with patch.dict(llm_output_validator.TOOL_ALLOWLIST, {"explodes": spec}):
            decision = validate_tool_call({"tool": "explodes", "args": {"a": 1}})
        self.assertFalse(decision.allowed)
        self.assertIn("validator raised", decision.reason)
        self.assertTrue(decision.requires_human)


class AnUnlistedArgumentKeyIsRefused(unittest.TestCase):

    def test_an_unexpected_argument_is_refused_rather_than_ignored(self):
        decision = validate_tool_call(
            {"tool": "lookup_ip_reputation",
             "args": {"ip": EXTERNAL_V4, "and_also": "rm -rf /"}}
        )
        self.assertFalse(decision.allowed)

    def test_the_refusal_names_the_smuggled_key(self):
        decision = validate_tool_call(
            {"tool": "lookup_ip_reputation",
             "args": {"ip": EXTERNAL_V4, "and_also": "rm -rf /"}}
        )
        self.assertIn("unexpected argument", decision.reason)
        self.assertIn("and_also", decision.reason)

    def test_a_smuggled_force_flag_on_a_high_impact_call_is_refused(self):
        decision = validate_tool_call(
            {"tool": "disable_user",
             "args": {"user": "analyst@example.invalid",
                      "reason": "confirmed credential compromise",
                      "force": True}}
        )
        self.assertFalse(decision.allowed)
        self.assertIn("force", decision.reason)

    def test_every_smuggled_key_is_named_not_only_the_first(self):
        decision = validate_tool_call(
            {"tool": "isolate_endpoint",
             "args": {"device_id": "HOST-42", "reason": "confirmed beaconing",
                      "quarantine_all": True, "notify": False}}
        )
        self.assertFalse(decision.allowed)
        self.assertIn("notify", decision.reason)
        self.assertIn("quarantine_all", decision.reason)

    def test_a_refusal_on_an_unlisted_key_still_demands_a_human(self):
        decision = validate_tool_call(
            {"tool": "lookup_ip_reputation",
             "args": {"ip": EXTERNAL_V4, "and_also": "anything"}}
        )
        self.assertTrue(decision.requires_human)

    def test_the_unlisted_key_is_refused_before_the_bounds_are_even_consulted(self):
        """A valid address plus a smuggled key is still a refusal."""
        decision = validate_tool_call(
            {"tool": "lookup_ip_reputation", "args": {"ip": EXTERNAL_V4, "depth": 3}}
        )
        self.assertNotIn("bounds", decision.reason)
        self.assertIn("depth", decision.reason)


class HighImpactActionsKeepAHumanInTheLoop(unittest.TestCase):
    def test_a_low_impact_lookup_may_run_unattended(self):
        decision = validate_tool_call(
            {"tool": "lookup_ip_reputation", "args": {"ip": EXTERNAL_V4}}
        )
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.requires_human)

    def test_isolating_an_endpoint_requires_a_human_even_when_valid(self):
        decision = validate_tool_call(
            {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        )
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_human)

    def test_disabling_a_user_requires_a_human_even_when_valid(self):
        decision = validate_tool_call(
            {"tool": "disable_user",
             "args": {"user": "analyst@example.invalid",
                      "reason": "confirmed credential compromise"}}
        )
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_human)

    def test_every_refusal_path_demands_a_human(self):
        refusals = [
            {"tool": "delete_everything", "args": {}},
            {"tool": "lookup_ip_reputation", "args": {"ip": "bad"}},
            {"tool": "disable_user", "args": {"user": "*", "reason": "bad"}},
        ]
        for proposal in refusals:
            decision = validate_tool_call(proposal)
            self.assertFalse(decision.allowed)
            self.assertTrue(decision.requires_human)


class TheHumanGateLivesInsideExecute(unittest.TestCase):
    """Behavioral checks for the human gate lives inside execute."""

    def test_a_high_impact_call_is_held_and_the_runner_is_never_reached(self):
        runner = Runner()
        result = execute({"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}},
                         runner)
        self.assertTrue(result.startswith("HELD"))
        self.assertEqual(runner.calls, [])

    def test_the_hold_names_the_call_identifier_a_person_must_approve(self):
        proposal = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        result = execute(proposal, Runner())
        self.assertIn(call_digest(proposal), result)

    def test_a_matching_approval_lets_the_high_impact_call_run(self):
        runner = Runner()
        proposal = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        result = execute(proposal, runner, approval=call_digest(proposal))
        self.assertEqual(result, "RAN isolate_endpoint")
        self.assertEqual(runner.calls, [("isolate_endpoint", {"device_id": "HOST-42"})])

    def test_a_low_impact_call_runs_with_no_approval_at_all(self):
        runner = Runner()
        result = execute({"tool": "lookup_ip_reputation", "args": {"ip": EXTERNAL_V4}},
                         runner)
        self.assertEqual(result, "RAN lookup_ip_reputation")
        self.assertEqual(len(runner.calls), 1)

    def test_a_refused_call_never_reaches_the_runner(self):
        runner = Runner()
        result = execute({"tool": "delete_everything", "args": {}}, runner)
        self.assertTrue(result.startswith("REFUSED"))
        self.assertEqual(runner.calls, [])

    def test_a_malformed_proposal_is_refused_without_reaching_the_runner(self):
        runner = Runner()
        self.assertTrue(execute("drop table alerts", runner).startswith("REFUSED"))
        self.assertEqual(runner.calls, [])

    def test_an_approval_cannot_rescue_a_call_the_allowlist_refused(self):
        runner = Runner()
        proposal = {"tool": "delete_everything", "args": {}}
        result = execute(proposal, runner, approval=call_digest(proposal))
        self.assertTrue(result.startswith("REFUSED"))
        self.assertEqual(runner.calls, [])

    def test_an_approval_cannot_rescue_a_call_that_failed_its_bounds(self):
        runner = Runner()
        proposal = {"tool": "disable_user", "args": {"user": "*", "reason": "x" * 20}}
        result = execute(proposal, runner, approval=call_digest(proposal))
        self.assertTrue(result.startswith("REFUSED"))
        self.assertEqual(runner.calls, [])

    def test_a_truthy_approval_that_is_not_the_digest_does_not_open_the_gate(self):
        runner = Runner()
        for approval in ("yes", "approved", "True", "1"):
            result = execute({"tool": "isolate_endpoint",
                              "args": {"device_id": "HOST-42"}},
                             runner, approval=approval)
            self.assertTrue(result.startswith("HELD"), approval)
        self.assertEqual(runner.calls, [])


class AnApprovalIsBoundToOneExactCall(unittest.TestCase):
    """An approval for one tool and argument set cannot authorize a different call."""

    def test_an_approval_for_one_call_cannot_authorize_a_different_call(self):
        runner = Runner()
        approved = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        other = {"tool": "disable_user",
                 "args": {"user": "analyst@example.invalid",
                          "reason": "confirmed credential compromise"}}
        result = execute(other, runner, approval=call_digest(approved))
        self.assertTrue(result.startswith("HELD"))
        self.assertEqual(runner.calls, [])

    def test_an_approval_does_not_carry_over_to_the_same_tool_with_other_arguments(self):
        runner = Runner()
        approved = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        widened = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-99"}}
        self.assertTrue(
            execute(widened, runner, approval=call_digest(approved)).startswith("HELD")
        )
        self.assertEqual(runner.calls, [])

    def test_two_different_calls_never_share_a_digest(self):
        first = call_digest({"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}})
        second = call_digest({"tool": "isolate_endpoint", "args": {"device_id": "HOST-43"}})
        third = call_digest({"tool": "disable_user",
                             "args": {"user": "analyst@example.invalid",
                                      "reason": "confirmed credential compromise"}})
        self.assertEqual(len({first, second, third}), 3)

    def test_the_digest_is_stable_across_calls(self):
        proposal = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        self.assertEqual(call_digest(proposal), call_digest(proposal))

    def test_the_digest_does_not_depend_on_key_order(self):
        one = {"tool": "disable_user",
               "args": {"user": "analyst@example.invalid", "reason": "confirmed theft"}}
        two = {"args": {"reason": "confirmed theft", "user": "analyst@example.invalid"},
               "tool": "disable_user"}
        self.assertEqual(call_digest(one), call_digest(two))

    def test_a_digest_is_computed_for_an_unserializable_proposal_rather_than_raising(self):
        self.assertTrue(call_digest({"tool": "isolate_endpoint", "args": {"x": object()}}))

    def test_the_decision_carries_the_digest_an_approval_must_name(self):
        proposal = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        self.assertEqual(validate_tool_call(proposal).call_id, call_digest(proposal))

    def test_a_refused_call_still_carries_a_digest_for_the_audit_trail(self):
        proposal = {"tool": "delete_everything", "args": {}}
        self.assertEqual(validate_tool_call(proposal).call_id, call_digest(proposal))


class TheDigestWidthIsAChosenWidth(unittest.TestCase):
    """The defect: `call_digest` returned the first sixteen hex characters, 64
    bits, and nothing anywhere said why sixteen.

    The claim the digest carries is that an approval cannot be spent on a later
    call. An attacker who can steer the proposals, which is the premise of
    every other check in this module, needs a collision and not a second
    preimage, so the usable strength is half the width. At 64 bits that is a
    2**32 search. The width is now the whole digest, 256 bits, and these tests
    exist so that a future truncation has to be an argued one rather than a
    slice somebody added back.
    """

    def test_the_digest_is_the_declared_width(self):
        proposal = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        self.assertEqual(len(call_digest(proposal)), CALL_DIGEST_BITS // 4)

    def test_the_declared_width_is_two_hundred_and_fifty_six_bits(self):
        self.assertEqual(CALL_DIGEST_BITS, 256)

    def test_the_declared_width_carries_a_one_hundred_and_twenty_eight_bit_collision_margin(self):
        # The bar, stated as arithmetic rather than as a sentence: a collision
        # costs about 2**(n/2), and the margin this claim needs is 2**128.
        self.assertGreaterEqual(CALL_DIGEST_BITS // 2, 128)

    def test_the_digest_is_not_a_truncation_of_the_underlying_hash(self):
        # Pins the specific regression: a slice of the hex digest.
        proposal = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        canonical = json.dumps(proposal, sort_keys=True, separators=(",", ":"),
                               default=str)
        self.assertEqual(call_digest(proposal),
                         hashlib.sha256(canonical.encode("utf-8")).hexdigest())

    def test_the_held_message_names_the_full_digest_an_approval_must_carry(self):
        # A human reading the held line has to be able to produce the approval
        # from it, so the line carries the whole value and not a prefix of it.
        proposal = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
        message = execute(proposal, Runner())
        self.assertIn(call_digest(proposal), message)
        self.assertTrue(message.rstrip().endswith(call_digest(proposal)))


class TheAddressGuardReadsTheDestinationNotTheSpelling(unittest.TestCase):

    def _allowed(self, ip):
        return validate_tool_call(
            {"tool": "lookup_ip_reputation", "args": {"ip": ip}}).allowed

    def test_an_ipv4_mapped_loopback_address_is_refused(self):
        self.assertFalse(self._allowed("::ffff:127.0.0.1"))

    def test_an_ipv4_mapped_private_address_is_refused(self):
        self.assertFalse(self._allowed("::ffff:10.0.0.5"))
        self.assertFalse(self._allowed("::ffff:192.168.1.1"))

    def test_the_hexadecimal_spelling_of_a_mapped_private_address_is_refused(self):
        """The same address again, written so it does not read as RFC 1918."""
        self.assertFalse(self._allowed("::ffff:0a00:0005"))

    def test_a_six_to_four_address_wrapping_private_space_is_refused(self):
        self.assertFalse(self._allowed("2002:0a00:0005::1"))

    def test_an_octal_encoded_loopback_address_is_refused(self):
        self.assertFalse(self._allowed("0177.0.0.1"))

    def test_an_octal_encoded_private_address_is_refused(self):
        self.assertFalse(self._allowed("010.0.0.1"))

    def test_the_integer_encoding_of_loopback_is_refused(self):
        self.assertFalse(self._allowed("2130706433"))

    def test_an_abbreviated_address_is_refused(self):
        self.assertFalse(self._allowed("127.1"))

    def test_surrounding_whitespace_is_refused_rather_than_stripped(self):
        """Two spellings of one address is one spelling too many."""
        self.assertFalse(self._allowed(" 10.0.0.5"))
        self.assertFalse(self._allowed("10.0.0.5 "))

    def test_link_local_and_reserved_space_are_refused(self):
        self.assertFalse(self._allowed("169.254.169.254"))
        self.assertFalse(self._allowed("fe80::1"))

    def test_a_genuinely_external_address_is_still_allowed(self):
        """The other half. A guard that refuses everything is not a guard."""
        self.assertTrue(self._allowed(EXTERNAL_V4))
        self.assertTrue(self._allowed(EXTERNAL_V6))
        self.assertTrue(self._allowed("198.51.100.7"))

    def test_a_non_string_target_is_refused_rather_than_raising(self):
        self.assertFalse(self._allowed(12345))
        self.assertFalse(self._allowed(None))
        self.assertFalse(self._allowed(""))


class AProposalTooDeepToCanonicaliseIsRefusedBeforeTheAllowlist(unittest.TestCase):
    """`json.dumps` recurses once per level of the object it is handed.

    The row for this module said every validator is a shape test with its own
    explicit bound, and every validator is. `call_digest` is not a validator: a
    proposal carrying a deeply nested value reached RecursionError there, and
    the `repr` it fell back to recursed as well, so the crash came out of
    `validate_tool_call` before the allow-list was consulted at all.
    """

    @staticmethod
    def deep(depth=60000):
        out = []
        cursor = out
        for _ in range(depth):
            deeper = []
            cursor.append(deeper)
            cursor = deeper
        return out

    def test_the_bound_is_stated(self):
        self.assertEqual(MAX_CALL_NESTING, 64)

    def test_the_bound_is_what_refuses_and_not_the_interpreter(self):
        # A hundred levels serialize perfectly well, so only the stated bound
        # can be refusing this one, and a bound quietly raised is not a bound.
        self.assertFalse(validate_tool_call({
            "tool": "lookup_ip_reputation",
            "args": {"ip": EXTERNAL_V4},
            "smuggled": self.deep(100)}).allowed)
        self.assertTrue(validate_tool_call({
            "tool": "lookup_ip_reputation",
            "args": {"ip": EXTERNAL_V4},
            "smuggled": self.deep(10)}).allowed)

    def test_a_smuggled_deep_value_is_refused_rather_than_raising(self):
        decision = validate_tool_call({
            "tool": "lookup_ip_reputation",
            "args": {"ip": "203.0.113.9"},
            "smuggled": self.deep(),
        })
        self.assertFalse(decision.allowed)
        self.assertIn("canonicalised", decision.reason)

    def test_a_deep_argument_is_refused_rather_than_raising(self):
        decision = validate_tool_call({
            "tool": "isolate_endpoint",
            "args": {"device_id": self.deep(), "reason": "confirmed theft"},
        })
        self.assertFalse(decision.allowed)

    def test_a_proposal_that_refers_to_itself_is_refused(self):
        cyclic = {}
        cyclic["self"] = cyclic
        self.assertFalse(validate_tool_call({
            "tool": "lookup_ip_reputation",
            "args": {"ip": "203.0.113.9"},
            "loop": cyclic,
        }).allowed)

    def test_call_digest_still_returns_a_full_digest_over_a_deep_proposal(self):
        self.assertEqual(len(call_digest({"a": self.deep()})), 64)

    def test_execute_refuses_a_proposal_it_cannot_canonicalise(self):
        result = execute({"tool": "lookup_ip_reputation",
                          "args": {"ip": "203.0.113.9"},
                          "smuggled": self.deep()},
                         lambda tool, args: "RAN")
        self.assertTrue(result.startswith("REFUSED"))

    def test_an_ordinary_call_is_still_allowed(self):
        self.assertTrue(validate_tool_call({
            "tool": "lookup_ip_reputation",
            "args": {"ip": "203.0.113.9"}}).allowed)


class AnApprovalNamesOneCallAndNotTwo(unittest.TestCase):
    """The canonical form commits to the type of what it rendered."""

    class Reason(object):
        def __str__(self):
            return "routine maintenance window"

    def test_an_object_and_the_string_it_prints_as_are_different_calls(self):
        with_object = {"tool": "isolate_endpoint",
                       "args": {"device_id": "HOST-42",
                                "reason": AnApprovalNamesOneCallAndNotTwo.Reason()}}
        with_string = {"tool": "isolate_endpoint",
                       "args": {"device_id": "HOST-42",
                                "reason": "routine maintenance window"}}
        self.assertNotEqual(call_digest(with_object), call_digest(with_string))

    def test_an_approval_for_one_does_not_execute_the_other(self):
        def runner(tool, args):
            return "RAN"

        with_object = {"tool": "isolate_endpoint",
                       "args": {"device_id": "HOST-42",
                                "reason": AnApprovalNamesOneCallAndNotTwo.Reason()}}
        with_string = {"tool": "isolate_endpoint",
                       "args": {"device_id": "HOST-42",
                                "reason": "routine maintenance window"}}
        result = execute(with_object, runner, approval=call_digest(with_string))
        self.assertNotEqual(result, "RAN")

    def test_a_value_that_renders_as_its_address_names_no_call(self):
        class Opaque(object):
            pass

        first = {"tool": "isolate_endpoint",
                 "args": {"device_id": "H", "reason": Opaque()}}
        second = {"tool": "isolate_endpoint",
                  "args": {"device_id": "H", "reason": Opaque()}}
        self.assertEqual(call_digest(first), UNCANONICAL_DIGEST)
        self.assertEqual(call_digest(first), call_digest(second))


if __name__ == "__main__":
    unittest.main()
