"""Tests for blackgate/prohibitions.py.

The property under test throughout is that some refusals are not permissions
anybody can grant, and that the code has nowhere to put an override. Four
defects are pinned: a ban written as a policy rule that a senior enough
approval outranked, a ban that ran after the allow-list lookup so editing the
allow-list re-enabled it, unknown tools and unknown categories defaulting to
the permissive arm, and the argument parser treating the token after a boolean
switch as a consumed value and skipping its destination check.

Every tool name here is a neutral placeholder and no real argument appears.
"""

import inspect
import unittest

from blackgate.prohibitions import (
    CATEGORY_GATING,
    RATE_CAPS,
    REGISTRY,
    UNCONDITIONAL_BAN,
    Request,
    Resolution,
    Tool,
    registry_is_complete,
    resolve,
    resolve_with_approval,
)

APPROVAL_LEVELS = ("none", "operator", "ceremony_complete", "client_countersigned",
                   "emergency_override", "root")


class SomeThingsAreNotPermissionsAnybodyCanGrant(unittest.TestCase):
    """The defect: the ban lived in the same precedence table as everything
    else, with approval above it, so the strongest credential was a legal way
    to override an absolute prohibition."""

    def test_a_banned_tool_is_refused(self):
        result = resolve(Request("packet_flood", "shop.example.invalid"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "PROHIBITION")

    def test_no_approval_level_changes_the_answer(self):
        for level in APPROVAL_LEVELS:
            result = resolve_with_approval(
                Request("packet_flood", "shop.example.invalid"), level)
            self.assertFalse(result.allowed, level)
            self.assertEqual(result.gate, "PROHIBITION", level)

    def test_resolve_has_no_parameter_that_could_permit_a_banned_action(self):
        names = set(inspect.signature(resolve).parameters)
        self.assertEqual(names, {"request"})
        for forbidden in ("approval", "override", "force", "allow", "level"):
            self.assertNotIn(forbidden, names)

    def test_the_ban_runs_before_the_allow_list_is_consulted(self):
        # The banned tool is registered on purpose. If the lookup came first,
        # its presence in the registry would be enough to permit it.
        self.assertIn("packet_flood", REGISTRY)
        self.assertEqual(resolve(Request("packet_flood", "shop.example.invalid")).gate,
                         "PROHIBITION")

    def test_adding_a_banned_tool_to_the_registry_does_not_re_enable_it(self):
        REGISTRY["another_flood"] = Tool("another_flood", "RECON",
                                         behaviour_class="denial_of_service")
        try:
            self.assertEqual(resolve(Request("another_flood", "a.example.invalid")).gate,
                             "PROHIBITION")
        finally:
            del REGISTRY["another_flood"]

    def test_the_refusal_names_the_class_rather_than_only_the_tool(self):
        reason = resolve(Request("packet_flood", "shop.example.invalid")).reason
        self.assertIn("denial_of_service", reason)
        self.assertIn("unconditionally", reason)

    def test_every_banned_class_carries_a_written_reason(self):
        for klass, why in UNCONDITIONAL_BAN.items():
            self.assertTrue(why.strip(), klass)
            self.assertGreater(len(why), 30, klass)

    def test_the_banned_classes_include_the_three_that_cannot_be_consented_to(self):
        self.assertIn("denial_of_service", UNCONDITIONAL_BAN)
        self.assertIn("attribution_evasion", UNCONDITIONAL_BAN)
        self.assertIn("novel_exploit_development", UNCONDITIONAL_BAN)


class TheUnknownDefaultPointsAtRefusal(unittest.TestCase):
    def test_a_tool_nobody_registered_is_refused(self):
        result = resolve(Request("mystery_tool", "shop.example.invalid"))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "ALLOWLIST")

    def test_an_empty_tool_name_is_refused(self):
        self.assertFalse(resolve(Request("", "shop.example.invalid")).allowed)

    def test_a_tool_name_that_is_not_a_string_is_refused(self):
        self.assertFalse(resolve(Request(None, "shop.example.invalid")).allowed)

    def test_a_category_with_no_gating_decision_is_refused_rather_than_run(self):
        REGISTRY["odd_tool"] = Tool("odd_tool", "QUANTUM_RECON")
        try:
            result = resolve(Request("odd_tool", "shop.example.invalid"))
            self.assertFalse(result.allowed)
            self.assertEqual(result.gate, "CATEGORY")
            self.assertIn("consequential", result.reason)
        finally:
            del REGISTRY["odd_tool"]

    def test_every_registered_category_carries_an_explicit_decision(self):
        ok, missing = registry_is_complete()
        self.assertTrue(ok, missing)
        self.assertEqual(missing, [])

    def test_the_completeness_check_actually_detects_a_missing_decision(self):
        ok, missing = registry_is_complete({"x": Tool("x", "NOT_A_CATEGORY")})
        self.assertFalse(ok)
        self.assertEqual(missing, ["NOT_A_CATEGORY"])

    def test_no_category_is_left_without_a_gating_answer(self):
        for category, gated in CATEGORY_GATING.items():
            self.assertIn(gated, (True, False), category)

    def test_the_gated_categories_are_the_ones_that_change_or_escalate(self):
        self.assertTrue(CATEGORY_GATING["EXPLOIT"])
        self.assertTrue(CATEGORY_GATING["PERSISTENCE"])
        self.assertTrue(CATEGORY_GATING["CRED_ACCESS"])
        self.assertFalse(CATEGORY_GATING["RECON"])
        self.assertFalse(CATEGORY_GATING["OSINT"])


class OnlyDeclaredValueFlagsConsumeTheNextToken(unittest.TestCase):
    """The defect: the parser assumed the token after a flag was that flag's
    value. A boolean switch consumes nothing, so the token after it was a
    positional that skipped the destination check entirely."""

    def test_a_host_after_a_boolean_switch_is_checked_and_refused(self):
        result = resolve(Request("port_probe", "shop.example.invalid",
                                 ("--no-ping", "bank.example.invalid")))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "DESTINATION")

    def test_a_value_after_a_declared_value_flag_is_not_a_destination(self):
        result = resolve(Request("dns_enum", "shop.example.invalid",
                                 ("--domain", "shop.example.invalid")))
        self.assertTrue(result.allowed)

    def test_a_bare_host_with_no_flag_in_front_of_it_is_checked(self):
        self.assertEqual(resolve(Request("port_probe", "shop.example.invalid",
                                         ("bank.example.invalid",))).gate,
                         "DESTINATION")

    def test_the_engagement_host_itself_is_allowed_as_a_positional(self):
        self.assertTrue(resolve(Request("port_probe", "shop.example.invalid",
                                        ("shop.example.invalid",))).allowed)

    def test_an_address_naming_another_destination_is_refused(self):
        self.assertEqual(resolve(Request("port_probe", "shop.example.invalid",
                                         ("--no-ping", "198.51.100.7"))).gate,
                         "DESTINATION")

    def test_the_refusal_names_both_the_token_and_the_engagement_host(self):
        reason = resolve(Request("port_probe", "shop.example.invalid",
                                 ("bank.example.invalid",))).reason
        self.assertIn("bank.example.invalid", reason)
        self.assertIn("shop.example.invalid", reason)

    def test_a_declared_value_flag_is_separate_from_the_permitted_flag_list(self):
        for tool in REGISTRY.values():
            for flag in tool.value_flags:
                self.assertIn(flag, tool.flags, tool.name)

    def test_a_trailing_value_flag_with_no_value_is_refused(self):
        result = resolve(Request("dns_enum", "shop.example.invalid", ("--domain",)))
        self.assertFalse(result.allowed)
        self.assertIn("no value", result.reason)


class TheFlagSetIsExactRatherThanApproximate(unittest.TestCase):
    def test_an_undeclared_flag_is_refused(self):
        result = resolve(Request("tls_audit", "shop.example.invalid", ("--dump-keys",)))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "FLAG")

    def test_a_flag_that_merely_starts_with_a_permitted_one_is_refused(self):
        self.assertEqual(resolve(Request("tls_audit", "shop.example.invalid",
                                         ("--jsonp",))).gate, "FLAG")

    def test_a_permitted_flag_is_allowed(self):
        self.assertTrue(resolve(Request("tls_audit", "shop.example.invalid",
                                        ("--json",))).allowed)

    def test_a_flag_permitted_for_one_tool_is_not_permitted_for_another(self):
        self.assertTrue(resolve(Request("config_probe", "shop.example.invalid",
                                        ("--read-only",))).allowed)
        self.assertEqual(resolve(Request("tls_audit", "shop.example.invalid",
                                         ("--read-only",))).gate, "FLAG")

    def test_an_inline_value_form_is_matched_on_the_flag_name(self):
        self.assertTrue(resolve(Request("port_probe", "shop.example.invalid",
                                        ("--rate=500",))).allowed)


class TheBanIsOnTheBehaviourNotOnlyOnTheName(unittest.TestCase):
    def test_a_rate_above_the_cap_is_refused(self):
        result = resolve(Request("port_probe", "shop.example.invalid", ("--rate=50000",)))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "RATE_CAP")

    def test_a_rate_at_the_cap_is_allowed(self):
        self.assertTrue(resolve(Request("port_probe", "shop.example.invalid",
                                        ("--rate=1000",))).allowed)

    def test_a_thread_count_above_the_cap_is_refused(self):
        self.assertEqual(resolve(Request("tls_audit", "shop.example.invalid",
                                         ("--threads=200",))).gate, "RATE_CAP")

    def test_a_capped_flag_must_carry_its_value_inline(self):
        result = resolve(Request("port_probe", "shop.example.invalid", ("--rate", "500")))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "RATE_CAP")
        self.assertIn("inline", result.reason)

    def test_a_capped_flag_with_a_value_that_is_not_a_number_is_refused(self):
        self.assertEqual(resolve(Request("port_probe", "shop.example.invalid",
                                         ("--rate=fast",))).gate, "RATE_CAP")

    def test_the_refusal_names_the_cap_it_exceeded(self):
        reason = resolve(Request("port_probe", "shop.example.invalid",
                                 ("--rate=50000",))).reason
        self.assertIn("1000", reason)

    def test_every_cap_is_a_positive_number(self):
        for flag, cap in RATE_CAPS.items():
            self.assertGreater(cap, 0, flag)

    def test_the_caps_are_the_ones_declared_and_none_has_drifted(self):
        """Found by the mutation harness, which multiplied one cap by a
        thousand and watched the suite stay green.

        Written out as literals rather than read from `RATE_CAPS`, because a
        test that loops over the same table the module caps against will agree
        with any value that table happens to hold. The numbers are the contract
        and they belong somewhere a diff has to touch twice.
        """
        self.assertEqual(dict(RATE_CAPS), {
            "--rate": 1000,
            "--threads": 16,
            "--concurrency": 32,
            "--connections": 64,
        })

    def test_every_capped_flag_refuses_a_value_one_above_its_cap(self):
        # The caps that no other test exercised were being carried by nothing
        # at all. This walks every one of them, and it runs the real resolve
        # path rather than the private helper, so it also pins that the flood
        # check happens before the per-tool flag allow-list and therefore
        # applies to a capped flag no tool declares.
        for flag, cap in RATE_CAPS.items():
            over = resolve(Request("port_probe", "shop.example.invalid",
                                   ("%s=%d" % (flag, cap + 1),)))
            self.assertFalse(over.allowed, flag)
            self.assertEqual(over.gate, "RATE_CAP", flag)
            self.assertIn(str(cap), over.reason, flag)

    def test_a_capped_flag_at_exactly_its_cap_is_not_refused_by_the_cap(self):
        # The other side of the boundary. A cap that refuses its own limit is
        # as wrong as one that never fires, and only one of the two is visible
        # in a test that looks at refusals alone.
        for flag, cap in RATE_CAPS.items():
            at_limit = resolve(Request("port_probe", "shop.example.invalid",
                                       ("%s=%d" % (flag, cap),)))
            self.assertNotEqual(at_limit.gate, "RATE_CAP", flag)


class ClearingTheAllowListIsNotPermissionToRun(unittest.TestCase):
    def test_a_consequential_tool_still_needs_the_ceremony(self):
        result = resolve(Request("config_probe", "shop.example.invalid", ("--read-only",)))
        self.assertTrue(result.allowed)
        self.assertTrue(result.gated)

    def test_a_reconnaissance_tool_does_not(self):
        result = resolve(Request("port_probe", "shop.example.invalid", ("--no-ping",)))
        self.assertTrue(result.allowed)
        self.assertFalse(result.gated)

    def test_an_approval_short_of_a_completed_ceremony_is_refused(self):
        for level in ("none", "operator", "client_countersigned"):
            result = resolve_with_approval(
                Request("config_probe", "shop.example.invalid", ("--read-only",)), level)
            self.assertFalse(result.allowed, level)
            self.assertEqual(result.gate, "CEREMONY", level)

    def test_a_completed_ceremony_releases_it(self):
        result = resolve_with_approval(
            Request("config_probe", "shop.example.invalid", ("--read-only",)),
            "ceremony_complete")
        self.assertTrue(result.allowed)

    def test_an_approval_cannot_rescue_a_refusal_from_an_earlier_gate(self):
        result = resolve_with_approval(
            Request("tls_audit", "shop.example.invalid", ("--dump-keys",)),
            "ceremony_complete")
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "FLAG")

    def test_the_rendered_resolution_says_ceremony_required(self):
        rendered = resolve(Request("config_probe", "shop.example.invalid",
                                   ("--read-only",))).render()
        self.assertIn("ceremony required", rendered)

    def test_a_resolution_is_a_plain_record(self):
        self.assertFalse(Resolution(False, "PROHIBITION", "because").gated)


class TheDestinationCheckIsDefaultDeny(unittest.TestCase):
    """The defect found by audit: _LOOKS_LIKE_HOST was a whitelist of host
    shapes, and anything shaped differently skipped the destination check
    entirely and reached the command line. That is the file's own founding
    defect, a host nobody compared against the engagement target, arriving by a
    different door."""

    TARGET = "shop.example.invalid"
    OTHER = "bank.example.invalid"

    def refused(self, token):
        return resolve(Request("port_probe", self.TARGET, (token,)))

    def test_a_trailing_dot_does_not_hide_a_second_host(self):
        self.assertEqual(self.refused("bank.example.invalid.").gate, "DESTINATION")

    def test_an_invisible_character_does_not_hide_a_second_host(self):
        for invisible in ("\u200b", "\u200c", "\u2060", "\u00ad", "\ufeff"):
            token = self.OTHER + invisible
            self.assertEqual(self.refused(token).gate, "DESTINATION", repr(token))

    def test_surrounding_whitespace_does_not_hide_a_second_host(self):
        for token in (" " + self.OTHER, self.OTHER + " ", "\t" + self.OTHER):
            self.assertEqual(self.refused(token).gate, "DESTINATION", repr(token))

    def test_a_url_spelling_does_not_hide_a_second_host(self):
        self.assertEqual(self.refused("http://bank.example.invalid/").gate, "DESTINATION")

    def test_a_port_suffix_does_not_hide_a_second_host(self):
        self.assertEqual(self.refused("bank.example.invalid:443").gate, "DESTINATION")

    def test_a_userinfo_prefix_does_not_hide_a_second_host(self):
        self.assertEqual(
            self.refused("shop.example.invalid@bank.example.invalid").gate, "DESTINATION")

    def test_a_single_label_internal_name_is_still_a_destination(self):
        self.assertEqual(self.refused("bankexample").gate, "DESTINATION")

    def test_the_engagement_host_is_still_allowed_in_its_ordinary_spellings(self):
        for token in (self.TARGET, self.TARGET + ".", " " + self.TARGET,
                      "SHOP.EXAMPLE.INVALID"):
            self.assertTrue(resolve(Request("port_probe", self.TARGET, (token,))).allowed,
                            repr(token))

    def test_a_plain_count_is_not_treated_as_a_destination(self):
        self.assertTrue(resolve(Request("port_probe", self.TARGET,
                                        ("--no-ping", "100"))).allowed)

    def test_a_declared_value_flag_cannot_smuggle_a_host_as_its_value(self):
        result = resolve(Request("port_probe", self.TARGET,
                                 ("--top-ports", "bank.example.invalid")))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "DESTINATION")

    def test_a_declared_value_flag_still_takes_its_ordinary_value(self):
        self.assertTrue(resolve(Request("port_probe", self.TARGET,
                                        ("--top-ports", "100"))).allowed)
        self.assertTrue(resolve(Request("dns_enum", self.TARGET,
                                        ("--domain", self.TARGET))).allowed)


class TheRateCapCannotBeClearedWithAnEmptyValue(unittest.TestCase):
    """The defect found by audit: `--rate=` satisfied the "carries its value
    inline" rule with an empty value, and _is_flood_argument returned None for
    it, so the flag reached the command line with no cap checked at all."""

    def test_a_capped_flag_with_an_empty_inline_value_is_refused(self):
        for token in ("--rate=", "--threads=", "--concurrency=", "--connections="):
            tool = "port_probe" if token == "--rate=" else "tls_audit"
            if token not in REGISTRY[tool].flags:
                continue
            result = resolve(Request(tool, "shop.example.invalid", (token,)))
            self.assertFalse(result.allowed, token)
            self.assertEqual(result.gate, "RATE_CAP", token)

    def test_a_negative_rate_is_refused(self):
        result = resolve(Request("port_probe", "shop.example.invalid", ("--rate=-1",)))
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "RATE_CAP")

    def test_a_value_that_is_only_a_number_to_python_is_refused(self):
        # int() accepts underscores and non-ASCII digit forms. The tool being
        # invoked does not, so the cap has to be checked on the bytes it sees.
        for token in ("--rate=5_0000", "--rate=\uff15\uff10\uff10\uff10\uff10",
                      "--rate=\u0665\u0660\u0660\u0660\u0660"):
            result = resolve(Request("port_probe", "shop.example.invalid", (token,)))
            self.assertFalse(result.allowed, token)
            self.assertEqual(result.gate, "RATE_CAP", token)


    def test_a_very_long_digit_string_is_refused_without_parsing_it(self):
        # int() on a decimal string is quadratic below CPython 3.7.14/3.8.14/
        # 3.9.14/3.10.7 (CVE-2020-10735), and this interpreter may be one of
        # them. Measured at HEAD through resolve: 400,000 digits took 3.968s.
        # The threshold is 1.0s rather than something tight because this is a
        # loaded shared host; the fixed path is bounded before any parse and
        # returns in well under a millisecond, so the headroom is three orders
        # of magnitude and the test is not flaky.
        import time
        arg = "--rate=" + "9" * 400000
        start = time.time()
        result = resolve(Request("port_probe", "shop.example.invalid", (arg,)))
        elapsed = time.time() - start
        self.assertFalse(result.allowed)
        self.assertEqual(result.gate, "RATE_CAP")
        self.assertLess(elapsed, 1.0)

    def test_an_ordinary_numeric_value_still_parses_exactly_as_before(self):
        self.assertTrue(resolve(Request("port_probe", "shop.example.invalid",
                                        ("--rate=1000",))).allowed)
        self.assertTrue(resolve(Request("port_probe", "shop.example.invalid",
                                        ("--rate=0",))).allowed)
        self.assertEqual(resolve(Request("port_probe", "shop.example.invalid",
                                         ("--rate=1001",))).gate, "RATE_CAP")
        self.assertEqual(resolve(Request("tls_audit", "shop.example.invalid",
                                         ("--threads=16",))).allowed, True)

    def test_a_ten_digit_value_is_still_parsed_and_capped_on_its_number(self):
        result = resolve(Request("port_probe", "shop.example.invalid",
                                 ("--rate=9999999999",)))
        self.assertEqual(result.gate, "RATE_CAP")
        self.assertIn("above the cap", result.reason)

    def test_an_ordinary_rate_under_the_cap_still_resolves(self):
        self.assertTrue(resolve(Request("port_probe", "shop.example.invalid",
                                        ("--rate=500",))).allowed)


class AnUnreadableArgumentListIsARefusal(unittest.TestCase):
    def test_arguments_that_cannot_be_iterated_refuse_rather_than_raise(self):
        for args in (None, 0, 1.5):
            result = resolve(Request("port_probe", "shop.example.invalid", args))
            self.assertFalse(result.allowed, repr(args))
            self.assertEqual(result.gate, "ARGS", repr(args))




class FlagValueRepresentationsShareDestinationChecks(unittest.TestCase):
    def test_domain_values_are_checked_in_both_forms(self):
        target = "shop.example.invalid"
        for value in ("bank.example.invalid", "0x7f000001", "http://bank.example.invalid", "", "--json"):
            for args in (("--domain=" + value,), ("--domain", value)):
                with self.subTest(args=args):
                    self.assertFalse(resolve(Request("dns_enum", target, args)).allowed)
        for args in (("--domain=" + target,), ("--domain", target.upper() + ".")):
            self.assertTrue(resolve(Request("dns_enum", target, args)).allowed)
        self.assertFalse(resolve(Request("dns_enum", target,
            ("--domain=" + target, "--domain=bank.example.invalid"))).allowed)
        for empty in (None, "", " "):
            self.assertFalse(resolve(Request("dns_enum", empty, ("--domain=none",))).allowed)

    def test_inline_values_keep_declared_value_semantics(self):
        target = "shop.example.invalid"
        for tool, arg in (("config_probe", "--report=summary"), ("port_probe", "--top-ports=100"), ("port_probe", "--rate=500")):
            self.assertTrue(resolve(Request(tool, target, (arg,))).allowed)
        for tool, arg in (("tls_audit", "--json=bank.example.invalid"), ("port_probe", "--top-ports=bank.example.invalid"), ("port_probe", "--top-ports=0x7f000001"), ("port_probe", "--top-ports=0"), ("port_probe", "--top-ports=65536"), ("port_probe", "--top-ports=words")):
            self.assertFalse(resolve(Request(tool, target, (arg,))).allowed)


if __name__ == "__main__":
    unittest.main()
