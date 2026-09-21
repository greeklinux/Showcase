"""Tests for blackgate/scope_gate.py.

The property under test throughout is that the gate stack can only subtract,
that it names the gate which refused, and that everything it cannot read is a
refusal. Three specific defects are pinned: a never-target backstop that is
evaluated before the scope rather than out of it, address normalization that is
directional (folded on the deny surface, not folded on the allow surface), and
label-boundary host matching rather than a bare suffix test.

All hosts are RFC 5737 documentation addresses or .invalid names. No real host,
tenant, client or operator appears anywhere.
"""

import unittest

from blackgate.scope_gate import (
    ALWAYS_BLOCKED_NETS,
    CONSEQUENTIAL,
    GATES,
    Decision,
    EngagementScope,
    Gate,
    ScopeError,
    matches_entry,
    normalize_host,
    reject_unstable,
    sign_scope,
    signed_scope,
    verify_scope,
)

KEY = b"test scope signing key"
NEVER = ("203.0.113.0/24", "mycompany.invalid")


def a_scope(**over):
    fields = dict(
        engagement_id="ENG-TEST",
        targets=("198.51.100.0/24", "shop.example.invalid", "*.lab.example.invalid"),
        categories=("RECON", "CRED_ACCESS"),
        valid_from=100,
        valid_until=200,
    )
    fields.update(over)
    return signed_scope(EngagementScope(**fields), KEY)


def a_gate(**over):
    fields = dict(never_target=NEVER, scope=a_scope(), key=KEY)
    fields.update(over)
    return Gate(**fields)


class TheGateStackRunsInOneFixedOrder(unittest.TestCase):
    def test_the_declared_order_is_the_order_the_code_checks(self):
        self.assertEqual(GATES[0], "FREEZE")
        self.assertEqual(GATES[1], "NEVER_TARGET")
        self.assertEqual(GATES[2], "SELF_TARGET")
        self.assertEqual(GATES[-1], "TARGET_ALLOWLIST")

    def test_a_freeze_refuses_before_anything_else_is_consulted(self):
        gate = a_gate(frozen=True)
        decision = gate.authorize("198.51.100.20", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "FREEZE")

    def test_a_freeze_refuses_even_with_no_scope_loaded(self):
        gate = Gate(frozen=True, scope=None, key=b"")
        self.assertEqual(gate.authorize("198.51.100.20", "RECON", now=150).gate, "FREEZE")

    def test_every_decision_names_the_gate_that_made_it(self):
        gate = a_gate()
        for target, category in [("198.51.100.20", "RECON"), ("203.0.113.9", "RECON"),
                                 ("127.0.0.1", "RECON"), ("other.invalid", "RECON"),
                                 ("shop.example.invalid", "PERSISTENCE")]:
            decision = gate.authorize(target, category, now=150)
            self.assertIn(decision.gate, GATES)


class TheNeverTargetBackstopIsNotOverridable(unittest.TestCase):
    """The defect: a self-target guard that covered loopback and private ranges
    said nothing about the operator's own public assets, so one reaching a
    signed scope was authorized by every check downstream."""

    def test_an_operator_owned_host_is_refused(self):
        decision = a_gate().authorize("203.0.113.9", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_a_signed_scope_that_lists_it_does_not_authorize_it(self):
        gate = a_gate(scope=a_scope(targets=("203.0.113.0/24",)))
        decision = gate.authorize("203.0.113.9", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_the_backstop_runs_before_the_signature_is_checked(self):
        # An unsigned, unverifiable scope would refuse at SIGNATURE. A
        # never-target host refuses earlier than that, which is the ordering
        # claim: the backstop does not depend on the document being readable.
        gate = Gate(never_target=NEVER, scope=None, key=b"")
        self.assertEqual(gate.authorize("203.0.113.9", "RECON", now=150).gate,
                         "NEVER_TARGET")

    def test_a_subdomain_of_an_operator_owned_domain_is_refused(self):
        self.assertEqual(a_gate().authorize("mail.mycompany.invalid", "RECON", now=150).gate,
                         "NEVER_TARGET")

    def test_the_reason_says_which_entry_matched_and_that_it_cannot_be_overridden(self):
        reason = a_gate().authorize("203.0.113.9", "RECON", now=150).reason
        self.assertIn("203.0.113.0/24", reason)
        self.assertIn("not overridable", reason)


class AddressNormalizationIsDirectional(unittest.TestCase):
    """The defect: comparing address versions before folding the IPv4-mapped
    IPv6 form let the mapped spelling past every version 4 deny entry. The
    correct answer is the opposite on the allow surface, where a mapped literal
    must not be authorized by a version 4 entry."""

    def test_the_mapped_spelling_is_caught_by_a_version_four_deny_entry(self):
        self.assertTrue(matches_entry("203.0.113.0/24", "::ffff:203.0.113.9",
                                      fold_mapped=True))

    def test_the_mapped_spelling_is_refused_by_the_never_target_gate(self):
        decision = a_gate().authorize("::ffff:203.0.113.9", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_the_mapped_spelling_is_not_authorized_by_a_version_four_allow_entry(self):
        self.assertFalse(matches_entry("198.51.100.0/24", "::ffff:198.51.100.20",
                                       fold_mapped=False))

    def test_the_allow_surface_refuses_the_mapped_spelling_of_an_in_scope_host(self):
        decision = a_gate().authorize("::ffff:198.51.100.20", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "TARGET_ALLOWLIST")

    def test_the_plain_spelling_of_the_same_host_is_authorized(self):
        self.assertTrue(a_gate().authorize("198.51.100.20", "RECON", now=150).allowed)

    def test_a_mapped_deny_entry_still_catches_the_plain_spelling(self):
        self.assertTrue(matches_entry("::ffff:203.0.113.9", "203.0.113.9", fold_mapped=True))


class HostMatchingIsOnALabelBoundary(unittest.TestCase):
    """The defect: host.endswith(base) authorizes anything ending in the right
    letters, including a name nobody in the engagement owns."""

    def test_the_apex_matches_a_bare_entry(self):
        self.assertTrue(matches_entry("example.invalid", "example.invalid", fold_mapped=False))

    def test_a_subdomain_matches_a_bare_entry(self):
        self.assertTrue(matches_entry("example.invalid", "shop.example.invalid",
                                      fold_mapped=False))

    def test_a_name_that_merely_ends_in_the_same_letters_does_not_match(self):
        self.assertFalse(matches_entry("example.invalid", "notexample.invalid",
                                       fold_mapped=False))

    def test_a_name_that_carries_the_base_as_a_prefix_does_not_match(self):
        self.assertFalse(matches_entry("example.invalid", "example.invalid.other.invalid",
                                       fold_mapped=False))

    def test_the_gate_refuses_the_suffix_trap(self):
        self.assertFalse(a_gate().authorize("notexample.invalid", "RECON", now=150).allowed)

    def test_a_leading_dot_entry_behaves_like_the_bare_form(self):
        self.assertTrue(matches_entry(".example.invalid", "example.invalid", fold_mapped=False))
        self.assertTrue(matches_entry(".example.invalid", "a.example.invalid",
                                      fold_mapped=False))

    def test_a_wildcard_entry_matches_subdomains(self):
        self.assertTrue(matches_entry("*.lab.example.invalid", "dev.lab.example.invalid",
                                      fold_mapped=False))

    def test_a_wildcard_entry_does_not_match_the_apex(self):
        self.assertFalse(matches_entry("*.lab.example.invalid", "lab.example.invalid",
                                       fold_mapped=False))

    def test_the_gate_refuses_the_apex_of_a_wildcard_entry(self):
        decision = a_gate().authorize("lab.example.invalid", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "TARGET_ALLOWLIST")

    def test_an_address_literal_is_never_matched_by_a_name_entry(self):
        self.assertFalse(matches_entry("example.invalid", "198.51.100.20", fold_mapped=False))

    def test_a_name_is_never_matched_by_an_address_entry(self):
        self.assertFalse(matches_entry("198.51.100.0/24", "shop.example.invalid",
                                       fold_mapped=False))

    def test_an_empty_entry_matches_nothing(self):
        self.assertFalse(matches_entry("", "shop.example.invalid", fold_mapped=False))

    def test_matching_is_case_and_trailing_dot_insensitive(self):
        self.assertEqual(normalize_host("  SHOP.Example.INVALID. "), "shop.example.invalid")
        self.assertTrue(a_gate().authorize("SHOP.example.invalid.", "RECON", now=150).allowed)


class TheAbsoluteSelfTargetSetHasNoOverride(unittest.TestCase):
    def test_loopback_is_refused(self):
        self.assertEqual(a_gate().authorize("127.0.0.1", "RECON", now=150).gate, "SELF_TARGET")

    def test_cloud_instance_metadata_is_refused(self):
        self.assertEqual(a_gate().authorize("169.254.169.254", "RECON", now=150).gate,
                         "SELF_TARGET")

    def test_the_management_overlay_range_is_refused(self):
        self.assertEqual(a_gate().authorize("100.64.0.1", "RECON", now=150).gate, "SELF_TARGET")

    def test_the_name_localhost_is_refused(self):
        self.assertEqual(a_gate().authorize("localhost", "RECON", now=150).gate, "SELF_TARGET")

    def test_a_signed_scope_listing_loopback_does_not_authorize_it(self):
        gate = a_gate(scope=a_scope(targets=("127.0.0.1",)))
        self.assertEqual(gate.authorize("127.0.0.1", "RECON", now=150).gate, "SELF_TARGET")

    def test_every_declared_absolute_range_is_parseable(self):
        for entry in ALWAYS_BLOCKED_NETS:
            self.assertTrue(matches_entry(entry, entry.split("/")[0], fold_mapped=True), entry)


class TheSignatureCoversWhatTheScopeSays(unittest.TestCase):
    def test_a_correctly_signed_scope_verifies(self):
        self.assertTrue(verify_scope(a_scope(), KEY))

    def test_a_scope_with_no_signature_does_not_verify(self):
        self.assertFalse(verify_scope(EngagementScope("ENG-TEST"), KEY))

    def test_a_scope_verified_with_the_wrong_key_does_not_verify(self):
        self.assertFalse(verify_scope(a_scope(), b"a different key"))

    def test_a_host_appended_after_signing_invalidates_the_scope(self):
        scope = a_scope()
        tampered = EngagementScope(
            engagement_id=scope.engagement_id,
            targets=scope.targets + ("bank.example.invalid",),
            categories=scope.categories, valid_from=scope.valid_from,
            valid_until=scope.valid_until, signature=scope.signature)
        self.assertFalse(verify_scope(tampered, KEY))
        gate = a_gate(scope=tampered)
        self.assertEqual(gate.authorize("bank.example.invalid", "RECON", now=150).gate,
                         "SIGNATURE")

    def test_a_widened_window_invalidates_the_scope(self):
        scope = a_scope()
        tampered = EngagementScope(
            engagement_id=scope.engagement_id, targets=scope.targets,
            categories=scope.categories, valid_from=0, valid_until=99999,
            signature=scope.signature)
        self.assertFalse(verify_scope(tampered, KEY))

    def test_a_gate_with_no_key_refuses_at_the_signature(self):
        gate = a_gate(key=b"")
        self.assertEqual(gate.authorize("198.51.100.20", "RECON", now=150).gate, "SIGNATURE")

    def test_the_signature_is_stable_across_target_ordering(self):
        one = EngagementScope("ENG", ("a.invalid", "b.invalid"), ("RECON",), 1, 2)
        two = EngagementScope("ENG", ("b.invalid", "a.invalid"), ("RECON",), 1, 2)
        self.assertEqual(sign_scope(one, KEY), sign_scope(two, KEY))


class ByteStabilityIsEnforcedRatherThanHoped(unittest.TestCase):
    """The defect: two implementations that both verify a scope did not agree
    on the signed bytes for some characters, so a valid scope failed
    verification on one side, which is the kind of failure that gets fixed by
    loosening the check."""

    def test_printable_ascii_is_accepted(self):
        reject_unstable("shop.example.invalid", "RECON", "ENG-2026-014")

    def test_a_control_character_is_refused(self):
        with self.assertRaises(ScopeError):
            reject_unstable("shop\nexample.invalid")

    def test_the_line_separator_is_refused(self):
        with self.assertRaises(ScopeError):
            reject_unstable("shop example.invalid")

    def test_a_codepoint_with_a_disputed_lowercase_form_is_refused(self):
        with self.assertRaises(ScopeError):
            reject_unstable("İstanbul.invalid")
        with self.assertRaises(ScopeError):
            reject_unstable("straße.invalid")

    def test_the_message_names_the_codepoint_and_the_remedy(self):
        try:
            reject_unstable("münchen.invalid")
        except ScopeError as exc:
            self.assertIn("U+00FC", str(exc))
            self.assertIn("punycode", str(exc))
        else:
            self.fail("expected a ScopeError")

    def test_a_scope_that_cannot_be_canonicalized_is_denied_rather_than_raising(self):
        scope = EngagementScope("ENG ", ("a.invalid",), ("RECON",), 1, 2,
                                signature="deadbeef")
        self.assertFalse(verify_scope(scope, KEY))

    def test_a_host_carrying_an_unstable_character_cannot_be_normalized(self):
        self.assertIsNone(normalize_host("münchen.invalid"))


class EverythingUnreadableIsARefusal(unittest.TestCase):
    def test_a_target_that_is_not_a_string_is_refused(self):
        decision = a_gate().authorize(None, "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_an_empty_target_is_refused(self):
        self.assertFalse(a_gate().authorize("   ", "RECON", now=150).allowed)

    def test_an_integer_encoded_address_is_not_treated_as_a_hostname(self):
        self.assertFalse(matches_entry("3232235781", "3232235781", fold_mapped=False))

    def test_an_octal_encoded_address_is_not_treated_as_a_hostname(self):
        self.assertFalse(matches_entry("010.0.0.1", "010.0.0.1", fold_mapped=False))

    def test_an_empty_target_list_authorizes_nothing(self):
        gate = a_gate(scope=a_scope(targets=()))
        decision = gate.authorize("shop.example.invalid", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "TARGET_ALLOWLIST")

    def test_an_empty_category_list_authorizes_nothing(self):
        gate = a_gate(scope=a_scope(categories=()))
        self.assertEqual(gate.authorize("shop.example.invalid", "RECON", now=150).gate,
                         "CATEGORY")

    def test_no_scope_at_all_is_refused_by_name(self):
        gate = Gate(never_target=NEVER, scope=None, key=KEY)
        self.assertEqual(gate.authorize("shop.example.invalid", "RECON", now=150).gate,
                         "SCOPE_PRESENT")


class TheWindowAndTheCategoryAreBothChecked(unittest.TestCase):
    def test_a_call_before_the_window_is_refused(self):
        self.assertEqual(a_gate().authorize("198.51.100.20", "RECON", now=99).gate, "WINDOW")

    def test_a_call_after_the_window_is_refused(self):
        self.assertEqual(a_gate().authorize("198.51.100.20", "RECON", now=201).gate, "WINDOW")

    def test_both_edges_of_the_window_are_inclusive(self):
        self.assertTrue(a_gate().authorize("198.51.100.20", "RECON", now=100).allowed)
        self.assertTrue(a_gate().authorize("198.51.100.20", "RECON", now=200).allowed)

    def test_a_category_outside_the_scope_is_refused(self):
        self.assertEqual(a_gate().authorize("shop.example.invalid", "PERSISTENCE",
                                            now=150).gate, "CATEGORY")

    def test_category_matching_is_case_insensitive(self):
        self.assertTrue(a_gate().authorize("shop.example.invalid", "recon", now=150).allowed)


class ClearingTheGateIsNotPermissionToRun(unittest.TestCase):
    def test_a_consequential_category_still_requires_the_ceremony(self):
        decision = a_gate().authorize("shop.example.invalid", "CRED_ACCESS", now=150)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.needs_ceremony)

    def test_a_reconnaissance_category_does_not(self):
        decision = a_gate().authorize("198.51.100.20", "RECON", now=150)
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.needs_ceremony)

    def test_every_consequential_category_is_one_that_changes_or_escalates(self):
        self.assertIn("EXPLOIT", CONSEQUENTIAL)
        self.assertIn("PERSISTENCE", CONSEQUENTIAL)
        self.assertNotIn("RECON", CONSEQUENTIAL)
        self.assertNotIn("OSINT", CONSEQUENTIAL)

    def test_the_rendered_decision_says_ceremony_required(self):
        decision = a_gate().authorize("shop.example.invalid", "CRED_ACCESS", now=150)
        self.assertIn("ceremony required", decision.render())

    def test_a_refusal_renders_as_refuse_and_names_its_gate(self):
        rendered = a_gate().authorize("203.0.113.9", "RECON", now=150).render()
        self.assertTrue(rendered.startswith("REFUSE"))
        self.assertIn("NEVER_TARGET", rendered)

    def test_a_decision_is_a_plain_record_with_no_hidden_state(self):
        decision = Decision(True, "TARGET_ALLOWLIST", "ok")
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.needs_ceremony)


class AnAddressCannotBeSpelledPastTheDenySurface(unittest.TestCase):
    """The defect found by audit: normalize_host accepted any printable ASCII
    string, and matches_entry decided "address or name" by whether ipaddress
    could parse it. So every spelling ipaddress refuses was treated as a name,
    which no address entry can ever match, and was then matched literally
    against the allow-list. A scope listing the spelling authorized it, which
    is exactly what the absolute blocked set exists to make impossible."""

    def _gate_listing(self, host):
        return Gate(never_target=NEVER, scope=a_scope(targets=(host,)), key=KEY)

    def test_loopback_in_its_bracketed_form_is_refused(self):
        self.assertFalse(self._gate_listing("[::1]").authorize("[::1]", "RECON",
                                                               now=150).allowed)

    def test_loopback_with_a_port_suffix_is_refused(self):
        self.assertFalse(self._gate_listing("127.0.0.1:80")
                         .authorize("127.0.0.1:80", "RECON", now=150).allowed)

    def test_loopback_in_its_short_form_is_refused(self):
        for spelling in ("127.1", "127.0.1", "0x7f.0.0.1"):
            self.assertFalse(self._gate_listing(spelling)
                             .authorize(spelling, "RECON", now=150).allowed, spelling)

    def test_cloud_instance_metadata_with_a_port_is_refused(self):
        self.assertFalse(self._gate_listing("169.254.169.254:80")
                         .authorize("169.254.169.254:80", "RECON", now=150).allowed)

    def test_an_operator_owned_host_cannot_be_reached_by_respelling_it(self):
        for spelling in ("203.0.113.9:443", "[203.0.113.9]", "203.0.113.09",
                         "[::ffff:203.0.113.9]", "::203.0.113.9",
                         "0:0:0:0:0:0:cb00:7109", "mycompany.invalid:443",
                         "http://mycompany.invalid/",
                         "mycompany.invalid@shop.example.invalid"):
            decision = self._gate_listing(spelling).authorize(spelling, "RECON", now=150)
            self.assertFalse(decision.allowed, spelling)

    def test_the_version_four_compatible_spelling_folds_on_the_deny_surface(self):
        self.assertTrue(matches_entry("203.0.113.0/24", "::203.0.113.9", fold_mapped=True))

    def test_the_nat64_spelling_folds_on_the_deny_surface(self):
        self.assertTrue(matches_entry("203.0.113.0/24", "64:ff9b::203.0.113.9",
                                      fold_mapped=True))

    def test_folding_does_not_turn_loopback_into_a_version_four_address(self):
        # ::1 embeds 0.0.0.1 and does not mean it, so the fold must not fire.
        self.assertFalse(matches_entry("0.0.0.1/32", "::1", fold_mapped=True))
        self.assertTrue(matches_entry("::1/128", "::1", fold_mapped=True))

    def test_the_allow_surface_still_does_not_fold(self):
        self.assertFalse(matches_entry("203.0.113.0/24", "::203.0.113.9",
                                       fold_mapped=False))

    def test_a_name_whose_last_label_is_numeric_is_not_a_name(self):
        self.assertIsNone(normalize_host("127.1"))
        self.assertIsNone(normalize_host("shop.example.1"))

    def test_a_real_name_and_a_real_address_still_normalize(self):
        self.assertEqual(normalize_host("shop.example.invalid"), "shop.example.invalid")
        self.assertEqual(normalize_host("198.51.100.20"), "198.51.100.20")
        self.assertEqual(normalize_host("::ffff:198.51.100.20"), "::ffff:198.51.100.20")

    def test_a_host_longer_than_a_host_can_be_is_refused(self):
        self.assertIsNone(normalize_host("a" * 254 + ".invalid"))


class TheBackstopIsNotDisabledByATypo(unittest.TestCase):
    """The defect found by audit: Gate(never_target=("mycompany.invalid")) is a
    string, not a one-tuple, and iterating a string yields single characters,
    none of which ever match a host. The backstop silently protected nothing."""

    def test_a_never_target_written_without_its_trailing_comma_still_applies(self):
        gate = Gate(never_target=("mycompany.invalid"),
                    scope=a_scope(targets=("mycompany.invalid",)), key=KEY)
        decision = gate.authorize("mycompany.invalid", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_an_entry_that_is_not_a_string_refuses_rather_than_matching_nothing(self):
        for shape in ((None,), (0,), ("",), ({},)):
            gate = Gate(never_target=shape,
                        scope=a_scope(targets=("mycompany.invalid",)), key=KEY)
            decision = gate.authorize("mycompany.invalid", "RECON", now=150)
            self.assertFalse(decision.allowed, shape)
            self.assertEqual(decision.gate, "NEVER_TARGET", shape)

    def test_an_unreadable_backstop_is_named_as_unreadable(self):
        gate = Gate(never_target=5, scope=a_scope(), key=KEY)
        decision = gate.authorize("198.51.100.20", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertIn("could not be read", decision.reason)

    def test_no_backstop_configured_is_still_an_empty_backstop(self):
        gate = Gate(never_target=(), scope=a_scope(), key=KEY)
        self.assertTrue(gate.authorize("198.51.100.20", "RECON", now=150).allowed)

    def test_a_category_list_written_without_its_trailing_comma_is_one_entry(self):
        gate = Gate(never_target=NEVER, scope=a_scope(categories=("RECON")), key=KEY)
        self.assertTrue(gate.authorize("198.51.100.20", "RECON", now=150).allowed)
        self.assertEqual(gate.authorize("198.51.100.20", "R", now=150).gate, "CATEGORY")


class NoInputMakesTheGateRaiseInsteadOfRefusing(unittest.TestCase):
    """An uncaught exception out of a gate is a fail-open path: every caller
    that wraps the gate in try/except reads it as the absence of a refusal."""

    def test_a_signature_that_is_not_a_digest_denies_rather_than_raising(self):
        for signature in (b"deadbeef", "d\u00e9adbeef", ["x"], 5, None):
            scope = EngagementScope("E", ("shop.example.invalid",), ("RECON",),
                                    1, 9, signature)
            self.assertFalse(verify_scope(scope, KEY), repr(signature))
            decision = Gate(never_target=NEVER, scope=scope, key=KEY).authorize(
                "shop.example.invalid", "RECON", now=5)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.gate, "SIGNATURE")

    def test_a_key_that_is_not_bytes_denies_rather_than_raising(self):
        gate = Gate(never_target=NEVER, scope=a_scope(), key="a string key")
        self.assertEqual(gate.authorize("198.51.100.20", "RECON", now=150).gate,
                         "SIGNATURE")

    def test_a_scope_whose_targets_are_not_a_list_denies_rather_than_raising(self):
        scope = EngagementScope("E", 5, ("RECON",), 1, 9, "deadbeef")
        self.assertFalse(verify_scope(scope, KEY))

    def test_a_tick_that_is_not_a_number_refuses_at_the_window(self):
        for now in (None, "150", [], b"150"):
            decision = a_gate().authorize("198.51.100.20", "RECON", now=now)
            self.assertFalse(decision.allowed, repr(now))
            self.assertEqual(decision.gate, "WINDOW", repr(now))

    def test_a_window_whose_bounds_are_not_numbers_refuses(self):
        gate = Gate(never_target=NEVER, scope=a_scope(valid_from="100"), key=KEY)
        decision = gate.authorize("198.51.100.20", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "WINDOW")
        self.assertIn("could not be evaluated", decision.reason)


class TheGateCannotBeHungByTheHostItIsGiven(unittest.TestCase):
    """The defect found by audit: _NONCANONICAL_ADDR ended `[\d.]*\d+$`, two
    quantifiers that match the same characters, so a failing string of digits
    and dots was re-partitioned quadratically. 64 KB of it took 7.2 seconds in
    the engine and 19.7 seconds through authorize, which runs it once per list
    entry. A gate an attacker-named host can hang is a denial of service
    against the gate."""

    def test_a_long_run_of_digits_and_dots_does_not_hang_the_matcher(self):
        import time
        hostile = "0" + "1" * 40000 + "." + "1" * 40000 + "x"
        start = time.time()
        a_gate().authorize(hostile, "RECON", now=150)
        self.assertLess(time.time() - start, 1.0)

    def test_an_oversized_host_is_refused_before_it_is_walked(self):
        import time
        start = time.time()
        decision = a_gate().authorize("a" * (12 * 1024 * 1024), "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertLess(time.time() - start, 1.0)




class HexadecimalAddressesCannotMasqueradeAsHostnames(unittest.TestCase):
    def test_signed_scope_cannot_authorize_hexadecimal_address_aliases(self):
        for host in ("0x7f000001", "0X7F000001.", "0xa9fea9fe", "0x7f.0.0.1", "0x7f.0x0.0x0.0x1", "127.0.0.0x1"):
            with self.subTest(host=host):
                self.assertIsNone(normalize_host(host))
                self.assertFalse(Gate(scope=a_scope(targets=(host,)), key=KEY).authorize(host, "RECON", 150).allowed)
        for host in ("0x7f.example.invalid", "0xcorp", "203.0.113.7"):
            self.assertEqual(normalize_host(host), host)


class EverySpellingThatReachesAnOperatorAssetIsDenied(unittest.TestCase):
    """The defect: two translation prefixes carried a version 4 address past
    the backstop the gate calls not overridable.

    `_deny_probes` folded `::ffff:a.b.c.d`, `::a.b.c.d` and the NAT64 prefix,
    and stopped there. 6to4 carries the address in the second and third
    hextets of `2002::/16` and Teredo carries it bitwise inverted in the last
    two of `2001:0::/32`, so neither is inside any of those prefixes and a
    never-target entry of `203.0.113.0/24` did not reach either spelling. The
    sibling module `ai_security/llm_output_validator.py` already folded both,
    so the two files disagreed about which addresses one string reaches.
    """

    # 203.0.113.9 is 0xCB007109, which is cb00:7109 in 6to4 and 34ff:8ef6
    # inverted in Teredo.
    SIXTOFOUR = "2002:cb00:7109::"
    TEREDO = "2001:0:4136:e378:8000:63bf:34ff:8ef6"

    def test_the_backstop_reaches_the_6to4_spelling(self):
        self.assertTrue(matches_entry("203.0.113.0/24", self.SIXTOFOUR,
                                      fold_mapped=True))

    def test_the_backstop_reaches_the_teredo_spelling(self):
        self.assertTrue(matches_entry("203.0.113.0/24", self.TEREDO,
                                      fold_mapped=True))

    def test_the_gate_refuses_the_6to4_spelling_by_name(self):
        gate = a_gate(scope=a_scope(targets=("2002::/16",)))
        decision = gate.authorize(self.SIXTOFOUR, "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_the_gate_refuses_the_teredo_spelling_by_name(self):
        gate = a_gate(scope=a_scope(targets=("2001::/16",)))
        decision = gate.authorize(self.TEREDO, "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_loopback_reached_through_6to4_is_a_self_target(self):
        gate = a_gate(scope=a_scope(targets=("2002::/16",)))
        decision = gate.authorize("2002:7f00:1::", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "SELF_TARGET")

    def test_the_allow_surface_does_not_fold_them(self):
        # The deny list is a floor and the allow list a ceiling, so a version 4
        # allowance never grants its translated spellings.
        self.assertFalse(matches_entry("203.0.113.0/24", self.SIXTOFOUR,
                                       fold_mapped=False))
        self.assertFalse(matches_entry("203.0.113.0/24", self.TEREDO,
                                       fold_mapped=False))

    def test_an_ordinary_documentation_address_is_not_folded_by_accident(self):
        # 2001:db8::/32 is the documentation range, not the Teredo prefix, and
        # widening the deny surface must not start matching it.
        self.assertFalse(matches_entry("203.0.113.0/24", "2001:db8::1",
                                       fold_mapped=True))
        self.assertFalse(matches_entry("127.0.0.0/8", "2001:db8::1",
                                       fold_mapped=True))

class TheGateKeyIsNotInTheRepr(unittest.TestCase):
    """A gate is exactly the object a caller renders with `%r` when it writes
    down why a request was refused. See `blackgate/audit_chain.AuditChain.key`
    for the same decision on the audit key."""

    def test_repr_does_not_carry_the_key(self):
        secret = b"a-scope-key-that-must-not-be-logged"
        gate = Gate(never_target=("b.invalid",), key=secret)
        self.assertNotIn("scope-key", repr(gate))
        self.assertNotIn(str(secret), repr(gate))

    def test_the_key_is_still_the_key(self):
        secret = b"a-scope-key-that-must-not-be-logged"
        scope = signed_scope(EngagementScope(
            engagement_id="E", targets=("a.invalid",), categories=("RECON",),
            valid_from=0, valid_until=1000), secret)
        gate = Gate(never_target=("b.invalid",), scope=scope, key=secret)
        self.assertTrue(gate.authorize("a.invalid", "RECON", 100).allowed)


class AWindowThatCannotBeEvaluatedIsADecisionNotAnException(unittest.TestCase):
    """The same tick `blackgate/approval_ceremony` refuses.

    This gate named `TypeError` alone, which is what a comparison against a
    plain wrong type raises and not what a `decimal` signaling NaN or an `int`
    subclass with its own `__lt__` raises. A `ValueError` came out of
    `authorize` where a Decision belongs.
    """

    class HostileTick(int):
        def __lt__(self, other):
            raise ValueError("no ordering")

        def __gt__(self, other):
            raise ValueError("no ordering")

        def __le__(self, other):
            raise ValueError("no ordering")

        def __ge__(self, other):
            raise ValueError("no ordering")

        def __eq__(self, other):
            raise ValueError("no equality")

        def __hash__(self):
            return 0

    def gate(self):
        key = b"test key"
        scope = signed_scope(EngagementScope(
            engagement_id="E", targets=("a.invalid",), categories=("RECON",),
            valid_from=0, valid_until=1000), key)
        return Gate(never_target=("b.invalid",), scope=scope, key=key)

    def test_a_tick_that_refuses_ordering_is_refused_by_name(self):
        decision = self.gate().authorize("a.invalid", "RECON",
                                         self.HostileTick(100))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "WINDOW")

    def test_a_signaling_nan_tick_is_refused_by_name(self):
        import decimal
        decision = self.gate().authorize("a.invalid", "RECON",
                                         decimal.Decimal("sNaN"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "WINDOW")

    def test_an_ordinary_tick_inside_the_window_still_passes(self):
        self.assertTrue(self.gate().authorize("a.invalid", "RECON", 100).allowed)


class TheSignatureCommitsToWhatTheGateEnforces(unittest.TestCase):
    """Both fields are read the same way on both sides of the signature."""

    KEY = b"round three scope signing key"

    def test_a_bare_string_target_is_one_host_and_not_its_letters(self):
        scope = EngagementScope("ENG-1", ("example.shop.invalid"), ("RECON",), 100, 200)
        self.assertIn(b"20:example.shop.invalid", scope.canonical_bytes())

    def test_an_anagram_of_a_signed_target_does_not_verify(self):
        legit = signed_scope(EngagementScope(
            "ENG-1", ("example.shop.invalid"), ("RECON",), 100, 200), self.KEY)
        forged = EngagementScope(legit.engagement_id, ("shop.example.invalid"),
                                 legit.categories, legit.valid_from,
                                 legit.valid_until, legit.signature)
        self.assertNotEqual(forged.canonical_bytes(), legit.canonical_bytes())
        self.assertFalse(verify_scope(forged, self.KEY))

    def test_the_forged_scope_is_refused_by_the_gate(self):
        legit = signed_scope(EngagementScope(
            "ENG-1", ("example.shop.invalid"), ("RECON",), 100, 200), self.KEY)
        forged = EngagementScope(legit.engagement_id, ("shop.example.invalid"),
                                 legit.categories, legit.valid_from,
                                 legit.valid_until, legit.signature)
        decision = Gate(never_target=("203.0.113.0/24",), scope=forged,
                        key=self.KEY).authorize("shop.example.invalid", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "SIGNATURE")

    def test_the_boundary_between_the_two_lists_is_signed(self):
        left = EngagementScope("E", ("198.51.100.0/24", "203.0.113.0/24"),
                               ("RECON",), 1, 9)
        right = EngagementScope("E", ("198.51.100.0/24",),
                                ("203.0.113.0/24", "RECON"), 1, 9)
        self.assertNotEqual(left.canonical_bytes(), right.canonical_bytes())


class TheRefusalPathsDoNotRaise(unittest.TestCase):
    """A window that is outside is a refusal, whatever the bounds are written as."""

    KEY = b"round three scope signing key"

    def test_a_window_signed_with_string_ticks_refuses_rather_than_raises(self):
        scope = signed_scope(EngagementScope(
            "ENG-1", ("shop.example.invalid",), ("RECON",),
            valid_from="100", valid_until="200"), self.KEY)
        gate = Gate(never_target=("203.0.113.0/24",), scope=scope, key=self.KEY)
        decision = gate.authorize("shop.example.invalid", "RECON", now="900")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "WINDOW")

    def test_a_never_target_of_none_is_a_failed_read_not_an_empty_backstop(self):
        scope = signed_scope(EngagementScope(
            "ENG-1", ("203.0.113.0/24",), ("RECON",), 1, 999), self.KEY)
        decision = Gate(never_target=None, scope=scope,
                        key=self.KEY).authorize("203.0.113.9", "RECON", now=150)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.gate, "NEVER_TARGET")

    def test_an_empty_backstop_is_still_an_empty_backstop(self):
        scope = signed_scope(EngagementScope(
            "ENG-1", ("203.0.113.0/24",), ("RECON",), 1, 999), self.KEY)
        decision = Gate(never_target=(), scope=scope,
                        key=self.KEY).authorize("203.0.113.9", "RECON", now=150)
        self.assertTrue(decision.allowed)



class TheScopeThatVerifiesIsTheScopeThatDecides(unittest.TestCase):
    """`authorize` read `self.scope` seven times.

    The signature was checked against the first reading; the window, the
    category, the host allow-list and the engagement id in the receipt each
    came from a later one, so a scope swapped in between two of them decided a
    request whose signature had never been checked.
    """

    def gate_that_swaps(self):
        good = a_scope(engagement_id="ENG-GOOD",
                       targets=("shop.example.invalid",))
        forged = EngagementScope(
            engagement_id="ENG-FORGED", targets=("bank.example.invalid",),
            categories=("RECON",), valid_from=100, valid_until=200,
            signature="00" * 32)
        gate = a_gate(scope=good)

        class Swapping(int):
            def __le__(self, other):
                gate.scope = forged
                return int.__le__(self, other)

        object.__setattr__(good, "valid_from", Swapping(100))
        return gate, forged

    def test_the_forged_scope_is_not_signed(self):
        _, forged = self.gate_that_swaps()
        self.assertFalse(verify_scope(forged, KEY))

    def test_the_unsigned_scope_does_not_authorize_its_own_host(self):
        gate, _ = self.gate_that_swaps()
        self.assertFalse(gate.authorize("bank.example.invalid", "RECON", 150).allowed)

    def test_the_receipt_does_not_name_the_unsigned_scope(self):
        gate, _ = self.gate_that_swaps()
        decision = gate.authorize("shop.example.invalid", "RECON", 150)
        self.assertNotIn("ENG-FORGED", decision.reason)

    def test_an_ordinary_request_is_still_authorized(self):
        self.assertTrue(a_gate().authorize("shop.example.invalid", "RECON", 150).allowed)


if __name__ == "__main__":
    unittest.main()
