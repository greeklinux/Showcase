"""Tests for blackgate/detection_gap.py.

The property under test throughout is that the scorecard reports what was
measured and nothing else, and that a generated rule is a rule rather than
something rule-shaped. Four defects are pinned: generated rules whose condition
could never match a real event, rules built by interpolating values into a
format string, simulated verdicts counted as results, and a coverage rate
computed over an empty denominator.

Deterministic: every rule id is derived from its own content, so the same gap
always produces the same identifier and no clock or random source is involved.
"""

import hashlib
import unittest

from blackgate import detection_gap

from blackgate.detection_gap import (
    CAUGHT,
    MAX_FIELD_NESTING,
    LOG_SOURCE_FIELDS,
    OUTCOMES,
    PROVENANCE,
    Attempt,
    Gap,
    RuleError,
    RULE_ID_BITS,
    Scorecard,
    _frame,
    _validate_can_fire,
    scalar,
    score,
    sigma_rule,
    yara_rule,
)


def attempts():
    return [
        Attempt("T1595", "Active scanning", "reconnaissance", "shop.example.invalid",
                "alerted", log_source="firewall"),
        Attempt("T1110", "Password spraying", "credential-access", "shop.example.invalid",
                "blocked", log_source="authentication"),
        Attempt("T1087", "Account discovery", "discovery", "shop.example.invalid",
                "logged_not_alerted", log_source="process_creation"),
        Attempt("T1071", "Application layer protocol", "command-and-control",
                "shop.example.invalid", "no_telemetry", log_source="dns"),
    ]


def a_gap(**over):
    fields = dict(technique_id="T1087", technique="Account discovery",
                  tactic="discovery", log_source="process_creation",
                  reason="logged, nothing alerted")
    fields.update(over)
    return Gap(**fields)


class TheFourOutcomesAreKeptApart(unittest.TestCase):
    def test_a_blocked_technique_counts_as_caught(self):
        card = score([attempts()[1]])
        self.assertEqual(card.caught, 1)
        self.assertEqual(card.missed, 0)

    def test_an_alerted_technique_counts_as_caught(self):
        card = score([attempts()[0]])
        self.assertEqual(card.caught, 1)

    def test_an_event_in_the_log_that_alerted_nothing_is_a_miss(self):
        card = score([attempts()[2]])
        self.assertEqual(card.missed, 1)
        self.assertEqual(card.caught, 0)

    def test_no_telemetry_is_unmeasured_rather_than_missed(self):
        card = score([attempts()[3]])
        self.assertEqual(card.unmeasured, 1)
        self.assertEqual(card.missed, 0)
        self.assertEqual(card.measured, 0)

    def test_the_declared_caught_outcomes_are_a_subset_of_the_declared_outcomes(self):
        for outcome in CAUGHT:
            self.assertIn(outcome, OUTCOMES)

    def test_an_outcome_nobody_declared_is_unmeasured_rather_than_assumed(self):
        card = score([Attempt("T1", "x", "discovery", "a.invalid", "probably_fine")])
        self.assertEqual(card.unmeasured, 1)
        self.assertEqual(card.measured, 0)

    def test_the_four_counts_add_up_to_every_attempt(self):
        card = score(attempts())
        self.assertEqual(card.caught + card.missed + card.unmeasured, len(attempts()))


class ARateOverNothingIsNotARate(unittest.TestCase):
    """The defect: an empty denominator produced either a comfortable full
    score or an alarming zero, and both are inventions."""

    def test_coverage_is_none_when_nothing_was_measured(self):
        card = score([attempts()[3]])
        self.assertIsNone(card.coverage)

    def test_coverage_is_none_for_an_empty_input(self):
        self.assertIsNone(score([]).coverage)

    def test_coverage_is_not_zero_when_nothing_was_measured(self):
        self.assertNotEqual(score([]).coverage, 0.0)

    def test_it_renders_as_not_measured_rather_than_as_a_number(self):
        self.assertIn("not measured", score([]).render())

    def test_coverage_is_computed_over_what_was_measured(self):
        card = score(attempts())
        self.assertEqual(card.measured, 3)
        self.assertAlmostEqual(card.coverage, 2 / 3)

    def test_the_unmeasured_count_is_reported_next_to_the_rate(self):
        rendered = score(attempts()).render()
        self.assertIn("unmeasured 1", rendered)

    def test_a_tactic_with_nothing_measured_renders_as_not_measured(self):
        rendered = score(attempts()).render()
        self.assertIn("command-and-control", rendered)
        self.assertIn("not measured", rendered)

    def test_a_measured_tactic_renders_as_a_fraction(self):
        self.assertIn("1/1", score(attempts()).render())

    def test_the_per_tactic_rows_carry_their_own_unmeasured_count(self):
        card = score(attempts())
        self.assertEqual(card.by_tactic["command-and-control"]["unmeasured"], 1)
        self.assertEqual(card.by_tactic["command-and-control"]["measured"], 0)

    def test_a_scorecard_is_a_plain_record(self):
        self.assertIsNone(Scorecard(0, 0, 0, 0, 0, None).coverage)


class ARehearsalIsNotAResult(unittest.TestCase):
    """The defect: the replay harness fabricates outcomes so the loop can run
    without touching a client environment, and without provenance travelling
    with each verdict a rehearsal is indistinguishable from an engagement."""

    def test_a_simulated_catch_does_not_count_as_caught(self):
        card = score([Attempt("T1021", "Remote services", "lateral-movement",
                              "shop.example.invalid", "alerted", provenance="simulated")])
        self.assertEqual(card.caught, 0)

    def test_a_simulated_verdict_counts_as_unmeasured(self):
        card = score([Attempt("T1021", "Remote services", "lateral-movement",
                              "shop.example.invalid", "alerted", provenance="simulated")])
        self.assertEqual(card.unmeasured, 1)

    def test_a_simulated_miss_does_not_count_as_missed_either(self):
        card = score([Attempt("T1021", "Remote services", "lateral-movement",
                              "shop.example.invalid", "logged_not_alerted",
                              provenance="simulated")])
        self.assertEqual(card.missed, 0)

    def test_the_simulated_count_is_reported_on_its_own(self):
        card = score(attempts() + [Attempt("T1021", "Remote services", "lateral-movement",
                                           "a.invalid", "alerted", provenance="simulated")])
        self.assertEqual(card.simulated, 1)
        self.assertIn("simulated 1", card.render())

    def test_a_scorecard_built_entirely_from_a_rehearsal_has_no_coverage(self):
        card = score([Attempt("T1", "x", "discovery", "a.invalid", "alerted",
                              provenance="simulated"),
                      Attempt("T2", "y", "discovery", "a.invalid", "blocked",
                              provenance="simulated")])
        self.assertIsNone(card.coverage)
        self.assertEqual(card.simulated, 2)

    def test_an_unknown_provenance_is_unmeasured_rather_than_trusted(self):
        card = score([Attempt("T1", "x", "discovery", "a.invalid", "alerted",
                              provenance="probably_real")])
        self.assertEqual(card.measured, 0)

    def test_observed_and_simulated_are_the_only_declared_provenances(self):
        self.assertEqual(set(PROVENANCE), {"observed", "simulated"})


class EveryGapProducesARuleThatCanFire(unittest.TestCase):
    """The defect: the generator emitted a condition matching a MITRE
    technique id inside a command line, which never contains one, so every
    delivered rule matched zero events."""

    def test_a_generated_rule_names_fields_the_log_source_carries(self):
        rule = sigma_rule(a_gap())
        self.assertTrue(any(f in rule for f in LOG_SOURCE_FIELDS["process_creation"]))

    def test_a_rule_whose_selection_names_nothing_real_is_refused(self):
        with self.assertRaises(RuleError):
            _validate_can_fire("    selection:\n        CommandLine|contains: 'T1087'\n"
                               "    condition: selection", "dns")

    def test_the_refusal_says_the_rule_cannot_fire(self):
        try:
            _validate_can_fire("    selection:\n        Nonsense: 1\n"
                               "    condition: selection", "firewall")
        except RuleError as exc:
            self.assertIn("cannot fire", str(exc))
        else:
            self.fail("expected a RuleError")

    def test_the_technique_id_is_in_the_tags_and_not_in_the_detection_body(self):
        rule = sigma_rule(a_gap())
        body = rule.split("detection:", 1)[1].split("falsepositives:", 1)[0]
        self.assertIn("attack.t1087", rule)
        self.assertNotIn("T1087", body)

    def test_the_rule_references_the_technique(self):
        self.assertIn("attack.mitre.org/techniques/T1087", sigma_rule(a_gap()))

    def test_each_log_source_gets_its_own_detection_body(self):
        firewall = sigma_rule(a_gap(log_source="firewall"))
        dns = sigma_rule(a_gap(log_source="dns"))
        self.assertNotEqual(firewall.split("detection:")[1], dns.split("detection:")[1])

    def test_an_unknown_log_source_falls_back_to_one_that_exists(self):
        rule = sigma_rule(a_gap(log_source="not_a_source"))
        self.assertIn("process_creation", rule)

    def test_the_rule_id_is_derived_from_the_gap_and_is_stable(self):
        self.assertEqual(sigma_rule(a_gap()), sigma_rule(a_gap()))

    def test_two_different_gaps_get_two_different_rule_ids(self):
        one = sigma_rule(a_gap())
        two = sigma_rule(a_gap(technique_id="T1110", tactic="credential-access",
                               log_source="authentication"))
        self.assertNotEqual(one.split("\n")[1], two.split("\n")[1])

    def test_every_log_source_profile_names_only_fields_its_source_carries(self):
        """Found by the mutation harness, which dropped one field name from one
        log source profile and watched nothing turn red.

        The expected field names are written out here as literals rather than
        read from `LOG_SOURCE_FIELDS`, which is the whole point. A test that
        loops over the same table the module builds its regex and its profiles
        from checks the table against itself, and a table that loses a member
        loses the test case with it. These are the fields each of these log
        sources actually carries, stated independently, so removing one from
        the module is a failure here.
        """
        expected = {
            "process_creation": ("Image", "CommandLine", "ParentImage", "User",
                                 "EventID"),
            "firewall": ("action", "src_ip", "dst_ip", "dst_port", "rule_name"),
            "authentication": ("EventID", "TargetUserName", "LogonType",
                               "IpAddress", "Status"),
            "dns": ("query", "query_type", "answer", "client_ip"),
        }
        self.assertEqual(set(expected), set(LOG_SOURCE_FIELDS))
        for source, fields in expected.items():
            self.assertEqual(tuple(LOG_SOURCE_FIELDS[source]), fields, source)

    def test_a_selection_on_any_field_a_source_declares_is_allowed_to_fire(self):
        # The other half of the same gap. A field dropped from a profile would
        # make a legitimate rule refuse to generate, which is the failure the
        # generator's own validator is supposed to prevent rather than cause.
        for source, fields in (("dns", ("query", "query_type", "answer",
                                        "client_ip")),
                               ("firewall", ("action", "src_ip", "dst_ip",
                                             "dst_port", "rule_name"))):
            for field in fields:
                body = ("    selection:\n        %s: 'x'\n"
                        "    condition: selection" % field)
                _validate_can_fire(body, source)

    def test_a_rule_carries_a_false_positive_note(self):
        self.assertIn("falsepositives:", sigma_rule(a_gap()))

    def test_a_rule_says_it_is_experimental_and_needs_tuning(self):
        rule = sigma_rule(a_gap())
        self.assertIn("status: experimental", rule)
        self.assertIn("Tune before enabling", rule)


class EveryInterpolatedValueIsAValue(unittest.TestCase):
    """The defect: rules were built by interpolating into a format string, so a
    value carrying a newline landed as new YAML keys rather than as a value."""

    def test_a_newline_in_a_value_does_not_add_a_line(self):
        clean = sigma_rule(a_gap())
        hostile = sigma_rule(a_gap(technique="Account discovery'\nlevel: informational"))
        self.assertEqual(len(hostile.splitlines()), len(clean.splitlines()))

    def test_an_injected_key_does_not_become_a_key(self):
        rule = sigma_rule(a_gap(technique="x'\nlevel: informational"))
        self.assertNotIn("\nlevel: informational", rule)
        self.assertIn("level: high", rule)

    def test_an_injected_condition_does_not_become_a_condition(self):
        rule = sigma_rule(a_gap(technique="x'\ncondition: never"))
        self.assertIn("condition: selection", rule)
        self.assertNotIn("\ncondition: never", rule)

    def test_a_quote_is_doubled_rather_than_closing_the_scalar(self):
        self.assertEqual(scalar("it's"), "'it''s'")

    def test_whitespace_is_collapsed_to_a_single_space(self):
        self.assertEqual(scalar("a\n\tb   c"), "'a b c'")

    def test_an_empty_value_still_renders_as_a_scalar(self):
        self.assertEqual(scalar(""), "''")
        self.assertEqual(scalar(None), "''")

    def test_the_technique_id_is_reduced_to_a_safe_token(self):
        rule = sigma_rule(a_gap(technique_id="T1087; rm -rf /"))
        self.assertNotIn("rm -rf", rule)

    def test_a_hostile_tactic_does_not_break_the_tag_block(self):
        rule = sigma_rule(a_gap(tactic="discovery\nlevel: low"))
        self.assertIn("level: high", rule)


class TheGapListSaysWhichKindOfGapItIs(unittest.TestCase):
    def test_a_logged_but_unalerted_technique_becomes_a_gap(self):
        card = score([attempts()[2]])
        self.assertEqual(len(card.gaps), 1)
        self.assertIn("nothing alerted", card.gaps[0].reason)

    def test_a_technique_with_no_telemetry_becomes_a_different_gap(self):
        card = score([attempts()[3]])
        self.assertIn("no telemetry", card.gaps[0].reason)

    def test_a_caught_technique_produces_no_gap(self):
        self.assertEqual(score([attempts()[0]]).gaps, [])

    def test_a_simulated_attempt_produces_no_gap(self):
        card = score([Attempt("T1", "x", "discovery", "a.invalid", "logged_not_alerted",
                              provenance="simulated")])
        self.assertEqual(card.gaps, [])

    def test_the_gap_carries_the_log_source_the_rule_will_be_written_against(self):
        card = score([attempts()[3]])
        self.assertEqual(card.gaps[0].log_source, "dns")

    def test_the_rendered_scorecard_lists_every_gap(self):
        rendered = score(attempts()).render()
        self.assertEqual(rendered.count("GAP"), 2)


class TheGeneratedYaraSkeletonCarriesNoContent(unittest.TestCase):
    def test_it_has_no_strings_in_it(self):
        rule = yara_rule(a_gap())
        self.assertIn("supply artifacts from your own environment", rule)

    def test_its_condition_is_false_until_somebody_fills_it_in(self):
        self.assertIn("condition:\n        false", yara_rule(a_gap()))

    def test_the_rule_name_is_a_safe_identifier(self):
        rule = yara_rule(a_gap(technique_id="T1087;drop", tactic="dis covery"))
        name = rule.splitlines()[0]
        self.assertNotIn(";", name)
        self.assertNotIn(" ", name.replace("rule ", ""))

    def test_a_quote_in_the_technique_name_is_escaped(self):
        rule = yara_rule(a_gap(technique='say "hello"'))
        self.assertIn('\\"hello\\"', rule)

    def test_a_newline_in_the_technique_name_does_not_add_a_line(self):
        clean = len(yara_rule(a_gap()).splitlines())
        hostile = len(yara_rule(a_gap(technique="a\nb")).splitlines())
        self.assertEqual(clean, hostile)


class AValidatorThatCannotReadTheRuleRefusesIt(unittest.TestCase):
    """The defect found by audit: _validate_can_fire read the selection as
    `rule.split(marker, 1)[-1]`, and `[-1]` of a split that found nothing is
    the whole string. A rule with no selection was therefore validated against
    its own title and tags and passed, and a rule with no condition had its
    body run to the end of the file and took its evidence from the false
    positives section. Both pass a rule with no detection in it, which is this
    module's founding defect arriving through the door marked validator."""

    def test_a_rule_with_no_selection_is_refused(self):
        with self.assertRaises(RuleError):
            _validate_can_fire("detection:\n  query: 'x'\n", "dns")

    def test_a_rule_with_no_condition_is_refused(self):
        with self.assertRaises(RuleError):
            _validate_can_fire("    selection:\n        bogus: 1\n"
                               "falsepositives:\n    - 'x'\nquery: 1\n", "dns")

    def test_an_empty_rule_is_refused(self):
        with self.assertRaises(RuleError):
            _validate_can_fire("", "dns")

    def test_a_field_named_only_after_the_condition_does_not_count(self):
        with self.assertRaises(RuleError):
            _validate_can_fire("    selection:\n        bogus: 1\n"
                               "    condition: selection and query: 1", "dns")

    def test_an_unknown_log_source_is_a_rule_error_not_a_key_error(self):
        with self.assertRaises(RuleError):
            _validate_can_fire("    selection:\n        Image: x\n"
                               "    condition: selection", "not_a_source")

    def test_a_real_generated_rule_still_validates(self):
        for source in ("process_creation", "firewall", "authentication", "dns"):
            rule = sigma_rule(Gap("T1087", "Account discovery", "discovery",
                                  source, "logged, nothing alerted"))
            _validate_can_fire(rule, source)


class TheScorecardNeverPrintsARateItDidNotMeasure(unittest.TestCase):
    def test_a_coverage_set_over_zero_measurements_still_prints_not_measured(self):
        self.assertIn("not measured", Scorecard(0, 0, 0, 0, 0, 1.0).render())

    def test_a_rate_is_not_rounded_up_to_perfect_while_something_was_missed(self):
        rendered = Scorecard(1000, 999, 1, 0, 0, 0.999).render()
        self.assertNotIn("100%", rendered)
        self.assertIn("missed 1", rendered)

    def test_a_genuinely_perfect_rate_still_prints_as_perfect(self):
        self.assertIn("100%", Scorecard(4, 4, 0, 0, 0, 1.0).render())

    def test_a_tactic_row_missing_its_counts_renders_as_not_measured(self):
        rendered = Scorecard(0, 0, 0, 0, 0, None,
                             by_tactic={"discovery": {"caught": 1}}).render()
        self.assertIn("not measured", rendered)


class NoInputMakesTheScorerRaiseInsteadOfSayingNotMeasured(unittest.TestCase):
    """Not measured, measured and none found, and measured k of N are three
    states this module exists to keep apart. A traceback is none of them."""

    def test_an_input_that_cannot_be_read_scores_as_not_measured(self):
        for attempts in (None, 5, 1.5):
            card = score(attempts)
            self.assertIsNone(card.coverage, repr(attempts))
            self.assertEqual(card.measured, 0, repr(attempts))

    def test_an_entry_that_is_not_an_attempt_counts_as_unmeasured(self):
        card = score([None, 0, "x"])
        self.assertIsNone(card.coverage)
        self.assertEqual(card.unmeasured, 3)
        self.assertEqual(card.caught, 0)

    def test_an_attempt_whose_tactic_cannot_be_a_key_still_scores(self):
        card = score([Attempt("T1", "n", ["discovery"], "h", "alerted")])
        self.assertEqual(card.measured, 1)

    def test_a_gap_carrying_no_technique_name_still_makes_a_yara_skeleton(self):
        for technique in (None, 0, ["x"]):
            self.assertIn("rule ", yara_rule(Gap("T1", technique, "t", "dns", "r")))

    def test_a_log_source_that_cannot_be_looked_up_still_emits_a_rule(self):
        self.assertIn("logsource:", sigma_rule(Gap("T1", "n", "t", ["dns"], "r")))



class TheRuleIdIsFramedNotJoined(unittest.TestCase):
    """Hardening, not a closed hole.

    The rule id was hashed over `"%s|%s|%s"`. That pre-image is ambiguous the
    way `automation/alert_deduper.fingerprint` argues at length, and two gaps
    sharing one rule id means a SIEM keyed on rule id keeps one rule and drops
    the other. Nothing could reach it, because `_safe_token` strips the pipe
    out of both interpolated fields, so the property held because of a
    character class in a different function written for a different reason.
    These tests hold the framing directly, so the id stays injective whatever
    that character class later admits.
    """

    def test_the_framing_is_injective_where_a_join_is_not(self):
        self.assertEqual("|".join(["a|b", "c", "d"]), "|".join(["a", "b|c", "d"]))
        self.assertNotEqual(_frame("a|b", "c", "d"), _frame("a", "b|c", "d"))

    def test_the_framing_separates_a_boundary_moved_by_any_character(self):
        pairs = (
            (("T1087|x", "y", "dns"), ("T1087", "x|y", "dns")),
            (("", "ab", "dns"), ("a", "b", "dns")),
            (("a:b", "c", "dns"), ("a", "b", "c:dns")),
            (("1:a", "", "dns"), ("", "1:a", "dns")),
        )
        for left, right in pairs:
            self.assertNotEqual(_frame(*left), _frame(*right), (left, right))

    def test_the_framing_is_stable_for_the_same_fields(self):
        self.assertEqual(_frame("T1087", "discovery", "dns"),
                         _frame("T1087", "discovery", "dns"))

    def test_the_emitted_id_is_the_framed_digest_of_its_three_fields(self):
        """The id and the framing are tied together, not merely adjacent.

        Without this the framing could be correct and unused: the id line
        could go back to a join and every test above would still pass, because
        they hold `_frame` and nothing holds what the rule is built from.
        """
        rule = sigma_rule(Gap("T1087", "Account discovery", "credential-access",
                              "dns", "logged, nothing alerted"))
        expected = hashlib.sha256(
            _frame("T1087", "credential_access", "dns")
        ).hexdigest()[:RULE_ID_BITS // 4]
        self.assertEqual(rule_id_of(rule), expected)
        joined = hashlib.sha256(
            "T1087|credential_access|dns".encode("utf-8")
        ).hexdigest()[:RULE_ID_BITS // 4]
        self.assertNotEqual(rule_id_of(rule), joined)

    def test_the_id_width_is_declared_and_is_what_is_emitted(self):
        self.assertEqual(RULE_ID_BITS, 64)
        rule = sigma_rule(Gap("T1087", "Account discovery", "discovery",
                              "dns", "logged, nothing alerted"))
        self.assertEqual(len(rule_id_of(rule)), RULE_ID_BITS // 4)

    def test_the_id_still_depends_on_all_three_fields(self):
        base = Gap("T1087", "Account discovery", "discovery", "dns", "reason")
        ids = {rule_id_of(sigma_rule(base))}
        ids.add(rule_id_of(sigma_rule(Gap("T1088", base.technique, base.tactic,
                                          base.log_source, base.reason))))
        ids.add(rule_id_of(sigma_rule(Gap(base.technique_id, base.technique,
                                          "execution", base.log_source, base.reason))))
        ids.add(rule_id_of(sigma_rule(Gap(base.technique_id, base.technique,
                                          base.tactic, "firewall", base.reason))))
        self.assertEqual(len(ids), 4)


def rule_id_of(rule):
    """The id line of an emitted rule, unquoted and without its prefix."""
    for line in rule.splitlines():
        if line.startswith("id: "):
            return line[len("id: "):].strip().strip("'")[len("blackgate-gap-"):]
    raise AssertionError("the rule carries no id line")


class AFieldNestedPastAnyRenderingIsQuotedAsAMarker(unittest.TestCase):
    """Length is one way a field is unbounded and depth is the other.

    `str()` of a container recurses once per level, so a gap field carrying a
    list nested sixty thousand deep raised RecursionError out of `scalar`, out
    of `sigma_rule` and out of whatever was generating rules. Every other
    unreadable input in this module comes back as a rule that says so.
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

    def test_scalar_renders_a_marker_rather_than_recursing(self):
        rendered = scalar(self.deep())
        self.assertIsInstance(rendered, str)
        self.assertIn("unrenderable", rendered)

    def test_scalar_still_renders_ordinary_values(self):
        self.assertEqual(scalar("a b"), "'a b'")
        self.assertEqual(scalar(["a", "b"]), "'[''a'', ''b'']'")
        self.assertEqual(scalar(None), "''")

    def test_a_rule_over_a_deeply_nested_gap_is_emitted_not_raised(self):
        deep = self.deep()
        gap = Gap("T1087", deep, "discovery", "dns", deep)
        rule = sigma_rule(gap)
        self.assertIn("unrenderable", rule)
        self.assertIn("\n", yara_rule(gap))

    def test_the_bound_is_stated(self):
        self.assertEqual(MAX_FIELD_NESTING, 64)
        # Pinned just past the bound. A list a hundred deep renders perfectly
        # well, so only the stated bound can be refusing it.
        self.assertIn("unrenderable", scalar(self.deep(100)))
        self.assertNotIn("unrenderable", scalar(self.deep(10)))


class ATacticIsARowAndNotAnObject(unittest.TestCase):
    """The scorecard keys on the text of a tactic, never on the attempt."""

    class Same(str):
        """Equal to everything, and hashing to one bucket."""
        def __eq__(self, other):
            return True

        def __ne__(self, other):
            return False

        def __hash__(self):
            return 0

    def test_two_tactics_do_not_collapse_into_one_row(self):
        card = score([
            Attempt("T1110", "Password spraying",
                    ATacticIsARowAndNotAnObject.Same("credential-access"),
                    "h", "blocked"),
            Attempt("T1087", "Account discovery",
                    ATacticIsARowAndNotAnObject.Same("discovery"),
                    "h", "logged_not_alerted"),
        ])
        self.assertEqual(sorted(card.by_tactic), ["credential-access", "discovery"])
        self.assertEqual(card.by_tactic["credential-access"]["caught"], 1)
        self.assertEqual(card.by_tactic["discovery"]["missed"], 1)

    def test_every_row_key_is_an_exact_string(self):
        card = score([Attempt("T1", "t", ["unhashable"], "h", "blocked")])
        for key in card.by_tactic:
            self.assertIs(type(key), str)

    def test_a_tactic_whose_hash_raises_is_scored_not_raised(self):
        class HashBoom(str):
            def __hash__(self):
                raise ValueError("no hash for you")

        card = score([Attempt("T1", "t", HashBoom("x"), "h", "blocked")])
        self.assertEqual(card.measured, 1)
        self.assertEqual(card.caught, 1)

    def test_a_tactic_whose_str_raises_still_renders(self):
        class StrBoom(str):
            def __str__(self):
                raise ValueError("no text")

            def __hash__(self):
                return hash("q")

        card = score([Attempt("T1", "t", StrBoom("q"), "h", "blocked")])
        rendered = card.render()
        self.assertIn("1/1", rendered)

    def test_a_rendering_is_an_exact_string(self):
        class Sub(str):
            pass

        class Wraps(object):
            def __str__(self):
                return Sub("abc")

        # Not merely a `str`. A `str` subclass carries its own `__str__`, and
        # `_frame` renders every part again on the way to bytes: the text that
        # was checked and the text that was hashed were two readings of one
        # object and only the first was guarded.
        self.assertIs(type(detection_gap._text(Wraps())), str)
        self.assertEqual(detection_gap._text(Wraps()), "abc")

    def test_a_field_that_renders_to_a_raising_subclass_is_still_emitted(self):
        class Raises(str):
            def __str__(self):
                raise ValueError("the second render explodes")

        class Wraps(object):
            def __str__(self):
                return Raises("ok")

        gap = Gap("T1087", Wraps(), "discovery", "process_creation", "reason")
        self.assertIn("title:", sigma_rule(gap))

    def test_a_row_key_supplied_by_a_caller_cannot_break_the_renderer(self):
        class StrBoom(str):
            def __str__(self):
                raise ValueError("no text")

            def __hash__(self):
                return hash("q")

        card = Scorecard(measured=1, caught=1, missed=0, unmeasured=0, simulated=0,
                         coverage=1.0,
                         by_tactic={StrBoom("q"): {"measured": 1, "caught": 1}})
        self.assertIn("1/1", card.render())


if __name__ == "__main__":
    unittest.main()
