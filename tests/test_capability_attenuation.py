"""Tests for ai_security/capability_attenuation.py.

The property under test throughout is that authority only ever shrinks down a
delegation chain, and that "shrinks" means different things for different kinds
of component.

Three defects are pinned by name. An additive component copied to every sibling
amplifies across a fan-out while every individual link is a strict attenuation.
A resource scope compared as a raw string prefix lets a depth-three sub-agent
hold a tree the root never held. And a capability checked against an
unresolved name governs a string rather than the thing the tool touches.

Paths, principals and addresses here are synthetic.
"""

import unittest

from ai_security.capability_attenuation import (
    FLOOR_FACTOR,
    UNCERTAINTY_LADDER,
    Capability,
    Delegation,
    attenuation_gaps,
    covers,
    naive_covers,
    normalize_resource,
    uncertainty_factor,
    verify_chain,
)

ROOT = Capability(
    actions=frozenset({"read", "summarize"}),
    resources=frozenset({"data/reports/2026/"}),
    max_blast=200,
    budget=300,
    depth=3,
)


def child_request(budget=100, **overrides):
    base = dict(actions=frozenset({"read"}),
                resources=frozenset({"data/reports/2026/"}),
                max_blast=100, budget=budget, depth=2)
    base.update(overrides)
    return Capability(**base)


def root_node():
    return Delegation("orchestrator", ROOT)


class AnAdditiveComponentMustBeSplitNotCopied(unittest.TestCase):
    """Every link attenuates and the leaves still hold more than the root."""

    def test_the_first_full_budget_delegation_is_granted(self):
        self.assertTrue(root_node().delegate("analyst-a", child_request(200)).ok)

    def test_a_second_sibling_asking_for_the_same_budget_is_refused(self):
        root = root_node()
        root.delegate("analyst-a", child_request(200))
        self.assertFalse(root.delegate("analyst-b", child_request(200)).ok)

    def test_the_refusal_names_what_is_left_to_give(self):
        root = root_node()
        root.delegate("analyst-a", child_request(200))
        result = root.delegate("analyst-b", child_request(200))
        self.assertIn("already handed to sub-agents", result.gaps[0])

    def test_the_sibling_request_is_a_strict_attenuation_on_every_other_axis(self):
        """Only the budget stops it, which is the whole point."""
        request = child_request(200)
        self.assertEqual(attenuation_gaps(ROOT, request), [])

    def test_budget_committed_to_a_child_leaves_the_parent(self):
        root = root_node()
        root.delegate("analyst-a", child_request(200))
        self.assertEqual(root.remaining(), 100)

    def test_budget_leaves_the_parent_even_if_the_child_never_spends_it(self):
        root = root_node()
        root.delegate("analyst-a", child_request(200))
        self.assertEqual(root.subtree_spent(), 0)
        self.assertEqual(root.remaining(), 100)

    def test_three_siblings_can_split_the_budget_between_them(self):
        root = root_node()
        for name in ("a", "b", "c"):
            self.assertTrue(root.delegate(name, child_request(100)).ok, name)
        self.assertEqual(root.remaining(), 0)

    def test_a_fourth_sibling_after_a_full_split_gets_nothing(self):
        root = root_node()
        for name in ("a", "b", "c"):
            root.delegate(name, child_request(100))
        self.assertFalse(root.delegate("d", child_request(1)).ok)

    def test_spending_reduces_what_is_left_to_delegate(self):
        root = root_node()
        root.exercise("read", "data/reports/2026/q3.csv", 150, confidence=0.95)
        self.assertFalse(root.delegate("a", child_request(200)).ok)

    def test_the_whole_subtree_cannot_spend_more_than_the_root_held(self):
        # Validate the effective inputs and decision boundary explicitly.
        poisoned = root_node()
        poisoned.delegate("nan", child_request(float("nan")))
        self.assertFalse(poisoned.delegate("greedy",
                                           child_request(10 ** 9, depth=2)).ok)
        self.assertEqual(poisoned.remaining(), 300)
        self.assertLessEqual(poisoned.subtree_spent(), ROOT.budget)

        root = root_node()
        first = root.delegate("a", child_request(150)).child
        second = root.delegate("b", child_request(150)).child
        for node in (first, second):
            node.exercise("read", "data/reports/2026/q3.csv", 100,
                          confidence=0.95)
            node.exercise("read", "data/reports/2026/q3.csv", 50,
                          confidence=0.95)
        self.assertLessEqual(root.subtree_spent(), ROOT.budget)
        self.assertEqual(root.subtree_spent(), 300)

    def test_an_idempotent_component_may_be_copied_to_every_sibling(self):
        root = root_node()
        for name in ("a", "b", "c"):
            result = root.delegate(name, child_request(100))
            self.assertEqual(result.child.capability.actions, frozenset({"read"}))

    def test_a_negative_budget_is_not_an_attenuation(self):
        result = root_node().delegate("a", child_request(-5))
        self.assertFalse(result.ok)
        self.assertIn("negative budget", result.gaps[0])
        # Validate the effective inputs and decision boundary explicitly.
        for budget in (float("nan"), float("inf"), float("-inf"), None, "200"):
            root = root_node()
            self.assertFalse(root.delegate("a", child_request(budget)).ok, budget)
            self.assertEqual(root.committed, 0)
            self.assertEqual(root.remaining(), 300)


class AttenuationHoldsOnEveryIdempotentComponent(unittest.TestCase):
    def test_a_child_asking_for_an_action_the_parent_lacks_is_refused(self):
        gaps = attenuation_gaps(ROOT, child_request(actions=frozenset({"write"})))
        self.assertTrue(any("actions not held" in g for g in gaps))

    def test_a_child_asking_for_a_wider_blast_radius_is_refused(self):
        gaps = attenuation_gaps(ROOT, child_request(max_blast=400))
        self.assertTrue(any("max_blast" in g for g in gaps))
        # Validate the effective inputs and decision boundary explicitly.
        for blast in (float("nan"), float("inf"), None):
            refused = attenuation_gaps(ROOT, child_request(max_blast=blast))
            self.assertTrue(any("max_blast" in g for g in refused), blast)

    def test_an_equal_blast_radius_is_permitted(self):
        self.assertEqual(attenuation_gaps(ROOT, child_request(max_blast=200)), [])

    def test_depth_must_strictly_decrease(self):
        gaps = attenuation_gaps(ROOT, child_request(depth=3))
        self.assertTrue(any("does not decrease" in g for g in gaps))

    def test_a_parent_with_no_depth_left_cannot_delegate_at_all(self):
        leaf = Capability(actions=frozenset({"read"}),
                          resources=frozenset({"data/"}), max_blast=1,
                          budget=1, depth=0)
        gaps = attenuation_gaps(leaf, Capability(depth=0))
        self.assertTrue(any("no remaining delegation depth" in g for g in gaps))

    def test_a_child_asking_outside_every_parent_scope_is_refused(self):
        gaps = attenuation_gaps(
            ROOT, child_request(resources=frozenset({"secrets/"})))
        self.assertTrue(any("outside every parent scope" in g for g in gaps))

    def test_a_narrower_scope_is_permitted(self):
        self.assertEqual(
            attenuation_gaps(ROOT,
                             child_request(resources=frozenset({"data/reports/2026/q3/"}))),
            [])

    def test_every_violated_component_is_named_not_only_the_first(self):
        gaps = attenuation_gaps(ROOT, child_request(
            actions=frozenset({"write"}), max_blast=999, depth=9))
        self.assertGreaterEqual(len(gaps), 3)

    def test_an_identical_capability_is_a_permitted_attenuation_except_for_depth(self):
        gaps = attenuation_gaps(ROOT, ROOT)
        self.assertEqual(gaps, [f"depth {ROOT.depth} does not decrease from the "
                                f"parent's {ROOT.depth}"])


class ARawPrefixCheckAmplifiesWithDepth(unittest.TestCase):
    """The depth-three case. Each request is longer than the scope it came from."""

    WALK = ("data/reports/2026/../",
            "data/reports/2026/../../",
            "data/reports/2026/../../../secrets/")

    def test_the_raw_prefix_check_grants_every_link(self):
        for request in self.WALK:
            self.assertTrue(naive_covers("data/reports/2026/", request), request)

    def test_the_normalized_check_refuses_every_link(self):
        for request in self.WALK:
            self.assertFalse(covers("data/reports/2026/", request), request)

    def test_the_third_link_resolves_to_a_tree_the_root_never_held(self):
        self.assertEqual(normalize_resource(self.WALK[2]), "secrets/")

    def test_the_first_link_already_resolves_above_the_root(self):
        self.assertEqual(normalize_resource(self.WALK[0]), "data/reports/")

    def test_a_delegation_asking_for_the_escaped_scope_is_refused(self):
        result = root_node().delegate(
            "analyst-a", child_request(resources=frozenset({self.WALK[2]})))
        self.assertFalse(result.ok)

    def test_a_scope_check_holds_on_segment_boundaries(self):
        self.assertFalse(covers("data/reports", "data/reports-archive/q3.csv"))

    def test_a_scope_covers_itself(self):
        self.assertTrue(covers("data/reports/2026/", "data/reports/2026"))

    def test_a_scope_covers_a_file_beneath_it(self):
        self.assertTrue(covers("data/reports/2026/", "data/reports/2026/q3.csv"))

    def test_an_absolute_path_is_not_covered_by_anything(self):
        self.assertFalse(covers("data/", "/etc/passwd"))

    def test_a_windows_style_path_is_not_covered_by_anything(self):
        self.assertFalse(covers("data/", "data\\reports\\q3.csv"))

    def test_a_path_with_an_embedded_null_is_not_covered(self):
        self.assertFalse(covers("data/", "data/q3.csv\x00.txt"))

    def test_a_non_string_resource_is_not_covered(self):
        self.assertFalse(covers("data/", None))
        self.assertFalse(covers(None, "data/q3.csv"))

    def test_an_empty_resource_is_not_covered(self):
        self.assertFalse(covers("data/", "   "))

    def test_a_path_that_climbs_above_its_own_root_cannot_be_normalized(self):
        self.assertIsNone(normalize_resource("../secrets/"))

    def test_a_path_that_normalizes_to_the_current_directory_is_refused(self):
        self.assertIsNone(normalize_resource("./"))

    def test_an_interior_dot_segment_is_reduced_not_refused(self):
        self.assertEqual(normalize_resource("data/./reports/"), "data/reports/")


class TheCheckRunsOnTheResolvedTarget(unittest.TestCase):
    def setUp(self):
        self.agent = Delegation("analyst-a", Capability(
            actions=frozenset({"read"}),
            resources=frozenset({"data/reports/2026/"}),
            max_blast=100, budget=100, depth=1))

    def test_a_name_resolving_inside_the_scope_is_allowed(self):
        table = {"latest-report": "data/reports/2026/q3.csv"}
        receipt = self.agent.exercise("read", "latest-report", 10,
                                      confidence=0.95, resolve=table.get)
        self.assertTrue(receipt.allowed, receipt.reason)

    def test_the_same_name_resolving_outside_the_scope_is_refused(self):
        table = {"latest-report": "secrets/api-keys.txt"}
        receipt = self.agent.exercise("read", "latest-report", 10,
                                      confidence=0.95, resolve=table.get)
        self.assertFalse(receipt.allowed)
        self.assertIn("resolved target is outside", receipt.reason)

    def test_the_receipt_records_both_the_name_and_what_it_resolved_to(self):
        table = {"latest-report": "secrets/api-keys.txt"}
        receipt = self.agent.exercise("read", "latest-report", 10,
                                      confidence=0.95, resolve=table.get)
        self.assertEqual(receipt.requested, "latest-report")
        self.assertEqual(receipt.resolved, "secrets/api-keys.txt")

    def test_the_render_shows_the_resolution_arrow(self):
        table = {"latest-report": "data/reports/2026/q3.csv"}
        receipt = self.agent.exercise("read", "latest-report", 10,
                                      confidence=0.95, resolve=table.get)
        self.assertIn("->", receipt.render())

    def test_a_resolver_returning_nothing_refuses_rather_than_passing(self):
        receipt = self.agent.exercise("read", "unknown-name", 10,
                                      confidence=0.95, resolve={}.get)
        self.assertFalse(receipt.allowed)

    def test_a_resolver_that_raises_refuses_and_says_nothing_was_checked(self):
        def broken(_):
            raise RuntimeError("no resolver")
        receipt = self.agent.exercise("read", "latest-report", 10,
                                      confidence=0.95, resolve=broken)
        self.assertFalse(receipt.allowed)
        self.assertIn("nothing was checked", receipt.reason)

    def test_an_action_not_held_is_refused_before_anything_else(self):
        receipt = self.agent.exercise("write", "data/reports/2026/q3.csv", 1,
                                      confidence=0.99)
        self.assertFalse(receipt.allowed)
        self.assertIn("not held by this principal", receipt.reason)
        # An action that is not even hashable, a list out of a model's tool
        # call for instance, is refused rather than raising out of the `in`.
        for action in (["read", "write"], {"a": 1}, {"read"}, None):
            refused = self.agent.exercise(action, "data/reports/2026/q3.csv", 1,
                                          confidence=0.99)
            self.assertFalse(refused.allowed, action)
            self.assertIn("not held by this principal", refused.reason)

    def test_a_refused_exercise_does_not_spend_budget(self):
        self.agent.exercise("write", "data/reports/2026/q3.csv", 50,
                            confidence=0.99)
        self.assertEqual(self.agent.remaining(), 100)

    def test_an_allowed_exercise_spends_its_records(self):
        self.agent.exercise("read", "data/reports/2026/q3.csv", 40,
                            confidence=0.99)
        self.assertEqual(self.agent.remaining(), 60)

    def test_an_exercise_beyond_the_remaining_budget_is_refused(self):
        self.agent.exercise("read", "data/reports/2026/q3.csv", 90,
                            confidence=0.99)
        receipt = self.agent.exercise("read", "data/reports/2026/q3.csv", 90,
                                      confidence=0.99)
        self.assertFalse(receipt.allowed)
        self.assertIn("left in this principal's budget", receipt.reason)

    def test_a_record_count_that_is_not_a_number_is_refused(self):
        for records in ("lots", None, float("nan"), float("inf"),
                        float("-inf")):
            receipt = self.agent.exercise("read", "data/reports/2026/q3.csv",
                                          records, confidence=0.99)
            self.assertFalse(receipt.allowed, records)
            self.assertIn("not a number", receipt.reason)

    def test_a_negative_record_count_is_refused(self):
        receipt = self.agent.exercise("read", "data/reports/2026/q3.csv", -10,
                                      confidence=0.99)
        self.assertFalse(receipt.allowed)
        self.assertIn("negative record count", receipt.reason)

    def test_a_refusal_on_another_ground_survives_an_unreadable_count(self):
        """A guard that crashes instead of refusing is not a guard.

        `int(float("inf"))` raises OverflowError rather than ValueError, so a
        guard that caught TypeError and ValueError still turned a clean DENY
        into an exception on an infinite count.
        """
        for records in ("lots", float("inf"), float("nan")):
            receipt = self.agent.exercise("write", "data/reports/2026/q3.csv",
                                          records, confidence=0.99)
            self.assertFalse(receipt.allowed, records)
            self.assertEqual(receipt.records, 0)

    def test_an_unreadable_count_on_an_out_of_scope_target_still_refuses(self):
        receipt = self.agent.exercise("read", "secrets/keys.txt", None,
                                      confidence=0.99)
        self.assertFalse(receipt.allowed)
        self.assertIn("outside every scope", receipt.reason)

    def test_a_non_string_target_is_refused_and_reported_readably(self):
        receipt = self.agent.exercise("read", None, 1, confidence=0.99)
        self.assertFalse(receipt.allowed)
        self.assertEqual(receipt.requested, "None")


class UncertaintyIsAppliedAtTheCall(unittest.TestCase):
    def setUp(self):
        self.agent = Delegation("analyst-a", Capability(
            actions=frozenset({"read"}),
            resources=frozenset({"data/reports/2026/"}),
            max_blast=100, budget=1000, depth=1))

    def target(self):
        return "data/reports/2026/q3.csv"

    def test_full_confidence_keeps_the_whole_blast_radius(self):
        receipt = self.agent.exercise("read", self.target(), 100, confidence=0.99)
        self.assertTrue(receipt.allowed, receipt.reason)
        self.assertEqual(receipt.effective_blast, 100)

    def test_the_same_call_is_refused_at_lower_confidence(self):
        receipt = self.agent.exercise("read", self.target(), 100, confidence=0.80)
        self.assertFalse(receipt.allowed)

    def test_a_smaller_call_still_runs_at_lower_confidence(self):
        receipt = self.agent.exercise("read", self.target(), 20, confidence=0.80)
        self.assertTrue(receipt.allowed, receipt.reason)

    def test_the_factor_is_monotone_in_confidence(self):
        levels = [uncertainty_factor(c) for c in (0.99, 0.90, 0.80, 0.60, 0.40)]
        self.assertEqual(levels, sorted(levels, reverse=True))

    def test_the_factor_never_exceeds_one(self):
        for confidence in (1.0, 0.99, 0.9, 0.5, 0.0):
            self.assertLessEqual(uncertainty_factor(confidence), 1.0)

    def test_below_the_lowest_rung_the_blast_radius_is_zero(self):
        self.assertEqual(uncertainty_factor(0.10), FLOOR_FACTOR)

    def test_a_missing_confidence_is_not_a_confident_one(self):
        self.assertEqual(uncertainty_factor(None), FLOOR_FACTOR)

    def test_a_confidence_that_is_not_a_number_is_refused(self):
        # Including one that would parse as a number. `float("0.99")` is 0.99
        # and buys the full blast radius, and a confidence that arrived as text
        # out of a model response is exactly the case that reaches this.
        for confidence in ("high", "0.99", "1.0", b"0.9", " 0.99 ", "1e0",
                           [0.99], None):
            self.assertEqual(uncertainty_factor(confidence), FLOOR_FACTOR,
                             confidence)

    def test_a_confidence_above_one_is_refused_rather_than_clamped(self):
        self.assertEqual(uncertainty_factor(1.5), FLOOR_FACTOR)

    def test_a_negative_confidence_is_refused(self):
        self.assertEqual(uncertainty_factor(-0.5), FLOOR_FACTOR)

    def test_an_exercise_with_no_confidence_is_refused_by_name(self):
        receipt = self.agent.exercise("read", self.target(), 1)
        self.assertFalse(receipt.allowed)
        self.assertIn("below the lowest rung", receipt.reason)

    def test_the_ladder_rungs_are_ordered_highest_confidence_first(self):
        thresholds = [t for t, _ in UNCERTAINTY_LADDER]
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))

    def test_uncertainty_never_grants_more_than_the_capability_holds(self):
        narrow = Delegation("narrow", Capability(
            actions=frozenset({"read"}),
            resources=frozenset({"data/reports/2026/"}),
            max_blast=4, budget=100, depth=1))
        receipt = narrow.exercise("read", self.target(), 5, confidence=1.0)
        self.assertFalse(receipt.allowed)
        self.assertEqual(receipt.effective_blast, 4)


class AChainIsVerifiedAgainstEachLinksParent(unittest.TestCase):
    def build(self):
        root = root_node()
        first = root.delegate("a", child_request(200, depth=2)).child
        second = first.delegate("b", Capability(
            actions=frozenset({"read"}),
            resources=frozenset({"data/reports/2026/q3/"}),
            max_blast=50, budget=100, depth=1)).child
        return [root, first, second]

    def test_a_well_formed_chain_reports_no_violations(self):
        self.assertEqual(verify_chain(self.build()), [])

    def test_a_chain_of_one_has_nothing_to_verify(self):
        self.assertEqual(verify_chain([root_node()]), [])

    def test_an_empty_chain_has_nothing_to_verify(self):
        self.assertEqual(verify_chain([]), [])

    def test_a_forged_link_is_named_with_its_position(self):
        chain = self.build()
        chain.append(Delegation("c", Capability(
            actions=frozenset({"read", "write"}),
            resources=frozenset({"secrets/"}),
            max_blast=999, budget=1, depth=0)))
        violations = verify_chain(chain)
        self.assertTrue(violations)
        self.assertTrue(all(v.startswith("link 3 (c)") for v in violations))

    def test_a_forged_link_reports_every_component_it_exceeded(self):
        chain = self.build()
        chain.append(Delegation("c", Capability(
            actions=frozenset({"read", "write"}),
            resources=frozenset({"secrets/"}),
            max_blast=999, budget=1, depth=0)))
        self.assertGreaterEqual(len(verify_chain(chain)), 3)

    def test_a_child_knows_its_parent(self):
        chain = self.build()
        self.assertIs(chain[2].parent, chain[1])

    def test_a_granted_child_is_recorded_on_the_parent(self):
        root = root_node()
        result = root.delegate("a", child_request(100))
        self.assertIn(result.child, root.children)

    def test_a_refused_delegation_records_nothing_on_the_parent(self):
        root = root_node()
        root.delegate("a", child_request(999))
        self.assertEqual(root.children, [])
        self.assertEqual(root.committed, 0)

    def test_a_result_renders_the_principal_it_granted(self):
        result = root_node().delegate("analyst-a", child_request(100))
        self.assertIn("analyst-a", result.render())

    def test_a_refusal_renders_every_reason(self):
        result = root_node().delegate("analyst-a", child_request(
            999, actions=frozenset({"write"})))
        rendered = result.render()
        self.assertIn("refused", rendered)
        self.assertIn("actions not held", rendered)


class TheScopesAPrincipalHoldsAreReadLikeAList(unittest.TestCase):
    """The holder's side of the scope check refuses rather than raising."""

    def test_an_unreadable_scope_list_is_a_refusal(self):
        holder = Delegation("analyst", Capability(
            actions=frozenset({"read"}), resources=None,
            max_blast=100, budget=100, depth=1))
        receipt = holder.exercise("read", "data/reports/q3.csv", 10, confidence=0.99)
        self.assertFalse(receipt.allowed)
        self.assertIn("could not be read", receipt.reason)

    def test_an_unreadable_parent_scope_list_is_a_gap(self):
        parent = Capability(actions=frozenset({"read"}), resources=None,
                            max_blast=100, budget=100, depth=2)
        child = Capability(actions=frozenset({"read"}), resources=frozenset({"data"}),
                           max_blast=10, budget=10, depth=1)
        gaps = attenuation_gaps(parent, child)
        self.assertTrue(any("could not be read" in gap for gap in gaps))

    def test_a_bare_string_scope_is_one_tree_and_not_its_letters(self):
        holder = Delegation("analyst", Capability(
            actions=frozenset({"read"}), resources="data/reports/2026/",
            max_blast=100, budget=100, depth=1))
        self.assertTrue(holder.exercise("read", "data/reports/2026/x.csv", 1,
                                        confidence=0.99).allowed)
        self.assertFalse(holder.exercise("read", "d/secrets/keys.txt", 1,
                                         confidence=0.99).allowed)


class ExerciseUsesTheScopeCheckAndNotTheDefectBesideIt(unittest.TestCase):
    """`naive_covers` stays in the module so the contrast is runnable, and
    nothing held `exercise` to the other one.

    Both functions are exported, they take the same two arguments and their
    names differ by one word, so a one-identifier edit at the call site turns
    the scope check back into the raw prefix test the module was written to
    argue against. That edit broke no test: the whole suite, the defence table
    and every published figure stayed green while a capability scoped to
    `data/reports/2026/` reached `/etc/shadow`.

    So the property is asserted here directly, on `exercise`, which is the
    function a caller reaches. `covers` and `normalize_resource` are tested on
    their own above; this class exists to pin which of the two the decision
    is wired to, because a control that is correct and not wired up is the
    thing this repository keeps finding.
    """

    def holder(self):
        return Delegation(
            "analyst",
            Capability(actions=frozenset(["read"]),
                       resources=frozenset(["data/reports/2026/"]),
                       max_blast=100, budget=1000, depth=2))

    def test_a_target_that_climbs_out_of_the_held_scope_is_denied(self):
        receipt = self.holder().exercise(
            "read", "data/reports/2026/../../../etc/shadow", 1, confidence=0.99)
        self.assertFalse(receipt.allowed)
        self.assertIn("outside every scope", receipt.reason)

    def test_every_spelling_of_the_climb_is_denied(self):
        for target in ("data/reports/2026/../2025/q4.csv",
                       "data/reports/2026/../../payroll/salaries.csv",
                       "data/reports/2026/./../../payroll/salaries.csv",
                       "data/reports/2026/../../../etc/shadow"):
            with self.subTest(target=target):
                receipt = self.holder().exercise("read", target, 1,
                                                 confidence=0.99)
                self.assertFalse(receipt.allowed)

    def test_the_naive_check_would_have_allowed_every_one_of_them(self):
        """The contrast, run rather than asserted in prose.

        If this ever starts failing, `naive_covers` has been fixed or removed
        and the test above is no longer pinning anything, so the two belong
        together.
        """
        for target in ("data/reports/2026/../2025/q4.csv",
                       "data/reports/2026/../../../etc/shadow"):
            with self.subTest(target=target):
                self.assertTrue(naive_covers("data/reports/2026/", target))
                self.assertFalse(covers("data/reports/2026/", target))

    def test_an_ordinary_target_inside_the_scope_is_still_allowed(self):
        """The denial must not be so wide that the capability stops working."""
        receipt = self.holder().exercise(
            "read", "data/reports/2026/q1.csv", 1, confidence=0.99)
        self.assertTrue(receipt.allowed)

    def test_the_resolver_output_is_what_is_screened_not_the_name(self):
        """A resolver that hands back the climb is screened on what it handed
        back, because `exercise` resolves before it checks."""
        receipt = self.holder().exercise(
            "read", "report-alias", 1, confidence=0.99,
            resolve=lambda name: "data/reports/2026/../../payroll/salaries.csv")
        self.assertFalse(receipt.allowed)



class AGrantCannotBeWidenedAfterItWasApproved(unittest.TestCase):
    """`frozen=True` freezes the reference, not the container behind it.

    The annotation said `frozenset` and nothing made it one, so a caller that
    passed a live `set` kept a name for the object the approved grant held.
    """

    def test_adding_an_action_after_approval_does_not_change_the_grant(self):
        parent = Capability(actions=frozenset({"read"}),
                            resources=frozenset({"data/"}),
                            max_blast=10, budget=100, depth=1)
        held = {"read"}
        child = Capability(actions=held, resources=frozenset({"data/"}),
                           max_blast=5, budget=10, depth=0)
        self.assertEqual(attenuation_gaps(parent, child), [])
        held.add("delete")
        self.assertEqual(child.actions, frozenset({"read"}))
        self.assertEqual(attenuation_gaps(parent, child), [])

    def test_adding_a_resource_after_approval_does_not_widen_the_scope(self):
        scopes = ["data/reports/"]
        holder = Delegation("analyst", Capability(
            actions=frozenset({"read"}), resources=scopes,
            max_blast=100, budget=100, depth=1))
        scopes.append("/etc")
        self.assertFalse(holder.exercise("read", "/etc/shadow", 1,
                                         confidence=0.99).allowed)

    def test_a_capability_is_hashable(self):
        self.assertIsInstance(hash(Capability(actions={"read"},
                                              resources={"data/"})), int)

    def test_a_bare_string_scope_is_still_read_by_the_scope_reader(self):
        # Not coerced here, because `_held_scopes` is the function that
        # decides a string is one tree, and answering for it would retire a
        # refusal this module is written around.
        self.assertIsInstance(Capability(resources="data/").resources, str)

    def test_a_one_shot_iterator_is_still_unreadable(self):
        held = Capability(resources=iter(["data/"]))
        gaps = attenuation_gaps(Capability(actions=frozenset(), resources=held.resources,
                                           max_blast=1, budget=1, depth=2),
                                Capability(actions=frozenset(),
                                           resources=frozenset({"data/"}),
                                           max_blast=1, budget=1, depth=1))
        self.assertTrue(any("could not be read" in gap for gap in gaps))



class TheBudgetIsCheckedAndCommittedInOneStep(unittest.TestCase):
    """`delegate` compared against `remaining()` and then constructed the
    child, and `Delegation.__init__` runs `str(principal)`, which is code the
    caller wrote. A principal name that delegated again saw a total the
    delegation in progress had not been subtracted from."""

    def root(self):
        # The budget is deliberately not equal to any other numeric component
        # here, so the serialization test below can block on the one read that
        # happens inside the critical section and on no other.
        return Delegation("root", Capability(
            actions=frozenset({"read"}), resources=frozenset({"data/"}),
            max_blast=100, budget=101, depth=3))

    def request(self):
        return Capability(actions=frozenset({"read"}),
                          resources=frozenset({"data/"}),
                          max_blast=10, budget=5, depth=2)

    def reentrant(self):
        root = self.root()
        request = self.request()

        class Reenter(object):
            def __init__(self, left):
                self.left = left

            def __str__(self):
                if self.left:
                    root.delegate(Reenter(self.left - 1), request)
                return "child-%d" % self.left

        root.delegate(Reenter(100), request)
        return root

    def test_the_subtree_never_holds_more_than_the_root(self):
        root = self.reentrant()
        self.assertLessEqual(root.committed, root.capability.budget)

    def test_what_is_left_never_goes_negative(self):
        self.assertGreaterEqual(self.reentrant().remaining(), 0)

    def test_the_children_that_were_granted_are_the_ones_recorded(self):
        root = self.reentrant()
        self.assertEqual(root.committed, 5 * len(root.children))

    def test_a_second_caller_waits_rather_than_reading_a_stale_total(self):
        """Deterministic, the way `test_audit_chain` holds `append`.

        `_finite_int` is the first thing `remaining()` calls, and
        `remaining()` is the first thing inside the critical section, so
        blocking it holds the first caller exactly where the total is being
        read and not yet written.
        """
        import threading
        from unittest.mock import patch
        import ai_security.capability_attenuation as module

        root = self.root()
        request = self.request()
        inside = threading.Event()
        release = threading.Event()
        original = module._finite_int

        def gated(value):
            if (threading.current_thread().name == "first"
                    and value == root.capability.budget):
                inside.set()
                if not release.wait(3):
                    raise AssertionError("the first caller was not released")
            return original(value)

        def ask():
            root.delegate("analyst", request)

        with patch.object(module, "_finite_int", gated):
            first = threading.Thread(target=ask, name="first")
            second = threading.Thread(target=ask, name="second")
            first.start()
            try:
                self.assertTrue(inside.wait(3))
                second.start()
                second.join(0.2)
                self.assertTrue(second.is_alive())
            finally:
                release.set()
                first.join(3)
                second.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(root.committed, 10)

    def test_an_ordinary_delegation_still_succeeds(self):
        self.assertTrue(self.root().delegate("analyst", self.request()).ok)


if __name__ == "__main__":
    unittest.main()
