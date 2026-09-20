"""Tests for ai_security/mount_audit.py.

The module exists for one finding: authorization is a property of the mounted
surface, not of the file you are reading. A router added later and mounted
without the dependency leaves a state-changing route open while every handler
still reads correctly, and a dependency override left in place at runtime
replaces a real auth check with something that always says yes while the route
still declares the control.

So the property under test throughout is the same one: the auditor checks the
**effective** control and never the declared one, and everything it cannot read
fails closed. Paths here are synthetic and no host, tenant or address appears.
"""

import unittest

from ai_security.mount_audit import _listed  # noqa: F401
from ai_security.mount_audit import (
    SAFE_METHODS,
    AuditReport,
    Finding,
    Route,
    audit_mount_surface,
    routes_from_app,
)

MOUNTED_WITH_AUTH = ("require_auth",)


def main_api_routes():
    """The API whose every route is guarded at the mount point."""
    return [
        Route("/api/alerts", ("GET",), "list_alerts",
              router_dependencies=MOUNTED_WITH_AUTH),
        Route("/api/alerts/{id}/close", ("POST",), "close_alert",
              router_dependencies=MOUNTED_WITH_AUTH),
        Route("/api/models/reload", ("POST",), "reload_models",
              router_dependencies=MOUNTED_WITH_AUTH),
    ]


def second_router_routes():
    """The router added later and mounted with no dependency at all."""
    return [
        Route("/api/reports/list", ("GET",), "list_reports"),
        Route("/api/reports/refresh/run", ("POST",), "refresh_run"),
        Route("/api/reports/purge", ("DELETE",), "purge_reports"),
    ]


def paths(findings):
    return sorted(f.route for f in findings)


class TheGapIsInTheMountNotInTheHandler(unittest.TestCase):
    def test_a_fully_guarded_surface_passes(self):
        report = audit_mount_surface(main_api_routes(), ["require_auth"])
        self.assertTrue(report.ok)
        self.assertEqual(report.findings, [])

    def test_a_router_mounted_without_the_dependency_is_reported(self):
        report = audit_mount_surface(main_api_routes() + second_router_routes(),
                                     ["require_auth"])
        self.assertFalse(report.ok)
        self.assertEqual(paths(report.findings),
                         ["/api/reports/purge", "/api/reports/refresh/run"])

    def test_the_finding_says_the_gap_is_on_the_route_or_the_mount(self):
        report = audit_mount_surface(second_router_routes(), ["require_auth"])
        for finding in report.findings:
            self.assertIn("no auth dependency on route or mount", finding.reason)

    def test_a_dependency_inherited_from_the_mount_point_counts_as_coverage(self):
        report = audit_mount_surface(
            [Route("/api/alerts/{id}/close", ("POST",),
                   router_dependencies=MOUNTED_WITH_AUTH)],
            ["require_auth"])
        self.assertTrue(report.ok)
        self.assertEqual(report.covered, ["/api/alerts/{id}/close"])

    def test_a_dependency_declared_on_the_route_itself_counts_as_coverage(self):
        report = audit_mount_surface(
            [Route("/api/alerts/{id}/close", ("POST",), dependencies=("require_auth",))],
            ["require_auth"])
        self.assertTrue(report.ok)

    def test_the_effective_set_is_the_union_of_route_and_mount_dependencies(self):
        route = Route("/api/x", ("POST",), dependencies=("rate_limit",),
                      router_dependencies=("require_auth",))
        self.assertEqual(route.effective_dependencies(),
                         frozenset({"rate_limit", "require_auth"}))

    def test_a_route_declaring_a_dependency_that_does_not_authenticate_is_reported(self):
        report = audit_mount_surface(
            [Route("/api/x", ("POST",), dependencies=("rate_limit",))],
            ["require_auth"])
        self.assertFalse(report.ok)
        self.assertIn("none of them authenticate", report.findings[0].reason)

    def test_the_report_names_the_methods_of_each_unguarded_route(self):
        report = audit_mount_surface(
            [Route("/api/reports/purge", ("DELETE",))], ["require_auth"])
        self.assertEqual(report.findings[0].methods, ("DELETE",))

    def test_a_finding_is_a_structure_a_build_can_act_on(self):
        report = audit_mount_surface([Route("/api/x", ("POST",))], ["require_auth"])
        self.assertIsInstance(report, AuditReport)
        self.assertIsInstance(report.findings[0], Finding)


class ARuntimeOverrideNeutralizesADeclaredControl(unittest.TestCase):
    """The reason this module checks the effective control and not the declared one.

    A dependency-override map, the shape a test suite installs to stub out
    authentication, left in place at runtime replaces the real check with
    something that always says yes. The route still declares the control. The
    control is no longer the thing that runs.
    """

    def test_a_route_whose_auth_dependency_is_overridden_is_reported_as_unguarded(self):
        routes = [Route("/api/alerts/{id}/close", ("POST",),
                        router_dependencies=MOUNTED_WITH_AUTH)]
        clean = audit_mount_surface(routes, ["require_auth"])
        overridden = audit_mount_surface(routes, ["require_auth"],
                                         overrides={"require_auth": "always_allow_stub"})
        self.assertTrue(clean.ok)
        self.assertFalse(overridden.ok)
        self.assertEqual(paths(overridden.findings), ["/api/alerts/{id}/close"])

    def test_the_finding_names_the_declared_control_and_what_replaced_it(self):
        report = audit_mount_surface(
            [Route("/api/alerts/{id}/close", ("POST",),
                   router_dependencies=MOUNTED_WITH_AUTH)],
            ["require_auth"], overrides={"require_auth": "always_allow_stub"})
        reason = report.findings[0].reason
        self.assertIn("require_auth", reason)
        self.assertIn("declared but replaced at runtime", reason)
        self.assertIn("always_allow_stub", reason)

    def test_the_neutralized_control_is_listed_on_the_report_itself(self):
        report = audit_mount_surface(
            main_api_routes(), ["require_auth"],
            overrides={"require_auth": "always_allow_stub"})
        self.assertEqual(report.neutralized, ["require_auth"])

    def test_the_neutralized_control_is_printed_where_a_reviewer_will_see_it(self):
        rendered = audit_mount_surface(
            main_api_routes(), ["require_auth"],
            overrides={"require_auth": "always_allow_stub"}).render()
        self.assertIn("runtime override neutralizes: require_auth", rendered)

    def test_an_override_of_an_unrelated_dependency_neutralizes_nothing(self):
        report = audit_mount_surface(
            main_api_routes(), ["require_auth"],
            overrides={"get_db_session": "in_memory_session"})
        self.assertTrue(report.ok)
        self.assertEqual(report.neutralized, [])

    def test_a_second_auth_dependency_still_covers_a_route_when_the_first_is_overridden(self):
        report = audit_mount_surface(
            [Route("/api/x", ("POST",), dependencies=("require_auth", "require_mtls"))],
            ["require_auth", "require_mtls"],
            overrides={"require_auth": "always_allow_stub"})
        self.assertTrue(report.ok)
        self.assertEqual(report.neutralized, ["require_auth"])

    def test_overriding_every_auth_dependency_leaves_the_whole_surface_unguarded(self):
        report = audit_mount_surface(
            main_api_routes(), ["require_auth"],
            overrides={"require_auth": "always_allow_stub"})
        self.assertEqual(report.covered, [])
        self.assertEqual(paths(report.findings),
                         ["/api/alerts/{id}/close", "/api/models/reload"])


class EverythingUnreadableFailsClosed(unittest.TestCase):
    def test_a_route_that_could_not_be_introspected_is_reported_as_unguarded(self):
        report = audit_mount_surface([Route("<unreadable mount>", readable=False)],
                                     ["require_auth"])
        self.assertFalse(report.ok)
        self.assertIn("could not be introspected", report.findings[0].reason)

    def test_an_unreadable_route_is_reported_even_when_it_declares_auth(self):
        report = audit_mount_surface(
            [Route("<unreadable mount>", ("GET",), dependencies=("require_auth",),
                   readable=False)],
            ["require_auth"])
        self.assertFalse(report.ok)

    def test_a_route_with_no_methods_read_is_treated_as_mutating(self):
        self.assertTrue(Route("/api/x").is_mutating())

    def test_an_unrecognized_method_is_treated_as_mutating(self):
        self.assertTrue(Route("/api/x", ("PROPFIND",)).is_mutating())
        self.assertNotIn("PROPFIND", SAFE_METHODS)

    def test_an_empty_auth_dependency_set_certifies_nothing(self):
        report = audit_mount_surface(main_api_routes(), [])
        self.assertFalse(report.ok)
        for finding in report.findings:
            self.assertIn("no effective auth dependency is configured at all",
                          finding.reason)

    def test_a_route_that_could_not_be_read_is_a_finding(self):
        report = audit_mount_surface([Route("/x", ("POST",), readable=False)],
                                     ["require_auth"])
        self.assertFalse(report.ok)


class AnEmptySurfaceIsNotMeasuredRatherThanClean(unittest.TestCase):

    def test_an_empty_surface_is_not_measured_rather_than_passed(self):
        report = audit_mount_surface([], ["require_auth"])
        self.assertFalse(report.ok)
        self.assertTrue(report.unmeasured)
        self.assertEqual(report.examined, 0)

    def test_an_unmeasured_report_does_not_render_as_a_pass(self):
        rendered = audit_mount_surface([], ["require_auth"]).render()
        self.assertIn("NOT MEASURED", rendered)
        self.assertNotIn("PASS", rendered)

    def test_a_surface_that_was_measured_and_is_clean_still_passes(self):
        """The other half of the distinction, and the reason it is a distinction.

        Measured and none found must stay separable from not measured. If this
        test and the one above both came out the same way the fix would have
        replaced one collapsed pair with another.
        """
        report = audit_mount_surface([Route("/api/x", ("GET",))], ["require_auth"])
        self.assertTrue(report.ok)
        self.assertFalse(report.unmeasured)
        self.assertEqual(report.examined, 1)
        self.assertIn("PASS", report.render())

    def test_routes_of_none_is_refused_rather_than_raising(self):
        report = audit_mount_surface(None, ["require_auth"])
        self.assertFalse(report.ok)
        self.assertTrue(report.unmeasured)

    def test_auth_dependencies_of_none_is_refused_rather_than_raising(self):
        report = audit_mount_surface([Route("/api/x", ("POST",))], None)
        self.assertFalse(report.ok)
        self.assertTrue(report.unmeasured)

    def test_the_safe_methods_are_the_four_that_do_not_change_state(self):
        self.assertEqual(SAFE_METHODS, frozenset({"GET", "HEAD", "OPTIONS", "TRACE"}))

    def test_a_lowercase_method_is_still_recognized_as_safe(self):
        self.assertFalse(Route("/api/x", ("get",)).is_mutating())

    def test_a_route_mixing_a_safe_and_a_mutating_method_counts_as_mutating(self):
        self.assertTrue(Route("/api/x", ("GET", "POST")).is_mutating())

    def test_a_read_only_route_is_set_aside_rather_than_flagged(self):
        report = audit_mount_surface([Route("/api/alerts", ("GET",))], ["require_auth"])
        self.assertTrue(report.ok)
        self.assertEqual(report.read_only, ["/api/alerts"])


class EveryExemptionIsNamedAndPrinted(unittest.TestCase):
    def test_an_exempt_route_does_not_count_as_a_finding(self):
        report = audit_mount_surface([Route("/login", ("POST",))], ["require_auth"],
                                     {"/login": "credential exchange, public by design"})
        self.assertTrue(report.ok)

    def test_the_exemption_and_its_written_reason_are_carried_on_the_report(self):
        report = audit_mount_surface([Route("/login", ("POST",))], ["require_auth"],
                                     {"/login": "credential exchange, public by design"})
        self.assertEqual(report.exempted,
                         [("/login", "credential exchange, public by design")])

    def test_the_exemption_is_printed_because_an_unseen_one_hides_the_next_gap(self):
        rendered = audit_mount_surface(
            [Route("/login", ("POST",))], ["require_auth"],
            {"/login": "credential exchange, public by design"}).render()
        self.assertIn("exempt     /login", rendered)
        self.assertIn("credential exchange, public by design", rendered)

    def test_an_exemption_for_one_path_does_not_cover_a_neighbouring_path(self):
        report = audit_mount_surface(
            [Route("/login", ("POST",)), Route("/login/reset", ("POST",))],
            ["require_auth"], {"/login": "credential exchange, public by design"})
        self.assertFalse(report.ok)
        self.assertEqual(paths(report.findings), ["/login/reset"])

    def test_an_exemption_for_an_unmounted_path_exempts_nothing(self):
        report = audit_mount_surface([Route("/api/x", ("POST",))], ["require_auth"],
                                     {"/login": "public by design"})
        self.assertFalse(report.ok)
        self.assertEqual(report.exempted, [])

    def test_an_exemption_does_not_rescue_a_route_that_could_not_be_read(self):
        report = audit_mount_surface([Route("/login", readable=False)], ["require_auth"],
                                     {"/login": "public by design"})
        self.assertFalse(report.ok)


class IntrospectionIsBestEffortAndSaysSoWhenItFails(unittest.TestCase):
    class _Entry:
        def __init__(self, path, methods, name=""):
            self.path = path
            self.methods = methods
            self.name = name

    class _App:
        def __init__(self, routes):
            self.routes = routes

    def test_routes_are_read_off_an_application_object(self):
        app = self._App([self._Entry("/api/alerts", {"GET"}, "list_alerts")])
        routes = routes_from_app(app)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].path, "/api/alerts")
        self.assertEqual(routes[0].methods, ("GET",))
        self.assertEqual(routes[0].name, "list_alerts")

    def test_a_mount_prefix_lends_its_dependencies_to_the_routes_beneath_it(self):
        app = self._App([self._Entry("/api/alerts/close", ["POST"])])
        routes = routes_from_app(app, {"/api/": ["require_auth"]})
        self.assertEqual(routes[0].router_dependencies, ("require_auth",))

    def test_a_route_outside_every_known_prefix_inherits_nothing(self):
        app = self._App([self._Entry("/internal/purge", ["DELETE"])])
        routes = routes_from_app(app, {"/api/": ["require_auth"]})
        self.assertEqual(routes[0].router_dependencies, ())

    def test_an_entry_with_no_readable_path_comes_back_marked_unreadable(self):
        app = self._App([object()])
        routes = routes_from_app(app)
        self.assertEqual(len(routes), 1)
        self.assertFalse(routes[0].readable)

    def test_an_unreadable_entry_becomes_a_finding_rather_than_a_silent_skip(self):
        report = audit_mount_surface(routes_from_app(self._App([object()])),
                                     ["require_auth"])
        self.assertFalse(report.ok)
        self.assertEqual(len(report.findings), 1)

    def test_an_application_with_no_routes_attribute_yields_nothing(self):
        self.assertEqual(routes_from_app(object()), [])

    def test_dependency_names_are_pulled_off_a_route_entry(self):
        class _Dep:
            def __init__(self, call):
                self.dependency = call

        def require_auth():
            return None

        entry = self._Entry("/api/x", ["POST"])
        entry.dependencies = [_Dep(require_auth)]
        routes = routes_from_app(self._App([entry]))
        self.assertEqual(routes[0].dependencies, ("require_auth",))

    def test_an_introspected_surface_audits_end_to_end(self):
        guarded = self._Entry("/api/alerts/close", ["POST"])
        unguarded = self._Entry("/reports/purge", ["DELETE"])
        app = self._App([guarded, unguarded])
        report = audit_mount_surface(routes_from_app(app, {"/api/": ["require_auth"]}),
                                     ["require_auth"])
        self.assertFalse(report.ok)
        self.assertEqual(paths(report.findings), ["/reports/purge"])


class TheReportReadsAsAReview(unittest.TestCase):
    def _mixed_surface(self):
        return audit_mount_surface(
            main_api_routes() + second_router_routes()
            + [Route("/healthz", ("GET",), "healthz"), Route("/login", ("POST",), "login")],
            ["require_auth"],
            {"/login": "credential exchange, public by design"})

    def test_a_failing_audit_says_fail_and_counts_each_category(self):
        rendered = self._mixed_surface().render()
        self.assertIn("mount surface audit: FAIL", rendered)
        self.assertIn("2 unguarded", rendered)
        self.assertIn("2 guarded", rendered)
        self.assertIn("1 exempt", rendered)
        self.assertIn("3 read only", rendered)

    def test_a_passing_audit_says_pass(self):
        rendered = audit_mount_surface(main_api_routes(), ["require_auth"]).render()
        self.assertIn("mount surface audit: PASS", rendered)

    def test_every_unguarded_route_is_printed_with_its_method_and_reason(self):
        rendered = self._mixed_surface().render()
        self.assertIn("UNGUARDED  DELETE", rendered)
        self.assertIn("/api/reports/purge", rendered)
        self.assertIn("UNGUARDED  POST", rendered)

    def test_an_unreadable_route_prints_its_methods_as_unknown(self):
        rendered = audit_mount_surface([Route("<unreadable mount>", readable=False)],
                                       ["require_auth"]).render()
        self.assertIn("UNGUARDED  UNKNOWN", rendered)

    def test_a_clean_report_prints_no_override_line(self):
        self.assertNotIn("neutralizes",
                         audit_mount_surface(main_api_routes(), ["require_auth"]).render())

    def test_the_audit_is_deterministic_for_the_same_surface(self):
        first = self._mixed_surface().render()
        second = self._mixed_surface().render()
        self.assertEqual(first, second)


class TheMostSpecificMountWinsRatherThanTheFirstDeclared(unittest.TestCase):
    """The auditor's verdict must not depend on the order of its own mapping.

    This is the module's own finding pointed back at the module. A guarded
    parent router at "/api" and a second router mounted under "/api/reports"
    with no dependency is exactly the shape the file was written for. Taking
    the first prefix that matched meant a route on the unguarded second router
    matched "/api" first and inherited require_auth from a mount it was never
    on, so an unauthenticated DELETE route was reported as guarded and the
    build passed. Writing the same two entries in the other order produced the
    correct FAIL on an identical surface.

    An auditor that fails open on dict ordering is worse than no auditor,
    because the PASS is the answer people act on.
    """

    class _Entry:
        def __init__(self, path, methods):
            self.path = path
            self.methods = methods
            self.name = path
            self.dependencies = ()

    class _App:
        def __init__(self, routes):
            self.routes = routes

    def _surface(self):
        return self._App([self._Entry("/api/alerts/close", {"POST"}),
                          self._Entry("/api/reports/purge", {"DELETE"})])

    GUARDED_PARENT_FIRST = {"/api": ["require_auth"], "/api/reports": []}
    UNGUARDED_CHILD_FIRST = {"/api/reports": [], "/api": ["require_auth"]}

    def _audit(self, mapping):
        return audit_mount_surface(
            routes_from_app(self._surface(), mapping), ["require_auth"])

    def test_the_unguarded_child_route_is_found_whichever_order_is_declared(self):
        for label, mapping in (("parent first", self.GUARDED_PARENT_FIRST),
                               ("child first", self.UNGUARDED_CHILD_FIRST)):
            with self.subTest(order=label):
                report = self._audit(mapping)
                self.assertFalse(report.ok)
                self.assertEqual([f.route for f in report.findings],
                                 ["/api/reports/purge"])

    def test_both_orders_produce_the_same_verdict(self):
        first = self._audit(self.GUARDED_PARENT_FIRST)
        second = self._audit(self.UNGUARDED_CHILD_FIRST)
        self.assertEqual(first.ok, second.ok)
        self.assertEqual([f.route for f in first.findings],
                         [f.route for f in second.findings])

    def test_the_route_on_the_guarded_parent_is_still_covered(self):
        for mapping in (self.GUARDED_PARENT_FIRST, self.UNGUARDED_CHILD_FIRST):
            with self.subTest(mapping=sorted(mapping)):
                self.assertIn("/api/alerts/close", self._audit(mapping).covered)

    def test_a_deeper_mount_inherits_the_deeper_dependency_set(self):
        app = self._App([self._Entry("/api/reports/purge", {"DELETE"})])
        routes = routes_from_app(app, {"/api": ["require_auth"],
                                       "/api/reports": ["require_report_auth"]})
        self.assertEqual(routes[0].router_dependencies, ("require_report_auth",))



class MountInheritanceRequiresPathBoundaries(unittest.TestCase):
    def test_equivalent_mount_spellings_cannot_add_auth_by_order(self):
        from types import SimpleNamespace
        app = SimpleNamespace(routes=[SimpleNamespace(path="/api/x", methods=("POST",))])
        for mapping in ({"/api": ["auth"], "/api/": []}, {"/api/": [], "/api": ["auth"]}):
            report = audit_mount_surface(routes_from_app(app, mapping), ["auth"])
            self.assertFalse(report.ok)
            self.assertEqual(report.covered, [])
        for mapping in ({"/api": ["auth"], "/api/": ["auth"]}, {"/api/": ["auth"], "/api": ["auth"]}):
            self.assertTrue(audit_mount_surface(routes_from_app(app, mapping), ["auth"]).ok)

    def test_mount_names_do_not_cover_neighboring_prefixes(self):
        from types import SimpleNamespace
        app = SimpleNamespace(routes=[SimpleNamespace(path=p, methods=("POST",))
            for p in ("/api", "/api/x", "/apiary/x", "/api-v2/x")])
        for prefix in ("/api", "/api/"):
            report = audit_mount_surface(routes_from_app(app, {prefix: ["auth"]}), ["auth"])
            self.assertEqual(report.covered, ["/api", "/api/x"])
            self.assertEqual([f.route for f in report.findings], ["/apiary/x", "/api-v2/x"])
        report = audit_mount_surface(routes_from_app(app, {"/": ["auth"]}), ["auth"])
        self.assertEqual(len(report.covered), 4)


class UnreadableInputIsNotACleanSurface(unittest.TestCase):
    """The same rule the sibling gates apply to their sequence arguments.

    `blackgate/detection_gap.score`, `blackgate/prohibitions.resolve` and
    `blackgate/scope_gate.Gate._never_target_entries` each coerce the sequence
    they are handed and refuse when it cannot be read. This module handled
    `routes is None` and nothing else, so every other unreadable shape raised
    out of the middle of the audit, and an auditor that raises is one except
    clause away from an auditor that reports nothing wrong.
    """

    def test_a_single_route_passed_without_a_list_is_not_measured(self):
        report = audit_mount_surface(Route("/api/purge", ("DELETE",)), ["require_auth"])
        self.assertFalse(report.ok)
        self.assertIn("could not be read", report.unmeasured)
        self.assertIn("NOT MEASURED", report.render())

    def test_routes_that_cannot_be_walked_are_not_measured(self):
        for value in (42, object(), 3.5):
            report = audit_mount_surface(value, ["require_auth"])
            self.assertFalse(report.ok)
            self.assertTrue(report.unmeasured)

    def test_auth_dependencies_that_cannot_be_walked_are_not_measured(self):
        report = audit_mount_surface(main_api_routes(), 42)
        self.assertFalse(report.ok)
        self.assertTrue(report.unmeasured)

    def test_an_override_map_that_cannot_be_read_is_not_measured(self):
        report = audit_mount_surface(main_api_routes(), ["require_auth"],
                                     overrides=42)
        self.assertFalse(report.ok)
        self.assertIn("effective", report.unmeasured)

    def test_an_entry_that_is_not_a_route_is_a_finding(self):
        report = audit_mount_surface(main_api_routes() + [object()], ["require_auth"])
        self.assertFalse(report.ok)
        self.assertEqual(len(report.findings), 1)
        self.assertIn("no readable path", report.findings[0].reason)

    def test_a_route_whose_methods_cannot_be_read_is_mutating(self):
        self.assertTrue(Route("/x", methods=42).is_mutating())
        self.assertTrue(Route("/x", methods=object()).is_mutating())

    def test_a_route_whose_fields_cannot_be_read_is_unguarded(self):
        route = Route("/api/purge", ("DELETE",), dependencies=42,
                      router_dependencies=("require_auth",))
        report = audit_mount_surface([route], ["require_auth"])
        self.assertFalse(report.ok)
        self.assertEqual(report.covered, [])
        self.assertIn("could not be read", report.findings[0].reason)

    def test_an_unreadable_dependency_set_names_no_dependency(self):
        self.assertEqual(Route("/x", dependencies=42).effective_dependencies(),
                         frozenset())
        self.assertFalse(Route("/x", dependencies=42).legible())
        self.assertTrue(Route("/x", ("GET",), dependencies=("a",)).legible())

    def test_introspection_reports_an_unreadable_method_list_as_unreadable(self):
        from types import SimpleNamespace
        app = SimpleNamespace(routes=[
            SimpleNamespace(path="/api/purge", methods=42, name="purge")])
        routes = routes_from_app(app)
        self.assertEqual(len(routes), 1)
        self.assertFalse(routes[0].readable)
        self.assertFalse(audit_mount_surface(routes, ["require_auth"]).ok)

    def test_introspection_reports_an_unreadable_dependency_list_as_unreadable(self):
        from types import SimpleNamespace
        app = SimpleNamespace(routes=[
            SimpleNamespace(path="/api/purge", methods=("DELETE",), dependencies=7)])
        routes = routes_from_app(app)
        self.assertFalse(routes[0].readable)

    def test_an_app_whose_routes_cannot_be_walked_is_one_unreadable_route(self):
        from types import SimpleNamespace
        routes = routes_from_app(SimpleNamespace(routes=7))
        self.assertEqual(len(routes), 1)
        self.assertFalse(routes[0].readable)
        self.assertFalse(audit_mount_surface(routes, ["require_auth"]).ok)

    def test_a_mount_map_that_cannot_be_read_lends_no_authority(self):
        from types import SimpleNamespace
        app = SimpleNamespace(routes=[
            SimpleNamespace(path="/api/purge", methods=("DELETE",))])
        routes = routes_from_app(app, 42)
        self.assertEqual(routes[0].router_dependencies, ())
        self.assertFalse(audit_mount_surface(routes, ["require_auth"]).ok)


class AFieldThatRefusesToBeWalkedIsUnreadable(unittest.TestCase):
    """The unreadable case is the one this module was missing, and it is wider
    than `TypeError`. A routes attribute backed by anything real refuses in its
    own currency, and `except TypeError` let every one of those out of the
    middle of the audit."""

    class RaisingSequence(object):
        def __iter__(self):
            raise RuntimeError("the driver went away mid-read")

    def test_listed_reports_unreadable_rather_than_raising(self):
        self.assertIsNone(_listed(self.RaisingSequence()))

    def test_the_audit_refuses_rather_than_raising(self):
        raising = self.RaisingSequence()
        self.assertFalse(audit_mount_surface(raising, ["auth"]).ok)
        self.assertFalse(
            audit_mount_surface([Route("/a", ("POST",))], raising).ok)
        self.assertFalse(
            audit_mount_surface([Route("/a", ("POST",), dependencies=raising)],
                                ["auth"]).ok)

    def test_the_readable_surface_is_unaffected(self):
        self.assertIsNone(_listed(42))
        self.assertEqual(_listed(None), ())
        self.assertEqual(_listed("a"), ("a",))


class ARouteFieldThatEmptiesAsItIsReadIsNotAReading(unittest.TestCase):
    """Every caller reads the same field more than once.

    `Route.legible` reads all three fields, `Route.is_mutating` reads
    `methods` again and `effective_dependencies` reads the other two again. A
    generator answers the first read with its contents and every read after it
    with nothing, so a route was reported legible on a dependency list that
    `effective_dependencies` then saw as empty, and the audit printed
    "mutating route with no auth dependency" over a route that declared one.
    An answer that changes between two reads of one field is not a reading of
    that field.
    """

    def test_listed_reads_a_one_shot_iterator_as_unreadable(self):
        self.assertIsNone(_listed(iter(["require_auth"])))
        self.assertIsNone(_listed(x for x in ["POST"]))

    def test_a_field_that_fails_partway_through_is_unreadable(self):
        """The half of `_listed` that the one-shot guard does not shadow.

        A field whose `__iter__` raises never reaches the second read at all.
        A cursor is the other shape: `iter()` hands back a reader and the
        driver fails on the row after that, and a partial read of a dependency
        list is not a dependency list.
        """

        class Cursor(object):
            def __iter__(self):
                return self.rows()

            def rows(self):
                yield "require_auth"
                raise RuntimeError("the driver went away mid-read")

        self.assertIsNone(_listed(Cursor()))
        report = audit_mount_surface(
            [Route("/a", ("POST",), dependencies=Cursor())], ["require_auth"])
        self.assertFalse(report.ok)

    def test_listed_still_reads_the_shapes_it_is_meant_to(self):
        self.assertEqual(_listed(None), ())
        self.assertEqual(_listed("a"), ("a",))
        self.assertEqual(_listed(["a", "b"]), ("a", "b"))
        self.assertEqual(_listed(("a",)), ("a",))
        self.assertIsNone(_listed(42))

    def test_a_route_built_from_generators_is_not_legible(self):
        route = Route("/danger", methods=(m for m in ["POST"]),
                      dependencies=(d for d in ["require_auth"]))
        self.assertFalse(route.legible())

    def test_the_audit_reports_such_a_route_rather_than_clearing_it(self):
        report = audit_mount_surface(
            [Route("/danger", methods=(m for m in ["POST"]),
                   dependencies=(d for d in ["require_auth"]))],
            ["require_auth"])
        self.assertFalse(report.ok)
        self.assertEqual(len(report.findings), 1)
        self.assertIn("could not be read", report.findings[0].reason)

    def test_a_route_surface_that_empties_as_it_is_read_is_not_measured(self):
        report = audit_mount_surface(
            iter([Route("/a", ("POST",), dependencies=("require_auth",))]),
            ["require_auth"])
        self.assertFalse(report.ok)
        self.assertTrue(report.unmeasured)


class AMountDependencyListIsReadTheSameWayEveryTime(unittest.TestCase):
    """The verdict cannot move with how the dependency list was spelled."""

    class Entry(object):
        def __init__(self, path, methods):
            self.path = path
            self.methods = methods
            self.dependencies = ()
            self.name = path

    class App(object):
        def __init__(self, routes):
            self.routes = routes

    def _app(self):
        return AMountDependencyListIsReadTheSameWayEveryTime.App([
            AMountDependencyListIsReadTheSameWayEveryTime.Entry("/api/a", ["POST"]),
            AMountDependencyListIsReadTheSameWayEveryTime.Entry("/api/b", ["POST"]),
            AMountDependencyListIsReadTheSameWayEveryTime.Entry("/api/c", ["DELETE"]),
        ])

    def test_a_list_of_names_guards_every_route_under_the_mount(self):
        routes = routes_from_app(self._app(), {"/api": ["require_auth"]})
        self.assertTrue(audit_mount_surface(routes, ["require_auth"]).ok)

    def test_a_bare_string_is_one_dependency_and_not_its_letters(self):
        routes = routes_from_app(self._app(), {"/api": "require_auth"})
        self.assertEqual(routes[0].router_dependencies, ("require_auth",))
        self.assertTrue(audit_mount_surface(routes, ["require_auth"]).ok)

    def test_a_list_read_once_lends_no_authority_to_any_route(self):
        names = (name for name in ["require_auth"])
        routes = routes_from_app(self._app(), {"/api": names})
        self.assertEqual([route.router_dependencies for route in routes],
                         [(), (), ()])

    def test_the_answer_does_not_change_between_two_calls(self):
        mapping = {"/api": (name for name in ["require_auth"])}
        first = [route.router_dependencies for route in routes_from_app(self._app(), mapping)]
        second = [route.router_dependencies for route in routes_from_app(self._app(), mapping)]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
