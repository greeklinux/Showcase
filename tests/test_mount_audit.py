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


if __name__ == "__main__":
    unittest.main()
