"""
mount_audit.py

Audit mounted mutating routes for effective authentication dependencies.

The audit enumerates mounted routes, checks dependency coverage, and accounts
for runtime dependency overrides. Unreadable methods are treated as mutating;
unreadable dependencies and an empty authentication set cannot establish
coverage. Public exemptions must be explicit and appear in the report.

A declared dependency is insufficient if an override replaces it. Conversely,
matching a dependency name does not prove the dependency implements correct
authentication or authorization. This module checks configuration coverage,
not the complete behavior of an application or its deployment.
See README.md for adapter scope, examples, and framework mappings.
"""

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional

# Methods that can change state. Anything not on this list is still treated as
# mutating, because an unrecognized method is an unknown, and an unknown is not
# a read.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


@dataclass(frozen=True)
class Route:
    """One mounted route, flattened the way the server will actually serve it.

    `router_dependencies` are inherited from the mount point. `dependencies`
    are declared on the route itself. The effective set is the union: that is
    the only set that matters.
    """
    path: str
    methods: tuple = ()
    name: str = ""
    dependencies: tuple = ()
    router_dependencies: tuple = ()
    readable: bool = True          # False when introspection could not read it

    def effective_dependencies(self) -> frozenset:
        return frozenset(self.dependencies) | frozenset(self.router_dependencies)

    def is_mutating(self) -> bool:
        if not self.methods:
            return True            # no methods read means no method ruled out
        return any(str(m).upper() not in SAFE_METHODS for m in self.methods)


@dataclass
class Finding:
    route: str
    methods: tuple
    reason: str


@dataclass
class AuditReport:
    ok: bool
    findings: list = field(default_factory=list)
    covered: list = field(default_factory=list)
    exempted: list = field(default_factory=list)
    read_only: list = field(default_factory=list)
    neutralized: list = field(default_factory=list)
    examined: int = 0
    # Validate the effective inputs and decision boundary explicitly.
    unmeasured: str = ""

    def render(self) -> str:
        lines = []
        if self.unmeasured:
            status = "NOT MEASURED"
        else:
            status = "PASS" if self.ok else "FAIL"
        lines.append(f"mount surface audit: {status}  "
                     f"({len(self.findings)} unguarded, {len(self.covered)} guarded, "
                     f"{len(self.exempted)} exempt, {len(self.read_only)} read only)")
        if self.unmeasured:
            lines.append(f"  no verdict     {self.unmeasured}")
        if self.neutralized:
            lines.append(f"  runtime override neutralizes: {', '.join(sorted(self.neutralized))}")
        for f in self.findings:
            methods = "/".join(f.methods) if f.methods else "UNKNOWN"
            lines.append(f"  UNGUARDED  {methods:<12} {f.route}  <- {f.reason}")
        for path, why in self.exempted:
            lines.append(f"  exempt     {path}  ({why})")
        return "\n".join(lines)


def audit_mount_surface(
    routes: Iterable[Route],
    auth_dependencies: Iterable[str],
    exemptions: Optional[Mapping[str, str]] = None,
    overrides: Optional[Mapping[str, str]] = None,
) -> AuditReport:
    """Report every mutating route not effectively covered by an auth dependency.

    `auth_dependencies` names the callables that actually authenticate.
    `exemptions` maps a route path to the written reason it may be public.
    `overrides` is a runtime replacement map, the shape a test fixture uses to
    stub a dependency. Any auth dependency appearing as a key there is treated
    as neutralized for every route, which is the whole point: the declared
    control is not the effective one.
    """
    # Nothing to iterate is not a clean surface. `routes_from_app` is
    # best-effort introspection against a framework this module does not
    # import, so the commonest way to reach this function with nothing in hand
    # is a read that failed, not an application with no routes. Handing back a
    # PASS for either one is the defect the sibling module states as a rule:
    # an empty bucket is an absence of evidence, not a perfect score.
    if routes is None or auth_dependencies is None:
        return AuditReport(
            ok=False,
            unmeasured="routes or auth dependencies were not supplied, so no "
                       "route was examined and there is no verdict to give")

    declared = {str(d) for d in auth_dependencies}
    override_map = dict(overrides or {})
    neutralized = sorted(declared & set(override_map))
    effective_auth = declared - set(override_map)
    exempt = dict(exemptions or {})

    report = AuditReport(ok=True, neutralized=neutralized)

    for route in routes:
        report.examined += 1
        methods = tuple(str(m).upper() for m in route.methods)

        if not route.readable:
            report.findings.append(Finding(route.path, methods,
                                           "route could not be introspected"))
            continue

        if not route.is_mutating():
            report.read_only.append(route.path)
            continue

        if route.path in exempt:
            report.exempted.append((route.path, exempt[route.path]))
            continue

        deps = route.effective_dependencies()
        if deps & effective_auth:
            report.covered.append(route.path)
            continue

        outranked = sorted(deps & set(neutralized))
        if outranked:
            reason = (f"auth dependency {outranked[0]} is declared but replaced "
                      f"at runtime by {override_map[outranked[0]]}")
        elif not deps:
            reason = "mutating route with no auth dependency on route or mount"
        elif not effective_auth:
            reason = "no effective auth dependency is configured at all"
        else:
            reason = (f"declares {', '.join(sorted(deps))} but none of them authenticate")
        report.findings.append(Finding(route.path, methods, reason))

    if report.examined == 0:
        # An application with genuinely no routes and an introspection that
        # returned nothing are the same three characters from in here, and
        # only one of them is good news. Say which state this is instead of
        # picking the reassuring one.
        report.ok = False
        report.unmeasured = ("no routes were presented, so nothing was "
                             "audited: an empty mount surface and a failed "
                             "read are indistinguishable from here")
        return report

    report.ok = not report.findings
    return report


def routes_from_app(app, router_dependency_names: Optional[Mapping[str, Iterable[str]]] = None):
    """Best-effort introspection of a Starlette or FastAPI style application.

    Duck-typed on purpose so this file stays dependency free and testable: it
    reads `app.routes` and pulls `path`, `methods`, `name`, and dependency
    names off each entry. Anything it cannot read comes back with
    `readable=False`, which the audit counts as unguarded. Guessing would be
    the failure mode this whole file exists to prevent.
    """
    prefix_deps = dict(router_dependency_names or {})
    out = []
    for entry in getattr(app, "routes", []) or []:
        path = getattr(entry, "path", None)
        if not isinstance(path, str):
            out.append(Route(path=repr(entry), readable=False))
            continue
        methods = tuple(getattr(entry, "methods", ()) or ())
        deps = tuple(_dependency_names(entry))
        # Longest prefix wins, never the first one declared.
        #
        # Taking the first match made the audit depend on the order the
        # caller happened to write the mapping in. With a guarded parent
        # router at "/api" and a second router mounted under "/api/reports"
        # with no dependency, a route on the second router matched "/api"
        # first and inherited require_auth from a mount it was never on. The
        # auditor then reported an unauthenticated DELETE route as guarded
        # and the build passed. Reordering the same mapping flipped the same
        # surface to FAIL, which is the tell: an auditor whose verdict moves
        # with dict order is not measuring the surface.
        #
        # That is this module's own thesis turned against it, and it fails
        # open, which is the direction that costs something. Matching the
        # most specific mount is both order independent and correct: it is
        # the mount the server will actually serve the route from.
        inherited = ()
        best_prefix = None
        for prefix, names in prefix_deps.items():
            if path.startswith(prefix) and (best_prefix is None
                                            or len(prefix) > len(best_prefix)):
                best_prefix = prefix
                inherited = tuple(names)
        out.append(Route(path=path, methods=methods,
                         name=str(getattr(entry, "name", "") or ""),
                         dependencies=deps, router_dependencies=inherited))
    return out


def _dependency_names(entry) -> list:
    """Pull dependency callable names off a route entry, tolerating any shape."""
    names = []
    dependant = getattr(entry, "dependant", None)
    for dep in getattr(dependant, "dependencies", ()) or ():
        call = getattr(dep, "call", dep)
        names.append(getattr(call, "__name__", str(call)))
    for dep in getattr(entry, "dependencies", ()) or ():
        call = getattr(dep, "dependency", getattr(dep, "call", dep))
        names.append(getattr(call, "__name__", str(call)))
    return names


if __name__ == "__main__":
    # A synthetic application. Every route of the main API is guarded at the
    # mount point. A second router lacks that dependency, demonstrating an
    # unguarded mount surface in the synthetic fixture.
    main_api = ("require_auth",)
    routes = [
        Route("/api/alerts", ("GET",), "list_alerts", router_dependencies=main_api),
        Route("/api/alerts/{id}/close", ("POST",), "close_alert", router_dependencies=main_api),
        Route("/api/models/reload", ("POST",), "reload_models", router_dependencies=main_api),
        Route("/healthz", ("GET",), "healthz"),
        Route("/login", ("POST",), "login"),
        # The second router. Mounted with no dependency at all.
        Route("/api/reports/list", ("GET",), "list_reports"),
        Route("/api/reports/refresh/run", ("POST",), "refresh_run"),
        Route("/api/reports/purge", ("DELETE",), "purge_reports"),
        # A route the introspector could not read.
        Route("<unreadable mount>", readable=False),
    ]
    exemptions = {"/login": "credential exchange, public by design"}

    print(audit_mount_surface(routes, ["require_auth"], exemptions).render())

    print()
    print("Now the same surface with a test override left in place at runtime:")
    print(audit_mount_surface(
        routes, ["require_auth"], exemptions,
        overrides={"require_auth": "always_allow_stub"},
    ).render())
