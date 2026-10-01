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


def _listed(value):
    """One field that was meant to be a list of entries, as that list.

    `None` comes back as the empty tuple, a bare string or bytes comes back as
    a one-element tuple, and anything that cannot be walked at all comes back
    as `None`, which every caller below reads as "this could not be read" and
    never as "this was empty".

    The single-element case is the typo `blackgate/scope_gate.py` names: a
    one-element tuple written without its trailing comma is a string, and a
    string is iterable, so a loop over it silently walks single characters.
    The unreadable case is the one this module was missing. Three sibling
    gates, `blackgate/detection_gap.score`, `blackgate/prohibitions.resolve`
    and `blackgate/scope_gate.Gate._never_target_entries`, all coerce their
    sequence argument and refuse when it cannot be read. This one iterated
    whatever it was handed, so `audit_mount_surface(Route(...), [...])` and an
    application whose `routes` attribute is not a sequence raised TypeError out
    of the middle of the audit rather than returning the report that says so.
    A raising auditor is one except clause away from an auditor that reports
    nothing wrong.

    The clause below is `Exception` and not `TypeError`. A routes attribute
    backed by anything real refuses in its own currency: a lazily materialised
    response raises whatever it wraps and a cursor raises the driver's error.
    Only a hand-written wrong type raises `TypeError`, and that is the one
    shape a failed read was never going to arrive as.

    A field that is its own iterator also comes back as `None`. Every caller
    below reads the same field more than once: `Route.legible` reads all three,
    `Route.is_mutating` reads `methods` again and `effective_dependencies`
    reads the other two again. A generator answers the first read with its
    contents and every read after it with nothing, so one route was reported
    legible on a dependency list that `effective_dependencies` then saw as
    empty, and the audit printed "mutating route with no auth dependency" over
    a route that declared one. An answer that changes between two reads of the
    same field is not a reading of that field, and the honest name for it is
    the one this function already has for a field it cannot read.
    """
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    try:
        if iter(value) is value:
            return None
    except Exception:
        return None
    try:
        return tuple(value)
    except Exception:
        return None


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

    def legible(self) -> bool:
        """True when both dependency fields and the method list can be walked.

        A route whose fields cannot be read is not a route with no dependencies
        and no methods, which is what iterating them and letting the TypeError
        escape amounted to from the caller's side. `readable` already carries
        the introspector's own verdict; this carries the one the audit can
        reach by trying.
        """
        return (_listed(self.methods) is not None
                and _listed(self.dependencies) is not None
                and _listed(self.router_dependencies) is not None)

    def effective_dependencies(self) -> frozenset:
        """The union of the two declared sets, or the empty set when either
        cannot be read. An unreadable set names no dependency, and naming no
        dependency is what `audit_mount_surface` reports as unguarded."""
        declared = _listed(self.dependencies) or ()
        inherited = _listed(self.router_dependencies) or ()
        # Coerced to text, because a dependency name that arrived as bytes or
        # as an int is sorted and joined into a finding's reason further down,
        # and a `str.join` over a bytes member raised TypeError there: the
        # audit fell over while writing the sentence that says the route is
        # unguarded.
        return frozenset(str(name) for name in declared) | frozenset(
            str(name) for name in inherited)

    def is_mutating(self) -> bool:
        methods = _listed(self.methods)
        if methods is None:
            return True            # a method list that cannot be read rules nothing out
        if not methods:
            return True            # no methods read means no method ruled out
        return any(str(m).upper() not in SAFE_METHODS for m in methods)


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

    # The same rule one step further out. `routes is None` was handled from the
    # first version of this file and every other unreadable shape was not, so
    # `audit_mount_surface(Route(...), [...])`, the one-element-tuple typo, and
    # an application whose `routes` attribute is not a sequence all raised
    # TypeError out of the audit instead of returning the card that says
    # nothing was measured.
    listed_routes = _listed(routes)
    listed_auth = _listed(auth_dependencies)
    if listed_routes is None or listed_auth is None:
        return AuditReport(
            ok=False,
            unmeasured="routes or auth dependencies could not be read as a "
                       "list, so no route was examined and there is no verdict "
                       "to give")
    try:
        override_map = dict(overrides or {})
        exempt = dict(exemptions or {})
    except (TypeError, ValueError):
        # An override map that cannot be read is the one input that can turn a
        # guarded surface into an unguarded one, so a read that fails on it is
        # the last thing that may be treated as an empty map.
        return AuditReport(
            ok=False,
            unmeasured="the override or exemption map could not be read, so a "
                       "declared dependency could not be shown to be the "
                       "effective one")

    # Keyed the way every other dependency name in this module is keyed.
    #
    # The annotation says `Mapping[str, str]` and the framework this models
    # keys the same map by the callable: `app.dependency_overrides[
    # require_auth] = always_allow_stub` is the line in every test fixture
    # that produces one. `declared` is built from `str(d)` and the route side
    # comes from `_dependency_names`, which is `getattr(call, "__name__",
    # str(call))`, so both sides hold the name `require_auth` while the
    # override map held the function object. `declared & set(override_map)`
    # was the intersection of a set of strings with a set of functions, which
    # is empty for every input, so `neutralized` was empty, `effective_auth`
    # kept the dependency that had been replaced, and the audit returned PASS
    # over a surface whose authentication was a stub. It fails open, and it
    # fails open on the one call shape the docstring names.
    #
    # `_dependency_name` is the one reading, used on the declared list, on
    # the override keys and on the override values, so a fixture that keys by
    # callable and one that keys by name produce the same verdict and the
    # same sentence. A map that mixes the two is read the same way as well.
    declared = {_dependency_name(d) for d in listed_auth}
    override_map = {_dependency_name(k): _dependency_name(v)
                    for k, v in override_map.items()}
    neutralized = sorted(declared & set(override_map))
    effective_auth = declared - set(override_map)

    report = AuditReport(ok=True, neutralized=neutralized)

    for route in listed_routes:
        report.examined += 1
        # Every attribute below belongs to a caller-supplied object, so it is
        # read defensively and a route that cannot be read is a finding rather
        # than an exception. This loop previously took `route.methods` and
        # `route.path` raw, and an entry that was not a Route ended the audit.
        methods = tuple(str(m).upper() for m in (_listed(getattr(route, "methods", ())) or ()))
        path = getattr(route, "path", None)
        if not isinstance(path, str):
            report.findings.append(Finding(repr(route), methods,
                                           "route entry carries no readable path"))
            continue

        if not getattr(route, "readable", False):
            report.findings.append(Finding(path, methods,
                                           "route could not be introspected"))
            continue

        if not isinstance(route, Route) or not route.legible():
            report.findings.append(Finding(
                path, methods,
                "route fields could not be read, so no dependency on it has "
                "been shown to authenticate"))
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
    try:
        prefix_deps = dict(router_dependency_names or {})
    except (TypeError, ValueError):
        # A mount map that cannot be read lends no authority to anything. It is
        # the input that turns an unguarded route into a guarded one, so the
        # only safe reading of an unreadable one is that it inherits nothing.
        prefix_deps = {}
    out = []
    # `app.routes` is whatever the framework put there, and this module does
    # not import the framework. A `routes` attribute that cannot be walked is
    # a read that failed, which is the one thing this function promises never
    # to report as an application with nothing on it.
    entries = _listed(getattr(app, "routes", ()))
    if entries is None:
        return [Route(path=repr(getattr(app, "routes", None)), readable=False)]
    for entry in entries:
        path = getattr(entry, "path", None)
        if not isinstance(path, str):
            out.append(Route(path=repr(entry), readable=False))
            continue
        methods = _listed(getattr(entry, "methods", ()))
        deps = _dependency_names(entry)
        if methods is None or deps is None:
            # The documented contract of this function, applied to the two
            # fields it was not applied to. An entry whose `methods` or
            # dependency list cannot be walked raised TypeError from here, and
            # the whole audit died on one unreadable route rather than
            # reporting that route as unguarded.
            out.append(Route(path=path, readable=False))
            continue
        methods = tuple(methods)
        deps = tuple(deps)
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
        for prefix, raw_names in prefix_deps.items():
            # `_listed`, for both reasons it exists. A mount whose dependency
            # list is a generator was read once and empty on every route after
            # the first, so the same surface audited PASS or FAIL depending on
            # which route the walk reached first and on whether this function
            # had been called before: the comment eight lines up says an
            # auditor whose verdict moves with dict order is not measuring the
            # surface, and iterator exhaustion moves it the same way. And a
            # mount written `{"/api": "require_auth"}` walked the string's
            # characters and lent twelve one-letter dependencies, which is the
            # one-element-tuple typo this module documents everywhere else.
            #
            # `or ()`, because `_listed` answers `None` for a field it could
            # not read, and a mount whose dependency list could not be read
            # lends no authority. That is the fail-closed direction: the
            # routes under it are reported unguarded rather than guarded by
            # something nobody managed to read.
            names = _listed(raw_names) or ()
            # Mounts own path segments, not neighboring string prefixes.
            if not isinstance(prefix, str) or not prefix.startswith("/"):
                continue
            prefix = prefix.rstrip("/") or "/"
            matches = (path == prefix or path.startswith(prefix.rstrip("/") + "/"))
            if matches and (best_prefix is None
                                            or len(prefix) > len(best_prefix)):
                best_prefix = prefix
                inherited = tuple(names)
            elif matches and prefix == best_prefix:
                # Equivalent spellings must agree before lending authority.
                inherited = tuple(sorted(set(inherited) & set(names)))
        out.append(Route(path=path, methods=methods,
                         name=str(getattr(entry, "name", "") or ""),
                         dependencies=deps, router_dependencies=inherited))
    return out


def _dependency_name(value) -> str:
    """The one name a dependency is known by, whatever shape it arrives in.

    A callable is its `__name__` and anything else is its text, which is the
    reading `_dependency_names` already took of the route side. It is a
    function so that the declared list, the override map and the route
    dependencies are all read the same way; keeping the reading in one place
    is what stopped the audit comparing names against function objects.

    A `__name__` that is not a `str`, or a `__str__` that raises, has no name
    here rather than a traceback out of the audit: the whole module's rule is
    that an unreadable input is a finding, and `audit_mount_surface` already
    refuses an unreadable override map by name.
    """
    name = getattr(value, "__name__", None)
    if type(name) is str:
        return name
    if isinstance(name, str):
        return str.__str__(name)
    try:
        text = str(value)
    except Exception:
        return "<unreadable dependency>"
    return text if type(text) is str else str.__str__(text)


def _dependency_names(entry):
    """Pull dependency callable names off a route entry, tolerating any shape.

    `None` when either dependency list cannot be walked. The caller turns that
    into `readable=False`, which the audit counts as unguarded, rather than
    into a list with the unreadable half silently missing from it: a route
    whose dependencies could not be read is not a route with fewer of them.
    """
    names = []
    dependant = getattr(entry, "dependant", None)
    inner = _listed(getattr(dependant, "dependencies", ()))
    outer = _listed(getattr(entry, "dependencies", ()))
    if inner is None or outer is None:
        return None
    for dep in inner:
        call = getattr(dep, "call", dep)
        names.append(getattr(call, "__name__", str(call)))
    for dep in outer:
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
