# Security Policy

## Scope and intent

This repository holds **small, sanitized, illustrative examples** of AI-security
and signal-processing techniques. It is a public showcase, not a production
system: the code runs on synthetic data, wires in no live model or credential,
and is meant to be read rather than deployed. Treat every detection, guard, and
heuristic here as a starting point to adapt and harden for your own environment,
not as a turnkey control.

## Reporting a vulnerability

If you find a security issue in this repository, please report it privately:

- Use GitHub's **"Report a vulnerability"** button on the Security tab of this
  repository (Private Vulnerability Reporting), or
- Open a minimal issue that describes the problem **without** including a working
  exploit or any sensitive data.

Please do not disclose a suspected vulnerability publicly until it has been
addressed. Because this is illustrative example code with no production
deployment or user data, there is no formal SLA; reports are reviewed on a
best-effort basis.

## What is in scope

- The example code and queries in `ai_security/`, `automation/`, and `polymind/`.
- The governance mappings in `GOVERNANCE.md`.

## What is out of scope

- Anything that depends on wiring these examples into a live model, data source,
  or credential (do not do that with this code as-is).
- Theoretical bypasses of the deliberately-simple demo guards (for example, the
  regex prompt screen), which are documented in the code as a cheap first filter
  and defense-in-depth, never the only control.
