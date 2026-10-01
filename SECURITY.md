# Security Policy

This repository is a public showcase. Everything in it is a small, sanitized
example built to run on synthetic data. It is not the production system, and
nothing here is wired to a real tenant, a real credential, or a real endpoint.
This policy covers the public examples and their development workflow.

## Reporting a vulnerability

Use GitHub private vulnerability reporting, which is enabled on this
repository:

**[Open a private report](https://github.com/greeklinux/Showcase/security/advisories/new)**
(Security tab, then "Report a vulnerability")

That channel is private between you and me until a fix is published. Please use
it rather than a public issue, and please do not use it to send credentials,
production data, or anything belonging to a third party.

Include the affected file and line, security impact, and a minimal reproduction. A proof of concept
against a local copy is welcome. Do not test against any live site.

## Scope

In scope, and I want to hear about it:

- A control in this repository that does not actually enforce what it claims.
  A guard that can be bypassed, a validator that passes something it documents
  as blocked, a default-deny allowlist that is not default-deny, a detection
  whose logic can never fire. This is the failure mode the repository is about,
  so a real example of it here is the most useful report I can get.
- A sanitization miss: a credential, key, token, private hostname, internal
  address, or personal data in the tree or in the git history.
- A supply chain problem: a GitHub Actions workflow that can be made to run
  attacker controlled code, or an action reference that can be moved under you.
- Anything that makes a copy-paste reader less safe, because the examples here
  are meant to be read and reused.

Out of scope:

- Findings that the example is simplified. It is, on purpose. Missing retries,
  missing persistence, missing auth on a function that takes a dict and returns
  a dict, hardcoded example inputs: these are not vulnerabilities, they are the
  point of a teaching example. If the simplification would mislead a reader into
  an unsafe production pattern, that is in scope and I would like to know.
- Findings against the private systems this repository describes. They are not
  reachable from here and are not covered by this policy.
- Automated scanner output with no working example behind it.
- Denial of service against a script you run on your own machine.

## What to expect

- Acknowledgement within 3 business days.
- An assessment, with my reasoning, within 10 business days.
- A fix or a written decision not to fix within 30 days for anything I agree is
  in scope. If a finding shows a control here does not enforce what it claims,
  I will either fix the control or change the text so it stops claiming it.
- Credit in the commit or the advisory if you want it, and none if you do not.

No monetary bounty is offered. Reporter credit is optional.

## Supported versions

Only the current `main` branch. There are no releases and no backports.
