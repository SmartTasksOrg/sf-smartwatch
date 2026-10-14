# Security policy

SmartWatch 0.1.0 is experimental software. Before release it had one code review by a separate AI
reviewer that did not write the code. It has had no independent human audit.
[README "Status"](README.md#status) says what is tested and what is not.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Report privately through GitHub: open <https://github.com/SmartTasksOrg/sf-smartwatch>, go to the
**Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Only
the maintainers can read the report.

Do not open a public issue, pull request or discussion for a vulnerability, and do not put a working
exploit in one.

If the Security tab shows no "Report a vulnerability" button, private reporting is switched off. Open a
public issue that says only "I have a security report; please enable private vulnerability reporting",
with no details, and wait for a maintainer.

## What to include

- The version (`sf-smartwatch --version`) or the port, and your platform.
- The smallest input that shows the problem, and what you expected.

Remove real secrets, tokens and personal data from what you send.

## Packages that pretend to be SmartWatch

The only package names the maintainers publish are listed with `"registered": true` in
[names.json](names.json). Official releases are built by `.github/workflows/release.yml` in
`SmartTasksOrg/sf-smartwatch` and published with trusted publishing, so each file carries a provenance
attestation that names this repository and that workflow.

A package on any registry that uses this project's name but is not listed there, or a release file
without that provenance, is not ours. Report it through the private form above, and to the registry
(PyPI: "Report project as malware" on the project page).

## What to expect

- An answer in the private report. No response time is promised; this is a small project without a
  security team on call.
- A confirmed issue is fixed in a new release, announced in `CHANGELOG.md` and in a GitHub security
  advisory, with credit to the reporter unless they ask not to be named.
- There is no bug bounty.

## Scope

In scope: the code in this repository and its build, deployment and release files. Especially:
- a reset or a decision accepted without a valid reset credential (a JWT with `reset:agent` when a JWT
  key is configured), or with an expired, wrongly signed or wrong-algorithm token;
- reaching an operator endpoint without the operator token or from outside the allowlist;
- an ingest token or operator token that opens endpoints of another role (docs/threat-model.md, "Role
  confusion");
- a forged webhook that a receiver checking the signature as documented would accept;
- an audit log that verifies after an edit, removal or reordering;
- memory or CPU growth without bound driven by requests (the limits are in docs/threat-model.md);
- two engines (Python and a port) giving different results for the same input.

Out of scope:
- reporters that report false traffic with a valid ingest token, including dilution by invented agents,
  and a shared ingest token acknowledging another agent's command (docs/threat-model.md);
- agents that coordinate outside the reported channels or ignore a reset command;
- hash collisions in the buckets (they only over-count; docs/failure-modes.md);
- the example values in `deploy/.env.example`.

Known by design:
- `/metrics` and `/healthz` need no credential; the metrics name the top pairs of the last window.
- The audit chain detects edits, not truncation followed by a new tail.
- Without a JWT key, the operator token is the reset credential.
