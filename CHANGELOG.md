# Changelog

All notable changes to SmartWatch are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semantic.

## Unreleased

## 0.1.0 — first release as `sf-smartwatch`

Built from the SmartWatch council specification (live agent coupling-density monitor).

### Added
- Engine (spec/SEMANTICS.md): coupling density per window (messages per possible pair per second, in
  millionths, in IEEE doubles with a fixed order of operations), graded levels with hysteresis and
  `min_agents`, late-event windows, empty and skipped windows after a silence, and a reset decision
  after `sustain_ms` that names the agents of the hottest pairs. Repeats are limited by `cooldown_ms`.
- Bounded counting: exact up to the policy limits, then HyperLogLog (p = 14), 2^20 FNV-1a buckets and
  bounded hot-pair candidates; every counter saturates at 2^53 − 1.
- Policy files (`smartwatch.policy/v1`, JSON Schema in spec/) with strict validation; calibration from
  your own traffic with prod and staging percentile profiles and an optional Kubernetes ConfigMap.
- Monitor over HTTP (stdlib):
  - event ingest with per-event errors and a clock-skew check;
  - reset commands that the agent side pulls and acknowledges;
  - proposals with confirm, cancel and escalate, and a timeout that resets or cancels;
  - manual reset at `POST /api/v1/agents/{id}/reset` (202, Idempotency-Key);
  - JWT (HS256, RS256, ES256, EdDSA) with the scope `reset:agent`;
  - signed webhooks with retries;
  - a hash-chained audit log, Prometheus metrics and a read-only status page;
  - token roles, an operator IP allowlist, rate limits, and request and connection limits.
- Reporter (pre-aggregation per pair and second, 1 s ± 200 ms jitter, bounded buffer, retry) and
  CommandPoller for Python.
- Command line: serve, validate, calibrate, synth, replay, ingest-log (Envoy JSON access logs), demo,
  bench, vectors, audit verify, state, proposals, decide, reset, token.
- 1472 shared vectors. The engine, reporter and poller are ported to Node.js, Go, Rust, Java, C#, PHP
  and Ruby; all ports pass the vectors and an interop test against the Python monitor.
- Deployment: Dockerfile and docker-compose with Prometheus alert rules and a Grafana dashboard;
  nightly validation workflow at 02:00 UTC.

### Fixed before release (pre-release review; regression tests in tests/test_review_fixes.py)
- A reporter clock ahead of the monitor's could close everyone's windows. Events more than 2 s ahead
  are now refused, and events up to 2 s ahead count at the monitor's current time.
- Late events are reported as `WATCH-LATE` instead of being silently dropped.
- Roles are separate: the operator token no longer ingests or acknowledges. HTTP Basic is accepted only
  for `/ui`. POSTs must be `application/json` and are refused when they come from a web page (`Origin`,
  `Sec-Fetch-Site`).
- An acknowledgement must name the reset's agent.
- `X-Forwarded-For` behind a trusted proxy uses the last value of the last header line.
- At most 32 open connections per address.
- A valid credential passes even when its address has many failures. The rate-limiter table no longer
  forgets lockouts when it is full.
- An audit write failure cuts the file back to its last complete record and stops all changes (503)
  until restart; short writes are completed.
- Webhooks use separate queues for resets, escalations and alerts. URLs with credentials are refused,
  and URLs are redacted in log lines.
- Request lines are escaped in the server log; the CLI escapes control characters in text it prints.
- JWTs with a non-finite `exp` or one more than 24 hours ahead are refused.
- `calibrate` refuses non-integer densities in window input. Example tokens from `deploy/.env.example`
  are refused at start. Empty per-agent queues are removed.
- C# port: answers are read with a hard size limit instead of being buffered whole.

### Known and documented (docs/threat-model.md)
- A holder of the ingest token can dilute density by reporting invented idle agents. The hot pair still
  shows in `top` and in `smartwatch_pair_messages`.
- One shared ingest token can read and acknowledge any agent's reset commands.
