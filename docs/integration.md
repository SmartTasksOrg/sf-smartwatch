# Integration

## Reporting messages

Report each agent-to-agent message once: on the sending side (preferred) or the receiving side, not
both, or every message counts twice. Ids must match `[A-Za-z0-9._:@/-]{1,128}`.

**Python**

```python
from sf_smartwatch import Reporter
rep = Reporter("https://watch.example", token=INGEST_TOKEN).start()
rep.record("planner", "coder")              # in your message-sending code
...
rep.close()                                 # at shutdown: sends what is left
```

`record` adds to an in-memory map and never blocks. Delivery is at least once: if the monitor counted a
batch but the answer was lost on the way back, the batch is sent again and counted twice. Every second (± up to 200 ms) a background thread
sends the counts per (src, dst, second). If the monitor cannot be reached, the counts are kept and sent
next time; at most `max_keys` (100,000) keys are kept, and beyond that `rep.dropped` counts the lost
messages. Answers 400/401/403/413 drop the batch and count it in `rep.rejected`. With a policy
`window_ms` below 1000, pass `bucket_ms` equal to the window (or a divisor of it).

**Other languages:** `ports/<language>` has the same reporter and poller (see each README).

**Envoy access logs:** configure a JSON access log that includes the calling agent's id (for example
a request header) and the called agent (for example the upstream cluster), then:

```bash
sf-smartwatch ingest-log /var/log/envoy/access.json --src-field x_agent_id --dst-field upstream_cluster \
    --ts-field start_time --url https://watch.example        # SMARTWATCH_TOKEN = the ingest token
```

Fields may be nested (`a.b`). `start_time` may be milliseconds or ISO 8601 (Envoy's `%START_TIME%`).
Lines without both ids, with ids outside the pattern or with a bad time are counted as skipped.

**HTTP directly:** `POST /v1/events` with `{"events": [{"src", "dst", "ts_ms", "count"}]}` (at most
10,000 events and 1 MiB). The answer is 200 (all accepted), 207 (some refused) or 400 (none accepted),
with `{"accepted": n, "rejected": [{"index", "code", "error"}]}`. Every POST needs
`Content-Type: application/json`. Events more than 2 s ahead of the monitor's clock are refused
(`WATCH-CLOCK-SKEW`); events up to 2 s ahead count at the monitor's current time. Events for a window
that has already closed (older than `late_windows` windows) are refused as `WATCH-LATE` and counted in
`smartwatch_late_messages`. Keep reporter clocks in sync (NTP).

## Receiving resets

A reset command means: the monitor (or a person) wants this agent to start over before its coordination
gets further. What "reset" does is yours to define: clear the agent's conversation state, restart its
worker, or take it out of the pool. SmartWatch never kills a process.

**Pull (recommended):** the agent or its supervisor polls `GET /v1/agents/{id}/commands`, performs the
reset, then `POST /v1/resets/{reset_id}/ack` with `{"agent_id": "<the agent>"}` (required; it must be
the reset's agent). In Python:

```python
from sf_smartwatch import Client, CommandPoller
CommandPoller(Client(URL, INGEST_TOKEN), "coder", on_reset=lambda cmd: restart("coder")).start()
```

A handler that raises does not acknowledge, so the command comes again: make the reset idempotent per
`reset_id`. Ids with `/` are percent-encoded in the path (`team%2Fcoder`).

**Webhook:** set `SMARTWATCH_RESET_WEBHOOK`. Every command is POSTed as JSON
`{"kind": "reset", "environment", "reset_id", "agent_id", "reason", "by", "created_ms"}` with headers
`X-SmartWatch-Event`, `X-SmartWatch-Timestamp` and, with `SMARTWATCH_WEBHOOK_SECRET`,
`X-SmartWatch-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>." + body)>`. Webhook URLs must not contain a user name or password; the monitor refuses them at start, and log lines
show only the scheme, host and path. Check the signature
with a constant-time comparison and reject timestamps older than a few minutes. A 2xx answer is
success; anything else is retried (5 attempts, 1/2/4/8 s apart). Delivery is at least once:
deduplicate by `reset_id`. A webhook delivery does not acknowledge the command. The agent's side
acknowledges through the API when the reset is done.

**In process:** `Watcher(policy, on_reset=callable, on_alert=callable)` runs the whole monitor inside
your Python process, without HTTP. Feed it with `ingest([...])` and call `tick()` every 100 ms or so.

## Alerts

`SMARTWATCH_ALERT_WEBHOOK` receives `{"kind": "level", "window", "from", "to", "density_micro", ...}` on
every level change and `{"kind": "proposal", "proposal_id", "deadline_ms", "on_timeout", "agents", ...}`
on every proposal. They are signed in the same way as reset webhooks. Point the webhook at your chat or
paging bridge. The Prometheus rules in `deploy/` cover the same events for Alertmanager.

## Deciding

People with a JWT carrying `reset:agent` confirm, cancel or escalate a proposal:
`POST /v1/proposals/{id}/confirm` (or `cancel`, `escalate`) with an optional `{"note": "..."}`, or
`sf-smartwatch decide`. A decision after the deadline is refused with 409: the timeout already decided.
Escalation keeps the proposal open and calls `SMARTWATCH_ESCALATION_WEBHOOK`.
