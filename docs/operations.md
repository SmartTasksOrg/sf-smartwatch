# Operations

## Run the monitor

```bash
export SMARTWATCH_INGEST_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export SMARTWATCH_OPERATOR_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export SMARTWATCH_JWT_PUBLIC_KEY=/etc/smartwatch/idp-public.pem   # or SMARTWATCH_JWT_HS256_SECRET (32+ bytes)
export SMARTWATCH_JWT_ISSUER=https://idp.example                  # optional, checked when set
export SMARTWATCH_JWT_AUDIENCE=smartwatch                         # optional, checked when set
sf-smartwatch serve --policy policy.json --audit /var/lib/smartwatch/audit.jsonl --host 0.0.0.0 --port 8730
```

The monitor refuses to start without both tokens, or with tokens that are shorter than 16 characters,
equal to each other or still the example values. Reset JWTs must expire within 24 hours. `--insecure-dev` runs without credentials and binds 127.0.0.1 only.

| Variable | Meaning |
|---|---|
| `SMARTWATCH_INGEST_TOKEN` | reporters and agents: events, commands, acknowledgements |
| `SMARTWATCH_OPERATOR_TOKEN` | operators, read-only: state, windows, proposals, resets, `/ui` (it cannot ingest or acknowledge) |
| `SMARTWATCH_JWT_HS256_SECRET` / `SMARTWATCH_JWT_PUBLIC_KEY` | who may reset and decide (scope `reset:agent`); exactly one |
| `SMARTWATCH_JWT_ISSUER`, `SMARTWATCH_JWT_AUDIENCE` | checked when set |
| `SMARTWATCH_OPERATOR_ALLOW` | addresses or CIDRs allowed on operator and reset endpoints |
| `SMARTWATCH_TRUSTED_PROXIES` | your reverse proxy: its last `X-Forwarded-For` address is the client |
| `SMARTWATCH_INGEST_RATE` | ingest requests per minute per address (default 6000) |
| `SMARTWATCH_ALERT_WEBHOOK` | level changes and new proposals |
| `SMARTWATCH_RESET_WEBHOOK` | every reset command |
| `SMARTWATCH_ESCALATION_WEBHOOK` | escalated proposals |
| `SMARTWATCH_WEBHOOK_SECRET` | signs every webhook body |

Put a TLS proxy in front: the monitor speaks plain HTTP. Without a JWT key, the operator token is also
the reset credential. Configure a JWT key in production, so that every reset in the audit log names a
person (`jwt:<sub>`), not a shared token.

## Docker and Compose

```bash
docker build -t sf-smartwatch:0.1.0 .
cp deploy/.env.example deploy/.env          # fill in the tokens; never commit deploy/.env
cp deploy/policy.example.json deploy/policy.json   # then calibrate it (calibration.md)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
```

The compose file runs the monitor, Prometheus (alert rules in `deploy/prometheus/alerts.yml`) and
Grafana (dashboard "SmartWatch"). The policy is mounted from `deploy/policy.json` (ignored by git). The compose stack is
not run in CI; check it on your own machine before you rely on it.

## Daily work

| Task | Command |
|---|---|
| What does the monitor see | `sf-smartwatch state --url URL` (`SMARTWATCH_TOKEN` = operator token) |
| Open proposals | `sf-smartwatch proposals --url URL --status open` |
| Confirm / cancel / escalate | `sf-smartwatch decide --url URL PROPOSAL_ID confirm --note "..."` (`SMARTWATCH_TOKEN` = a JWT) |
| Reset one agent by hand | `sf-smartwatch reset --url URL AGENT --reason "..." --idempotency-key KEY` |
| Check the audit log | `sf-smartwatch audit verify audit.jsonl` |
| Status page | `https://URL/ui` (HTTP Basic: any user name, the operator token as password) |

`sf-smartwatch token --sub NAME` makes a short-lived HS256 test token from
`SMARTWATCH_JWT_HS256_SECRET`. Use it for trials only; in production your identity provider issues the
tokens.

## The audit log

One JSON object per line, chained by SHA-256 and written with fsync. On start the monitor verifies the
file and refuses to append to a broken chain. Rotate the log by stopping the monitor, moving the file,
recording its last `hash` somewhere else, and starting again with a new file. Records:

| event | when |
|---|---|
| `started` | the monitor started (environment, reset mode) |
| `level` | the graded level changed |
| `proposal` | a reset is proposed (confirm mode) |
| `proposal-confirmed`, `proposal-cancelled`, `proposal-escalated`, `proposal-timeout` | decisions |
| `reset-auto` | auto mode decided to reset these agents |
| `reset` | one reset command issued (reason auto, confirmed, timeout or manual; `by`) |
| `reset-acked` | the agent's side acknowledged it |
| `reset-skipped` | the reset level was sustained but no pair reached `hot_pair_min_count` |

The chain shows that the file was not edited in place. It does not show that the file is complete:
whoever controls the file can cut it and write a new tail. Keep a copy or the head hash elsewhere.

## Metrics and alerts

`GET /metrics` without credentials. Put it behind your network policy if pair names are sensitive: the
top pairs carry agent ids. Alert rules in `deploy/prometheus/alerts.yml`:
- `SmartWatchElevated` (level ≥ 1 for 1 minute);
- `SmartWatchResetLevel` (any reset command issued);
- `SmartWatchProposalOpen` (proposals waiting);
- `SmartWatchSketchMode` (estimates in use for 10 minutes: raise the exact limits or accept it);
- `SmartWatchWebhookFailing`;
- `SmartWatchNoTraffic` (no events for 5 minutes: reporters may be down).

## Restart behaviour

The engine state (open windows, the current level, a sustained streak) lives in memory. After a
restart, windows start again from the next event and the level starts at `normal`. Pending proposals
and unacknowledged reset commands are lost from the queue, but they are in the audit log. Check
`sf-smartwatch audit verify` and the log's tail after an unplanned restart.
