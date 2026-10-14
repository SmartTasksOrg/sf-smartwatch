# Decisions: the council's specification and what 0.1.0 does

The council's specification ("SmartWatch — Live Agent Coupling-Density Monitor") fixed the goals:
measure coupling density live, grade it against environment-specific percentile thresholds, and reset
the affected agents (automatically or after a human confirms) before coordination passes a threshold a
human can follow. This table says how each decision was implemented, and where 0.1.0 differs and why.

| Council decision | 0.1.0 |
|---|---|
| Coupling density: weighted average of unique pair message rates, normalised by all possible pairs | Messages per possible pair per second, in millionths (SEMANTICS.md §1). Weighting every pair by its messages and dividing by all possible pairs comes down to this number; the share of pairs that talk at all is reported next to it (`pair_ratio_micro`). |
| Environment-specific percentile thresholds, prod p95 / staging p90, dynamic calibration | `calibrate` with profiles prod (p95, p99, p99.9) and staging (p90, p95, p99), nearest-rank percentiles, one policy file per environment; recalibrate whenever the system changes. "Dynamic" is a calibration you rerun, not a moving threshold: a moving threshold follows a slow drift into dense coordination and never alerts on it. |
| Calibration: 30 s sample, per-environment ConfigMap | `calibrate` refuses fewer than 30 windows (30 s at 1 s) by default and writes a ConfigMap with `--configmap`. |
| Sampling 1 s with ±200 ms jitter | 1 s windows by default (`window_ms`); the reporter sends every 1 s ± up to 200 ms. |
| OPA decides auto-reset vs manual override | A JSON policy (`reset.mode` auto / confirm / off, `confirm_timeout_ms`, `on_timeout`, `sustain_ms`, `cooldown_ms`), validated strictly. No OPA runtime dependency; the policy is small enough to review as data. |
| Auto-reset if over the baseline for more than 5 s without confirmation | `sustain_ms` 5000 and `confirm_timeout_ms` 5000 with `on_timeout: reset` in the default policy. |
| Reset endpoint `POST /api/v1/agents/{agent_id}/reset`, OAuth2 JWT scope `reset:agent`, idempotent, 202, audit | As specified: HS256, RS256, ES256 or EdDSA verification of your identity provider's tokens, `Idempotency-Key`, 202, every request in the audit log. |
| Retries with exponential backoff up to 5 attempts | Webhook delivery: 5 attempts, 1/2/4/8 s apart. Reset commands for pulling stay queued until acknowledged. |
| Grafana modal with cancel / force reset / escalate | The same three decisions through the API and `sf-smartwatch decide`; escalation calls `SMARTWATCH_ESCALATION_WEBHOOK`. Grafana shows the dashboard; a write action from a dashboard would need Grafana plugins outside this package. |
| Sidecar intercepting Envoy / gRPC / WebSocket at transport level, no payload inspection | Not built. Reporters in the agent process (seven languages) and `ingest-log` for Envoy JSON access logs. Neither reads payloads. |
| Fallback when Envoy is unavailable: direct HTTP throttling or service-mesh control | Not built: the monitor does not throttle traffic. Its outputs are alerts and reset commands. |
| 1M buckets with FNV-32a, HyperLogLog above 500 kpps, exact counters when HLL error > 1 % | Exact counting first (up to `max_pairs_exact` / `max_agents_exact`), then HyperLogLog (p = 14, standard error about 0.8 %) for distinct counts, 2^20 FNV-1a buckets and bounded candidates for hot pairs. The switch is by size, not rate: a rate trigger would make the same traffic count differently on a faster machine. |
| Seed: pod name + namespace | `hash_seed` in the policy; set it to "namespace/pod" if you want the council's convention. |
| Prometheus, Grafana, alerting to Slack/PagerDuty/email | Prometheus metrics, alert rules and a dashboard in `deploy/`; route the alerts with your Alertmanager. Webhooks for level changes, proposals, resets and escalations. |
| PostgreSQL audit table, 30-day TTL | Hash-chained JSON Lines file. Retention is yours (rotate by moving the file and keeping its head hash). |
| Cortex: 30 days raw, 90 days aggregated | Not built; configure your Prometheus retention or remote write. |
| Label mapping agent_a → agent_id_a, agent_b → agent_id_b | `smartwatch_pair_messages{agent_id_a, agent_id_b}` for the top pairs of the last window. |
| CPU < 2 % avg, < 5 % peak, < 5 ms p99, ≤ 10 MB for 20k agents | Not measured. The reporter's `record` is an in-memory dictionary update; the monitor's memory is bounded by the limits in the policy (an 8 MiB bucket array per window over the exact limit). `sf-smartwatch bench` prints throughput. |
| Nightly validation at 02:00 UTC | `.github/workflows/nightly.yml`, cron `0 2 * * *`. |
| `docs/failure-modes.md` with overflow scenarios | [failure-modes.md](failure-modes.md). |
| Validation against ground truth, 1 % HLL error | Not met for every estimate. HyperLogLog with p = 14 has about 0.8 % standard error, so single estimates often miss by more than 1 %, and by up to about 3.7 % just above 40,960 distinct items. Exact counting has no error: raise `limits.max_pairs_exact` and `limits.max_agents_exact` to stay exact for your sizes. `tests/test_engine.py` checks HyperLogLog within 3 % at three sizes; the vectors pin exact values. No ground-truth payload logger. |
