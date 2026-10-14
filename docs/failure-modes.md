# Failure modes

What can go wrong, what SmartWatch does, and what you see. The council asked for the exact-counter
overflow scenarios in particular; they come first.

## Counting

| Situation | What happens | What you see |
|---|---|---|
| More distinct pairs in a window than `limits.max_pairs_exact` | Pairs already counted stay exact. New pairs go to a HyperLogLog (distinct count, about 0.8 % standard error) and to 2^20 hashed buckets (8 MiB per such window). | `exact: false` in the window, `smartwatch_sketch_mode 1` |
| More distinct agents than `limits.max_agents_exact` | The agent count becomes a HyperLogLog estimate, capped at 10^8. Density then uses the estimate. The estimator has about 0.8 % standard error, plus an upward bias of about 2.5 % just above 40,960 distinct items (where it switches from linear counting to the raw estimate). In private tests at 20,000 agents, density errors were up to about 4 % for a few hash seeds. | `exact: false` |
| Two pairs in one bucket | The bucket counts both. A pair's estimate can only be too high, never too low. A crafted collision (anyone who knows `hash_seed` can compute one) can make a pair look hotter, so it may be named in a reset. It cannot hide a hot pair. | `exact: false` on that entry of `top` |
| More hot pairs than `limits.candidates` | The candidate with the lowest (estimate, pair) is replaced by a hotter one. A pair that was hot early in the window and then went quiet can be evicted. | `top` holds the hottest candidates seen |
| A counter reaches 2^53 − 1 | It stays there (saturates); it never wraps. 2^53 is about 9 × 10^15 messages. | the value 9007199254740991 |
| Density above 2^53 − 1 millionths | Capped at 2^53 − 1. | the same value |

## Time

| Situation | What happens | What you see |
|---|---|---|
| Event older than `late_windows` windows | Dropped; its count goes to `late_dropped`. | `WATCH-LATE` in the answer; `smartwatch_late_messages` rises |
| Reporter clock ahead by up to 2 s | Counted at the monitor's current time. | nothing |
| Reporter clock ahead by more than 2 s | Events refused. A reporter's clock never moves the windows ahead of the monitor's. | `WATCH-CLOCK-SKEW` in the answer, `smartwatch_events_total{result="rejected"}` |
| Reporter clock behind | Events land in old windows and may be dropped as late. | late messages; fix NTP on the reporter host |
| The monitor counted a batch but its answer was lost (network cut, proxy timeout) | The reporter sends the batch again: events are delivered at least once and can be counted twice. A 2xx answer the reporter cannot read is not resent. | density briefly higher; `rep.errors` |
| Monitor clock jumps forward | Windows close early; the next events may be late. | a burst of late messages |
| No traffic | Up to `max_empty_windows` empty windows are emitted (density 0), then windows are skipped. A level above normal falls to normal and a sustained streak is reset. | `smartwatch_skipped_windows`; `SmartWatchNoTraffic` alert |

## Resets

| Situation | What happens | What you see |
|---|---|---|
| Reset level sustained but no pair reaches `hot_pair_min_count` | No proposal; recorded. | `reset-skipped` in the audit log |
| Nobody decides a proposal | At `confirm_timeout_ms` the policy's `on_timeout` applies: `reset` issues the commands, `cancel` drops the proposal. | `proposal-timeout` with the outcome |
| Agent side never acknowledges | The command stays pending (at most 100 per agent, oldest dropped first). | `pending_resets` in state; `smartwatch_reset_acks_total` flat |
| Reset webhook down | 5 attempts, 1/2/4/8 s apart, each with a 5 s timeout per socket operation, then given up. Resets, escalations and alerts have separate queues and workers, so a dead alert receiver does not delay resets. A receiver that answers very slowly holds its own queue. | `smartwatch_webhooks_total{result="failed"}` |
| Webhook queue full (10,000) | New webhooks are dropped. | `result="dropped"` |
| More than 1000 proposals open at once | No new proposal until some are decided or time out. | `proposal-dropped` in the audit log |
| Level stays at the reset level after a reset | No second reset until the level falls below it and rises again, and `cooldown_ms` has passed. | one `reset` per episode |
| `reset.mode: off` | Levels and alerts only. | no proposals |

## The service

| Situation | What happens | What you see |
|---|---|---|
| Monitor restarts | Open windows, the level and the streak start fresh; queued commands and open proposals are gone (the audit log has them). | `started` in the audit log |
| Audit file damaged | The monitor refuses to start on it. | `refusing to append to a broken chain` |
| Disk full, or the audit file cannot be written | A partly written record is cut back, so the file stays a valid chain. From then on the monitor refuses every change with 503 (`WATCH-AUDIT-FAILED`) until it is restarted: an unrecorded reset is worse than none. Events already counted in that request still count. | `audit_failed` in state; CRITICAL in the log; free space and restart |
| Monitor down | Reporters keep up to 100,000 keys and retry; agents keep running (SmartWatch is not a dead-man switch). | `rep.errors`; `up == 0` in Prometheus |
| Many reporters at once | The jitter spreads them; the ingest rate limit is per address. | 429 answers; raise `SMARTWATCH_INGEST_RATE` |
| A credential fails 20 times in a minute from one address | Further wrong credentials from that address get 429; valid ones still pass. | 429 |
| More than 32 open connections from one address | Further connections are closed at once (a trusted proxy is exempt). | connection closed |

## Calibration

| Situation | What happens |
|---|---|
| Fewer than `--min-windows` windows with `min_agents` agents | `calibrate` refuses. |
| Flat traffic (all windows alike) | Thresholds end up close together, and each is at least 1 above the previous one. Widen them by hand. |
| A density that is not a non-negative integer in the input | Refused. |
