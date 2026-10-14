# Calibration

The default thresholds in the policy (2, 5 and 10 messages per pair per second) are placeholders. A
system of planners and tools that call each other a few times a minute and a swarm of chat agents that
exchange hundreds of messages a second need thresholds that differ by orders of magnitude. Calibrate on
your own traffic, per environment, and recalibrate when the system changes.

## 1. Collect traffic

One of:

- run the monitor with the default policy and `reset.mode: off` for a representative period, then
  export the windows: `curl -s -H "Authorization: Bearer $SMARTWATCH_OPERATOR_TOKEN" https://watch.example/v1/windows?last=600 | python -c "import json,sys; [print(json.dumps(w)) for w in json.load(sys.stdin)['windows']]" > windows.jsonl`
  (600 windows at most per call; collect over time);
- turn an access log into events: `sf-smartwatch ingest-log access.log --src-field x_agent --dst-field upstream --out traffic.jsonl`;
- record events from your reporters' side.

At least 30 windows with `min_agents` or more agents are required (`--min-windows`). The council asked
for 30 s; a working day is better, and it should include your normal peaks.

## 2. Compute the policy

```bash
sf-smartwatch calibrate --input traffic.jsonl --environment prod --profile prod --out policy-prod.json
sf-smartwatch calibrate --input staging.jsonl --environment staging --profile staging --out policy-staging.json
```

| Profile | elevated | high | critical |
|---|---|---|---|
| prod | p95 | p99 | p99.9 |
| staging | p90 | p95 | p99 |

`--permille 900,990` and `--names warm,hot` choose your own levels. `--base` starts from a policy with
your window, reset and limit settings. The percentile is the nearest rank: sorted densities, the value
at position ceil(p × N / 1000). Thresholds always increase by at least 1.

The printout on standard error shows the distribution. If the p99.9 is not far above the p95, your
traffic is flat and the top level will fire on ordinary peaks: widen the gap by hand, or use `--permille`.

## 3. Check it before you trust it

```bash
sf-smartwatch validate policy-prod.json
sf-smartwatch replay last-week.jsonl --policy policy-prod.json      # how often would each level have fired?
```

Start in `confirm` mode with `on_timeout: cancel`, so that nothing resets without a person. Move to
`on_timeout: reset` or `auto` once you have seen what the proposals look like.

## What calibration cannot do

Percentiles of normal traffic tell you what is unusual, not what is dangerous. A system that is always
tightly coupled will have high thresholds. If the thing you worry about is coordination at the level you
already run at, set the thresholds from your own judgement and use calibration only as a sanity check.
