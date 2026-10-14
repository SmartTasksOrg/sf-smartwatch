"""Prometheus metrics in the text exposition format, with no dependency.

smartwatch_events_total{result}            counter    events accepted / rejected / late (window already closed)
smartwatch_messages_total                  counter    messages in accepted events (the sum of their counts)
smartwatch_windows_total                   counter    windows closed
smartwatch_density_micro                   gauge      coupling density of the last closed window
smartwatch_pair_ratio_micro                gauge      distinct pairs / possible pairs of the last window, in millionths
smartwatch_agents                          gauge      agents seen in the last window
smartwatch_pairs                           gauge      distinct pairs in the last window
smartwatch_level                           gauge      graded level of the last window: 0 normal, 1 the first level, ...
smartwatch_sketch_mode                     gauge      1 when the last window was over the exact limits (estimates)
smartwatch_level_changes_total{to}         counter    level changes, by the level entered
smartwatch_skipped_windows                 gauge      windows skipped after a silence (max_empty_windows)
smartwatch_late_messages                   gauge      messages dropped because their window had closed
smartwatch_proposals_total{outcome}        counter    created / confirmed / cancelled / escalated / timeout_reset / timeout_cancel / auto
smartwatch_decision_ms                     histogram  proposal created -> human confirmed or cancelled
smartwatch_resets_total{reason}            counter    reset commands issued: auto / confirmed / timeout / manual
smartwatch_reset_acks_total                counter    reset commands acknowledged by the agent side
smartwatch_reset_ack_ms                    histogram  reset issued -> acknowledged
smartwatch_webhooks_total{kind,result}     counter    webhook attempts: ok / retry / failed / dropped
smartwatch_ingest_ms                       histogram  time to take one POST /v1/events batch
smartwatch_pair_messages{agent_id_a,agent_id_b} gauge  messages of each top pair in the last window (top_k series at most)
"""
from __future__ import annotations

import threading

def _fmt(v: float) -> str:
    return repr(float(v)) if v != int(v) else str(int(v))


class Counter:
    def __init__(self, name, help_, labels=()):
        self.name, self.help, self.labels = name, help_, labels
        self._v: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def inc(self, amount=1, **labels):
        key = tuple(labels.get(k, '') for k in self.labels)
        with self._lock:
            self._v[key] = self._v.get(key, 0) + amount

    def value(self, **labels):
        return self._v.get(tuple(labels.get(k, '') for k in self.labels), 0)

    def expose(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} counter']
        items = sorted(self._v.items())
        if not items and not self.labels:
            items = [((), 0)]
        for key, v in items:
            lab = ','.join(f'{k}="{x}"' for k, x in zip(self.labels, key))
            out.append(f'{self.name}{{{lab}}} {_fmt(v)}' if lab else f'{self.name} {_fmt(v)}')
        return out


class Histogram:
    def __init__(self, name, help_, buckets):
        self.name, self.help, self.buckets = name, help_, tuple(buckets)
        self._counts = [0] * len(self.buckets)
        self._sum, self._n = 0.0, 0
        self._obs: list[float] = []          # kept for percentiles in the benchmark (bounded)
        self._lock = threading.Lock()

    def observe(self, v):
        with self._lock:
            for i, b in enumerate(self.buckets):
                if v <= b:
                    self._counts[i] += 1
            self._sum += v
            self._n += 1
            if len(self._obs) < 200000:
                self._obs.append(v)

    @property
    def count(self):
        return self._n

    def percentile(self, q):
        with self._lock:
            xs = sorted(self._obs)
        if not xs:
            return 0.0
        return xs[min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))]

    def expose(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} histogram']
        for b, c in zip(self.buckets, self._counts):
            out.append(f'{self.name}_bucket{{le="{_fmt(b)}"}} {c}')
        out.append(f'{self.name}_bucket{{le="+Inf"}} {self._n}')
        out.append(f'{self.name}_sum {_fmt(self._sum) if self._sum else 0}')
        out.append(f'{self.name}_count {self._n}')
        return out


class Gauge:
    def __init__(self, name, help_):
        self.name, self.help, self.v = name, help_, 0

    def set(self, v):
        self.v = v

    def expose(self):
        return [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} gauge', f'{self.name} {_fmt(self.v)}']


class PairGauge:
    """The top pairs of the last window, replaced as a whole each window (at most top_k series).
    Labels follow the council's mapping agent_a -> agent_id_a, agent_b -> agent_id_b."""

    def __init__(self, name, help_):
        self.name, self.help, self.rows = name, help_, []

    def set_rows(self, rows):
        self.rows = list(rows)

    def expose(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} gauge']
        for a, b, v in self.rows:            # ids match [A-Za-z0-9._:@/-]: nothing to escape
            out.append(f'{self.name}{{agent_id_a="{a}",agent_id_b="{b}"}} {_fmt(v)}')
        return out


INGEST_MS_BUCKETS = (0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 1000)
HUMAN_MS_BUCKETS = (100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 300000)


class Metrics:
    def __init__(self):
        self.events = Counter('smartwatch_events_total', 'Events by result.', ('result',))
        self.messages = Counter('smartwatch_messages_total', 'Messages in accepted events.')
        self.windows = Counter('smartwatch_windows_total', 'Windows closed.')
        self.density = Gauge('smartwatch_density_micro', 'Coupling density of the last closed window (millionths of a message per possible pair per second).')
        self.pair_ratio = Gauge('smartwatch_pair_ratio_micro', 'Distinct pairs over possible pairs in the last window, in millionths.')
        self.agents = Gauge('smartwatch_agents', 'Agents seen in the last window.')
        self.pairs = Gauge('smartwatch_pairs', 'Distinct pairs in the last window.')
        self.level = Gauge('smartwatch_level', 'Level of the last window: 0 normal, 1 the first level, and so on.')
        self.sketch = Gauge('smartwatch_sketch_mode', '1 when the last window used estimates.')
        self.level_changes = Counter('smartwatch_level_changes_total', 'Level changes, by the level entered.', ('to',))
        self.skipped = Gauge('smartwatch_skipped_windows', 'Windows skipped after a silence.')
        self.late = Gauge('smartwatch_late_messages', 'Messages dropped because their window had closed.')
        self.proposals = Counter('smartwatch_proposals_total', 'Reset proposals, by outcome.', ('outcome',))
        self.decision_ms = Histogram('smartwatch_decision_ms', 'Proposal created to human decision, in milliseconds.', HUMAN_MS_BUCKETS)
        self.resets = Counter('smartwatch_resets_total', 'Reset commands issued, by reason.', ('reason',))
        self.acks = Counter('smartwatch_reset_acks_total', 'Reset commands acknowledged.')
        self.ack_ms = Histogram('smartwatch_reset_ack_ms', 'Reset issued to acknowledged, in milliseconds.', HUMAN_MS_BUCKETS)
        self.webhooks = Counter('smartwatch_webhooks_total', 'Webhook attempts, by kind and result.', ('kind', 'result'))
        self.top_pairs = PairGauge('smartwatch_pair_messages', 'Messages of the top pairs in the last window (estimates in sketch mode).')
        self.ingest_ms = Histogram('smartwatch_ingest_ms', 'Time to take one event batch, in milliseconds.', INGEST_MS_BUCKETS)

    def expose(self) -> str:
        lines = []
        for m in (self.events, self.messages, self.windows, self.density, self.pair_ratio, self.agents, self.pairs,
                  self.level, self.sketch, self.level_changes, self.skipped, self.late, self.proposals,
                  self.decision_ms, self.resets, self.acks, self.ack_ms, self.webhooks, self.ingest_ms, self.top_pairs):
            lines += m.expose()
        return '\n'.join(lines) + '\n'
