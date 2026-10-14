//! The SmartWatch engine (spec/SEMANTICS.md, sections 1, 2 and 6): count messages between agents per
//! window, compute the coupling density, grade it and decide when a reset is due. Deterministic: no
//! clock and no randomness; time comes from the events and from `flush(now_ms)`.
//!
//! ```no_run
//! use smartwatch::{Engine, Policy};
//! let mut eng = Engine::new(Policy::default_policy());
//! let out = eng.add("planner", "coder", 1_700_000_000_123, 4).unwrap();   // often empty
//! let out = eng.flush(1_700_000_010_000).unwrap();                        // close windows by the clock
//! for o in &out { println!("{}", smartwatch::json::canonical(&o.to_value()).unwrap()); }
//! ```
use crate::hashing::bucket;
use crate::hll::HyperLogLog;
use crate::json::Value;
use crate::policy::{is_id, Policy, MAX_INT};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const BAD_EVENT: &str = "WATCH-BAD-EVENT";
/// 2^20 bucket counters, allocated when a window goes over `limits.max_pairs_exact`.
pub const BUCKETS: usize = 1 << 20;
/// An agent estimate above this is reported as this (keeps n(n-1)/2 below 2^53).
pub const MAX_AGENTS: i64 = 100_000_000;
const MICRO: i64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventError(pub String);

impl EventError {
    pub fn code(&self) -> &'static str {
        BAD_EVENT
    }
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", BAD_EVENT, self.0)
    }
}

impl std::error::Error for EventError {}

/// Check an event (spec/SEMANTICS.md, section 2).
pub fn check_event(src: &str, dst: &str, ts_ms: i64, count: i64) -> Result<(), EventError> {
    if !is_id(src) || !is_id(dst) {
        return Err(EventError("src and dst must match [A-Za-z0-9._:@/-]{1,128}".into()));
    }
    if !(0..=MAX_INT).contains(&ts_ms) {
        return Err(EventError("ts_ms must be an integer from 0 to 2^53 - 1".into()));
    }
    if !(1..=1_000_000_000).contains(&count) {
        return Err(EventError("count must be an integer from 1 to 10^9".into()));
    }
    Ok(())
}

/// min(2^53 - 1, floor((double(messages) * 1e9) / (double(possible_pairs) * double(window_ms)))), 0 without pairs.
pub fn density_micro(messages: i64, possible_pairs: i64, window_ms: i64) -> i64 {
    if possible_pairs <= 0 {
        return 0;
    }
    let d = ((messages as f64 * 1e9) / (possible_pairs as f64 * window_ms as f64)).floor();
    if d >= MAX_INT as f64 {
        MAX_INT
    } else {
        d as i64
    }
}

/// Saturating add at 2^53 - 1.
pub fn sat(a: i64, b: i64) -> i64 {
    a.saturating_add(b).min(MAX_INT)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopPair {
    pub a: String,
    pub b: String,
    pub count: i64,
    pub exact: bool,
}

/// One engine output (spec/SEMANTICS.md, section 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Window {
        window: i64,
        start_ms: i64,
        messages: i64,
        self_messages: i64,
        agents: i64,
        pairs: i64,
        possible_pairs: i64,
        density_micro: i64,
        pair_ratio_micro: i64,
        exact: bool,
        level: String,
        top: Vec<TopPair>,
    },
    Level {
        window: i64,
        from: String,
        to: String,
        density_micro: i64,
    },
    Reset {
        window: i64,
        mode: String,
        level: String,
        density_micro: i64,
        sustained_ms: i64,
        agents: Vec<String>,
    },
}

impl Output {
    /// The JSON object of this output, with exactly the fields of spec/SEMANTICS.md.
    pub fn to_value(&self) -> Value {
        let i = Value::Int;
        match self {
            Output::Window {
                window,
                start_ms,
                messages,
                self_messages,
                agents,
                pairs,
                possible_pairs,
                density_micro,
                pair_ratio_micro,
                exact,
                level,
                top,
            } => Value::obj(vec![
                ("kind", Value::s("window")),
                ("window", i(*window)),
                ("start_ms", i(*start_ms)),
                ("messages", i(*messages)),
                ("self_messages", i(*self_messages)),
                ("agents", i(*agents)),
                ("pairs", i(*pairs)),
                ("possible_pairs", i(*possible_pairs)),
                ("density_micro", i(*density_micro)),
                ("pair_ratio_micro", i(*pair_ratio_micro)),
                ("exact", Value::Bool(*exact)),
                ("level", Value::s(level)),
                (
                    "top",
                    Value::Arr(
                        top.iter()
                            .map(|t| {
                                Value::obj(vec![
                                    ("a", Value::s(&t.a)),
                                    ("b", Value::s(&t.b)),
                                    ("count", i(t.count)),
                                    ("exact", Value::Bool(t.exact)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
            Output::Level { window, from, to, density_micro } => Value::obj(vec![
                ("kind", Value::s("level")),
                ("window", i(*window)),
                ("from", Value::s(from)),
                ("to", Value::s(to)),
                ("density_micro", i(*density_micro)),
            ]),
            Output::Reset { window, mode, level, density_micro, sustained_ms, agents } => Value::obj(vec![
                ("kind", Value::s("reset")),
                ("window", i(*window)),
                ("mode", Value::s(mode)),
                ("level", Value::s(level)),
                ("density_micro", i(*density_micro)),
                ("sustained_ms", i(*sustained_ms)),
                ("agents", Value::Arr(agents.iter().map(|a| Value::s(a)).collect())),
            ]),
        }
    }
}

/// The engine's counters (spec/SEMANTICS.md, "snapshot()").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub level: String,
    pub next_window: Option<i64>,
    pub open_windows: i64,
    pub events: i64,
    pub messages: i64,
    pub late_dropped: i64,
    pub skipped_windows: i64,
    pub windows: i64,
}

impl Snapshot {
    pub fn to_value(&self) -> Value {
        Value::obj(vec![
            ("level", Value::s(&self.level)),
            ("next_window", self.next_window.map(Value::Int).unwrap_or(Value::Null)),
            ("open_windows", Value::Int(self.open_windows)),
            ("events", Value::Int(self.events)),
            ("messages", Value::Int(self.messages)),
            ("late_dropped", Value::Int(self.late_dropped)),
            ("skipped_windows", Value::Int(self.skipped_windows)),
            ("windows", Value::Int(self.windows)),
        ])
    }
}

type Pair = (String, String);

#[derive(Default)]
struct Window {
    pairs: HashMap<Pair, i64>,
    agents: HashSet<String>,
    total: i64,
    self_messages: i64,
    buckets: Option<Vec<i64>>,
    cand: HashMap<Pair, i64>,
    /// The candidates ordered by (estimate, a, b), for the eviction.
    order: BTreeSet<(i64, String, String)>,
    hll_pairs: Option<HyperLogLog>,
    hll_agents: Option<HyperLogLog>,
    pairs_over: bool,
    agents_over: bool,
}

fn text(k: &Pair) -> String {
    format!("{}\n{}", k.0, k.1)
}

pub struct Engine {
    policy: Policy,
    reset_idx: i64,
    acc: BTreeMap<i64, Window>,
    next_emit: Option<i64>,
    high: i64,
    empties: i64,
    level: i64,
    streak_start: Option<i64>,
    triggered: bool,
    last_trigger: Option<i64>,
    events: i64,
    messages: i64,
    late_dropped: i64,
    skipped_windows: i64,
    windows: i64,
}

impl Engine {
    pub fn new(policy: Policy) -> Engine {
        let reset_idx = policy.level_index(&policy.reset.level);
        Engine {
            policy,
            reset_idx,
            acc: BTreeMap::new(),
            next_emit: None,
            high: 0,
            empties: 0,
            level: -1,
            streak_start: None,
            triggered: false,
            last_trigger: None,
            events: 0,
            messages: 0,
            late_dropped: 0,
            skipped_windows: 0,
            windows: 0,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Count `count` messages from `src` to `dst` at `ts_ms`; returns the outputs of the windows it closed.
    pub fn add(&mut self, src: &str, dst: &str, ts_ms: i64, count: i64) -> Result<Vec<Output>, EventError> {
        check_event(src, dst, ts_ms, count)?;
        let w = ts_ms / self.policy.window_ms;
        if self.next_emit.is_none() {
            self.next_emit = Some(w);
            self.high = w;
        }
        let next = self.next_emit.unwrap_or(w);
        if w < next {
            self.late_dropped = sat(self.late_dropped, count);
            return Ok(vec![]);
        }
        self.events = sat(self.events, 1);
        self.messages = sat(self.messages, count);
        let lim = &self.policy.limits;
        let seed = &self.policy.hash_seed;
        let acc = self.acc.entry(w).or_default();
        count_into(acc, lim.max_agents_exact, lim.max_pairs_exact, lim.candidates, seed, src, dst, count);
        if w > self.high {
            self.high = w;
        }
        Ok(self.close())
    }

    /// Close the windows the clock says are complete (also when no event arrives).
    pub fn flush(&mut self, now_ms: i64) -> Result<Vec<Output>, EventError> {
        if !(0..=MAX_INT).contains(&now_ms) {
            return Err(EventError("now_ms must be an integer from 0 to 2^53 - 1".into()));
        }
        if self.next_emit.is_none() {
            return Ok(vec![]);
        }
        self.high = self.high.max(now_ms / self.policy.window_ms);
        Ok(self.close())
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            level: self.name(self.level),
            next_window: self.next_emit,
            open_windows: self.acc.len() as i64,
            events: self.events,
            messages: self.messages,
            late_dropped: self.late_dropped,
            skipped_windows: self.skipped_windows,
            windows: self.windows,
        }
    }

    fn name(&self, i: i64) -> String {
        if i < 0 {
            "normal".to_string()
        } else {
            self.policy.levels[i as usize].name.clone()
        }
    }

    fn close(&mut self) -> Vec<Output> {
        let mut out = vec![];
        let late = self.policy.late_windows;
        while let Some(w) = self.next_emit {
            if w + late >= self.high {
                break;
            }
            if let Some(acc) = self.acc.remove(&w) {
                self.empties = 0;
                self.emit(w, &acc, &mut out);
                self.next_emit = Some(w + 1);
            } else if self.empties < self.policy.max_empty_windows {
                self.empties += 1;
                self.emit(w, &Window::default(), &mut out);
                self.next_emit = Some(w + 1);
            } else {
                let bound = self.high - late;
                let nxt = self.acc.range(w..).next().map(|(k, _)| *k).unwrap_or(bound).min(bound);
                self.skipped_windows += nxt - w;
                self.next_emit = Some(nxt);
                self.streak_start = None;
                self.triggered = false;
                if self.level != -1 {
                    out.push(Output::Level { window: w, from: self.name(self.level), to: "normal".into(), density_micro: 0 });
                    self.level = -1;
                }
            }
        }
        out
    }

    fn emit(&mut self, w: i64, acc: &Window, out: &mut Vec<Output>) {
        self.windows += 1;
        let n = if acc.agents_over {
            acc.hll_agents.as_ref().map(|h| h.estimate()).unwrap_or(0).min(MAX_AGENTS)
        } else {
            acc.agents.len() as i64
        };
        let possible = n * (n - 1) / 2;
        let distinct = if acc.pairs_over {
            acc.hll_pairs.as_ref().map(|h| h.estimate()).unwrap_or(0).min(possible)
        } else {
            acc.pairs.len() as i64
        };
        let window_ms = self.policy.window_ms;
        let density = density_micro(acc.total, possible, window_ms);
        let ratio = if possible > 0 { ((distinct as f64 * 1e6 / possible as f64).floor() as i64).min(MICRO) } else { 0 };
        let mut entries: Vec<(i64, &str, &str, bool)> =
            acc.pairs.iter().map(|((a, b), c)| (*c, a.as_str(), b.as_str(), true)).collect();
        entries.extend(acc.cand.iter().filter(|(k, _)| !acc.pairs.contains_key(*k)).map(|((a, b), c)| (*c, a.as_str(), b.as_str(), false)));
        entries.sort_by(|x, y| y.0.cmp(&x.0).then_with(|| x.1.cmp(y.1)).then_with(|| x.2.cmp(y.2)));
        let top: Vec<TopPair> = entries
            .iter()
            .take(self.policy.limits.top_k as usize)
            .map(|(c, a, b, ex)| TopPair { a: a.to_string(), b: b.to_string(), count: *c, exact: *ex })
            .collect();
        let before = self.level;
        self.level = self.grade(density, n);
        let name = self.name(self.level);
        let reset = self.reset_due(w, &top, density);
        out.push(Output::Window {
            window: w,
            start_ms: w * window_ms,
            messages: acc.total,
            self_messages: acc.self_messages,
            agents: n,
            pairs: distinct,
            possible_pairs: possible,
            density_micro: density,
            pair_ratio_micro: ratio,
            exact: !(acc.pairs_over || acc.agents_over),
            level: name.clone(),
            top,
        });
        if self.level != before {
            out.push(Output::Level { window: w, from: self.name(before), to: name, density_micro: density });
        }
        if let Some(r) = reset {
            out.push(r);
        }
    }

    fn grade(&self, density: i64, agents: i64) -> i64 {
        if agents < self.policy.min_agents {
            return -1;
        }
        let levels = &self.policy.levels;
        let mut raw = -1i64;
        for (i, lv) in levels.iter().enumerate() {
            if density >= lv.min_density_micro {
                raw = i as i64;
            }
        }
        if raw >= self.level {
            return raw;
        }
        let h = self.policy.hysteresis_permille as i128;
        let mut j = self.level;
        while j > raw {
            if density as i128 * 1000 >= levels[j as usize].min_density_micro as i128 * (1000 - h) {
                return j;
            }
            j -= 1;
        }
        raw
    }

    fn reset_due(&mut self, w: i64, top: &[TopPair], density: i64) -> Option<Output> {
        if self.level < self.reset_idx {
            self.streak_start = None;
            self.triggered = false;
            return None;
        }
        let start = *self.streak_start.get_or_insert(w);
        let r = &self.policy.reset;
        if r.mode == "off" || self.triggered {
            return None;
        }
        let window_ms = self.policy.window_ms;
        let sustained = (w - start + 1) * window_ms;
        if sustained < r.sustain_ms {
            return None;
        }
        if let Some(last) = self.last_trigger {
            if (w - last) * window_ms < r.cooldown_ms {
                return None;
            }
        }
        self.triggered = true;
        self.last_trigger = Some(w);
        let mut agents: Vec<String> = vec![];
        for t in top {
            if t.count < r.hot_pair_min_count {
                break;
            }
            for a in [&t.a, &t.b] {
                if !agents.contains(a) && (agents.len() as i64) < r.max_agents {
                    agents.push(a.clone());
                }
            }
        }
        Some(Output::Reset {
            window: w,
            mode: r.mode.clone(),
            level: self.name(self.level),
            density_micro: density,
            sustained_ms: sustained,
            agents,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn count_into(acc: &mut Window, max_agents: i64, max_pairs: i64, candidates: i64, seed: &str, src: &str, dst: &str, count: i64) {
    if src == dst {
        acc.self_messages = sat(acc.self_messages, count);
        return;
    }
    acc.total = sat(acc.total, count);
    for a in [src, dst] {
        if acc.agents.contains(a) {
            continue;
        }
        if acc.agents_over {
            acc.hll_agents.as_mut().expect("hll_agents").add(a);
        } else if (acc.agents.len() as i64) < max_agents {
            acc.agents.insert(a.to_string());
        } else {
            acc.agents_over = true;
            let mut h = HyperLogLog::new(seed);
            for x in &acc.agents {
                h.add(x);
            }
            h.add(a);
            acc.hll_agents = Some(h);
        }
    }
    let key: Pair = if src < dst { (src.to_string(), dst.to_string()) } else { (dst.to_string(), src.to_string()) };
    if let Some(c) = acc.pairs.get_mut(&key) {
        *c = sat(*c, count);
        return;
    }
    if !acc.pairs_over && (acc.pairs.len() as i64) < max_pairs {
        acc.pairs.insert(key, count);
        return;
    }
    let t = text(&key);
    if !acc.pairs_over {
        acc.pairs_over = true;
        let mut h = HyperLogLog::new(seed);
        for k in acc.pairs.keys() {
            h.add(&text(k));
        }
        acc.hll_pairs = Some(h);
        acc.buckets = Some(vec![0i64; BUCKETS]);
    }
    acc.hll_pairs.as_mut().expect("hll_pairs").add(&t);
    let buckets = acc.buckets.as_mut().expect("buckets");
    let i = bucket(seed, &t);
    buckets[i] = sat(buckets[i], count);
    let est = buckets[i];
    if let Some(old) = acc.cand.get(&key).copied() {
        acc.order.remove(&(old, key.0.clone(), key.1.clone()));
        acc.order.insert((est, key.0.clone(), key.1.clone()));
        acc.cand.insert(key, est);
    } else if (acc.cand.len() as i64) < candidates {
        acc.order.insert((est, key.0.clone(), key.1.clone()));
        acc.cand.insert(key, est);
    } else {
        let low = acc.order.iter().next().cloned().expect("candidates is at least 1");
        if (est, key.0.as_str(), key.1.as_str()) > (low.0, low.1.as_str(), low.2.as_str()) {
            acc.order.remove(&low);
            acc.cand.remove(&(low.1, low.2));
            acc.order.insert((est, key.0.clone(), key.1.clone()));
            acc.cand.insert(key, est);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn density_example_of_the_spec() {
        // 5 agents (10 possible pairs), 200 messages in 1 s: 20 messages per pair per second.
        assert_eq!(density_micro(200, 10, 1000), 20_000_000);
        assert_eq!(density_micro(10, 0, 1000), 0);
    }

    #[test]
    fn a_window_closes_after_late_windows() {
        let mut eng = Engine::new(Policy::default_policy());
        assert!(eng.add("a", "b", 1_000, 1).unwrap().is_empty());
        assert!(eng.add("a", "b", 3_000, 1).unwrap().is_empty()); // late_windows = 2
        let out = eng.add("a", "b", 4_000, 1).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Output::Window { window: 1, messages: 1, agents: 2, .. }));
        assert_eq!(eng.add("a", "b", 999, 1).unwrap(), vec![]);
        assert_eq!(eng.snapshot().late_dropped, 1);
        assert!(eng.add("a b", "c", 4_000, 1).is_err());
    }
}
