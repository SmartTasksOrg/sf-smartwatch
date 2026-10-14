//! Policy validation (spec/SEMANTICS.md, section 3). Any violation is `WATCH-BAD-POLICY`.
use crate::json::Value;

pub const MAX_INT: i64 = (1i64 << 53) - 1;
pub const BAD_POLICY: &str = "WATCH-BAD-POLICY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl PolicyError {
    pub fn code(&self) -> &'static str {
        BAD_POLICY
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", BAD_POLICY, self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Level {
    pub name: String,
    pub min_density_micro: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reset {
    pub level: String,
    pub sustain_ms: i64,
    pub mode: String,
    pub confirm_timeout_ms: i64,
    pub on_timeout: String,
    pub cooldown_ms: i64,
    pub max_agents: i64,
    pub hot_pair_min_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_pairs_exact: i64,
    pub max_agents_exact: i64,
    pub top_k: i64,
    pub candidates: i64,
}

/// The default policy of the Python reference (`DEFAULT_POLICY`). Its thresholds are placeholders: calibrate them
/// on your own traffic (spec/SEMANTICS.md, section 7).
pub const DEFAULT_POLICY: &str = r#"{"schema": "smartwatch.policy/v1", "environment": "default", "window_ms": 1000,
 "late_windows": 2, "max_empty_windows": 10, "min_agents": 3,
 "levels": [{"name": "elevated", "min_density_micro": 2000000}, {"name": "high", "min_density_micro": 5000000},
            {"name": "critical", "min_density_micro": 10000000}],
 "hysteresis_permille": 100,
 "reset": {"level": "critical", "sustain_ms": 5000, "mode": "confirm", "confirm_timeout_ms": 5000, "on_timeout": "reset",
           "cooldown_ms": 60000, "max_agents": 10, "hot_pair_min_count": 1},
 "limits": {"max_pairs_exact": 100000, "max_agents_exact": 50000, "top_k": 10, "candidates": 1024},
 "hash_seed": "default/smartwatch"}"#;

/// A validated policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub environment: String,
    pub window_ms: i64,
    pub late_windows: i64,
    pub max_empty_windows: i64,
    pub min_agents: i64,
    pub levels: Vec<Level>,
    pub hysteresis_permille: i64,
    pub reset: Reset,
    pub limits: Limits,
    pub hash_seed: String,
}

const FIELDS: [&str; 11] = [
    "schema",
    "environment",
    "window_ms",
    "late_windows",
    "max_empty_windows",
    "min_agents",
    "levels",
    "hysteresis_permille",
    "reset",
    "limits",
    "hash_seed",
];
const RESET_FIELDS: [&str; 8] =
    ["level", "sustain_ms", "mode", "confirm_timeout_ms", "on_timeout", "cooldown_ms", "max_agents", "hot_pair_min_count"];
const LIMIT_FIELDS: [&str; 4] = ["max_pairs_exact", "max_agents_exact", "top_k", "candidates"];

/// `[A-Za-z0-9._:@/-]{1,128}`: agent ids and environment names.
pub fn is_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:@/-".contains(&b))
}

/// `[a-z][a-z0-9_-]{0,31}`: level names.
pub fn is_level_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b[1..].iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

fn bad<T>(msg: &str) -> Result<T, PolicyError> {
    Err(PolicyError(msg.to_string()))
}

fn int_in(v: Option<&Value>, lo: i64, hi: i64, name: &str) -> Result<i64, PolicyError> {
    match v {
        Some(Value::Int(i)) if *i >= lo && *i <= hi => Ok(*i),
        _ => Err(PolicyError(format!("{} must be an integer from {} to {}", name, lo, hi))),
    }
}

fn exact(v: &Value, fields: &[&str]) -> bool {
    match v {
        Value::Obj(m) => m.len() == fields.len() && fields.iter().all(|f| m.contains_key(*f)),
        _ => false,
    }
}

impl Policy {
    /// Validate a parsed policy document.
    pub fn from_value(doc: &Value) -> Result<Policy, PolicyError> {
        if !exact(doc, &FIELDS) {
            return bad("the policy must have exactly the fields of spec/SEMANTICS.md, section 3");
        }
        let g = |k: &str| doc.get(k);
        if g("schema").and_then(Value::as_str) != Some("smartwatch.policy/v1") {
            return bad("schema must be \"smartwatch.policy/v1\"");
        }
        let environment = match g("environment").and_then(Value::as_str) {
            Some(s) if is_id(s) => s.to_string(),
            _ => return bad("environment must match [A-Za-z0-9._:@/-]{1,128}"),
        };
        let window_ms = int_in(g("window_ms"), 100, 60000, "window_ms")?;
        let late_windows = int_in(g("late_windows"), 0, 60, "late_windows")?;
        let max_empty_windows = int_in(g("max_empty_windows"), 0, 3600, "max_empty_windows")?;
        let min_agents = int_in(g("min_agents"), 2, 1_000_000, "min_agents")?;
        let hysteresis_permille = int_in(g("hysteresis_permille"), 0, 900, "hysteresis_permille")?;
        let lv = match g("levels").and_then(Value::as_arr) {
            Some(a) if !a.is_empty() && a.len() <= 8 => a,
            _ => return bad("levels must be a list of 1 to 8 levels"),
        };
        let mut levels: Vec<Level> = vec![];
        let mut prev = 0i64;
        for x in lv {
            if !exact(x, &["name", "min_density_micro"]) {
                return bad("each level must be {\"name\", \"min_density_micro\"}");
            }
            let name = match x.get("name").and_then(Value::as_str) {
                Some(n) if is_level_name(n) && n != "normal" && !levels.iter().any(|l| l.name == n) => n.to_string(),
                _ => return bad("level names must match [a-z][a-z0-9_-]{0,31}, be unique and not \"normal\""),
            };
            let min = int_in(x.get("min_density_micro"), 1, MAX_INT, "min_density_micro")?;
            if min <= prev {
                return bad("min_density_micro must be strictly increasing from level to level");
            }
            prev = min;
            levels.push(Level { name, min_density_micro: min });
        }
        let r = g("reset").unwrap_or(&Value::Null);
        if !exact(r, &RESET_FIELDS) {
            return bad("reset must have exactly the fields of spec/SEMANTICS.md, section 3");
        }
        let level = match r.get("level").and_then(Value::as_str) {
            Some(n) if levels.iter().any(|l| l.name == n) => n.to_string(),
            _ => return bad("reset.level must be one of the level names"),
        };
        let mode = match r.get("mode").and_then(Value::as_str) {
            Some(m @ ("auto" | "confirm" | "off")) => m.to_string(),
            _ => return bad("reset.mode must be auto, confirm or off"),
        };
        let on_timeout = match r.get("on_timeout").and_then(Value::as_str) {
            Some(m @ ("reset" | "cancel")) => m.to_string(),
            _ => return bad("reset.on_timeout must be reset or cancel"),
        };
        let reset = Reset {
            level,
            mode,
            on_timeout,
            sustain_ms: int_in(r.get("sustain_ms"), 0, 3_600_000, "reset.sustain_ms")?,
            confirm_timeout_ms: int_in(r.get("confirm_timeout_ms"), 0, 3_600_000, "reset.confirm_timeout_ms")?,
            cooldown_ms: int_in(r.get("cooldown_ms"), 0, 86_400_000, "reset.cooldown_ms")?,
            max_agents: int_in(r.get("max_agents"), 1, 1000, "reset.max_agents")?,
            hot_pair_min_count: int_in(r.get("hot_pair_min_count"), 1, 1_000_000_000, "reset.hot_pair_min_count")?,
        };
        let li = g("limits").unwrap_or(&Value::Null);
        if !exact(li, &LIMIT_FIELDS) {
            return bad("limits must have exactly the fields of spec/SEMANTICS.md, section 3");
        }
        let limits = Limits {
            max_pairs_exact: int_in(li.get("max_pairs_exact"), 1, 10_000_000, "limits.max_pairs_exact")?,
            max_agents_exact: int_in(li.get("max_agents_exact"), 1, 10_000_000, "limits.max_agents_exact")?,
            top_k: int_in(li.get("top_k"), 1, 100, "limits.top_k")?,
            candidates: int_in(li.get("candidates"), 1, 65536, "limits.candidates")?,
        };
        let hash_seed = match g("hash_seed").and_then(Value::as_str) {
            Some(s) if !s.is_empty() && s.len() <= 256 => s.to_string(),
            _ => return bad("hash_seed must be a string of 1 to 256 UTF-8 bytes"),
        };
        Ok(Policy {
            environment,
            window_ms,
            late_windows,
            max_empty_windows,
            min_agents,
            levels,
            hysteresis_permille,
            reset,
            limits,
            hash_seed,
        })
    }

    /// Parse and validate a policy from JSON text.
    pub fn parse(text: &str) -> Result<Policy, PolicyError> {
        let v = crate::json::parse(text).map_err(|e| PolicyError(format!("not JSON ({})", e)))?;
        Policy::from_value(&v)
    }

    /// Read and validate a policy file.
    pub fn load(path: &str) -> Result<Policy, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|e| PolicyError(format!("{}: {}", path, e)))?;
        Policy::parse(&text)
    }

    /// The default policy (`DEFAULT_POLICY`).
    pub fn default_policy() -> Policy {
        Policy::parse(DEFAULT_POLICY).expect("the default policy is valid")
    }

    /// Index of a level name in `levels`, or -1 for "normal" / an unknown name.
    pub fn level_index(&self, name: &str) -> i64 {
        self.levels.iter().position(|l| l.name == name).map(|i| i as i64).unwrap_or(-1)
    }
}
