//! Run the shared vectors (spec/conformance/*.json) against this port:
//!     cargo run --release --bin conformance -- <vectors dir>
//! Prints each failure and a last line "rust: N/N vectors passed"; exit 1 on any failure.
use smartwatch::audit;
use smartwatch::calibrate::thresholds_json;
use smartwatch::engine::{density_micro, Engine, EventError, Output};
use smartwatch::hashing::{fnv1a32, fnv1a64, mix64};
use smartwatch::hll::HyperLogLog;
use smartwatch::json::{self, canonical, Value};
use smartwatch::policy::Policy;
use smartwatch::sha256;

fn load(dir: &str, name: &str) -> Value {
    let path = format!("{}/{}", dir, name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}", path, e));
    json::parse(&text).unwrap_or_else(|e| panic!("{}: {}", path, e))
}

fn show(v: &Value) -> String {
    let s = canonical(v).unwrap_or_else(|_| format!("{:?}", v));
    s.chars().take(300).collect()
}

fn cases(v: &Value) -> &Vec<Value> {
    v.get("cases").and_then(Value::as_arr).expect("cases")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing string {}", k))
}

fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_int).unwrap_or_else(|| panic!("missing integer {}", k))
}

fn null() -> &'static Value {
    &Value::Null
}

/// The keys of `c` among `keys`, as an object (the "want" of a case).
fn pick(c: &Value, keys: &[&str]) -> Value {
    Value::Obj(keys.iter().filter_map(|k| c.get(k).map(|v| (k.to_string(), v.clone()))).collect())
}

fn err(code: &str) -> Value {
    Value::obj(vec![("ok", Value::Bool(false)), ("code", Value::s(code))])
}

fn outputs(r: Result<Vec<Output>, EventError>) -> Value {
    match r {
        Ok(out) => Value::obj(vec![("ok", Value::Bool(true)), ("outputs", Value::Arr(out.iter().map(Output::to_value).collect()))]),
        Err(e) => err(e.code()),
    }
}

/// An event field from a vector: a string id or an integer; anything else is a bad event.
fn add(eng: &mut Engine, st: &Value) -> Result<Vec<Output>, EventError> {
    let bad = || EventError("src, dst must be strings; ts_ms and count integers".into());
    let src = st.get("src").and_then(Value::as_str).ok_or_else(bad)?;
    let dst = st.get("dst").and_then(Value::as_str).ok_or_else(bad)?;
    let ts = st.get("ts_ms").and_then(Value::as_int).ok_or_else(bad)?;
    let count = st.get("count").and_then(Value::as_int).ok_or_else(bad)?;
    eng.add(src, dst, ts, count)
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "../../spec/conformance".into());
    let mut total = 0usize;
    let mut fails: Vec<String> = vec![];
    let mut check = |name: String, got: Value, want: &Value| {
        total += 1;
        if &got != want {
            fails.push(format!("{}: got {}, want {}", name, show(&got), show(want)));
        }
    };

    let v = load(&dir, "canonical.json");
    for c in cases(&v) {
        let got = match canonical(c.get("input").unwrap_or(null())) {
            Ok(t) => Value::Arr(vec![Value::Str(t.clone()), Value::Str(sha256::hex(t.as_bytes()))]),
            Err(e) => Value::Str(format!("error: {}", e)),
        };
        let want = Value::Arr(vec![c.get("canonical").cloned().unwrap_or(Value::Null), c.get("sha256").cloned().unwrap_or(Value::Null)]);
        check(format!("canonical/{}", s(c, "name")), got, &want);
    }

    let v = load(&dir, "hashing.json");
    for (k, c) in cases(&v).iter().enumerate() {
        let (seed, text) = (s(c, "seed"), s(c, "text"));
        let h64 = fnv1a64(seed, text);
        let h32 = fnv1a32(seed, text);
        let got = Value::obj(vec![
            ("fnv1a32", Value::Int(h32 as i64)),
            ("fnv1a64", Value::Str(h64.to_string())),
            ("mix64", Value::Str(mix64(h64).to_string())),
            ("bucket", Value::Int((h32 % (1 << 20)) as i64)),
        ]);
        check(format!("hashing/{}", k), got, &pick(c, &["fnv1a32", "fnv1a64", "mix64", "bucket"]));
    }

    let v = load(&dir, "hll.json");
    for c in cases(&v) {
        let mut h = HyperLogLog::new(s(c, "seed"));
        match c.get("items") {
            Some(Value::Arr(a)) => {
                for x in a {
                    h.add(x.as_str().expect("string item"));
                }
            }
            Some(r @ Value::Obj(_)) => {
                let prefix = s(r, "prefix");
                let mut item = String::with_capacity(prefix.len() + 20);
                for n in i(r, "from")..i(r, "to") {
                    item.clear();
                    item.push_str(prefix);
                    item.push_str(&n.to_string());
                    h.add(&item);
                }
            }
            _ => panic!("hll items"),
        }
        let got = Value::obj(vec![("estimate", Value::Int(h.estimate())), ("digest", Value::Str(h.digest()))]);
        check(format!("hll/{}", s(c, "name")), got, &pick(c, &["estimate", "digest"]));
    }

    let v = load(&dir, "density.json");
    for (k, c) in cases(&v).iter().enumerate() {
        let got = density_micro(i(c, "messages"), i(c, "possible_pairs"), i(c, "window_ms"));
        check(format!("density/{}", k), Value::Int(got), c.get("density_micro").unwrap_or(null()));
    }

    let v = load(&dir, "policies.json");
    for c in cases(&v) {
        let got = match Policy::from_value(c.get("policy").unwrap_or(null())) {
            Ok(_) => Value::obj(vec![("ok", Value::Bool(true))]),
            Err(e) => err(e.code()),
        };
        check(format!("policies/{}", s(c, "name")), got, &pick(c, &["ok", "code"]));
    }

    let v = load(&dir, "calibration.json");
    for c in cases(&v) {
        let arr = |k: &str| c.get(k).and_then(Value::as_arr).expect(k);
        let got = match thresholds_json(arr("densities"), arr("permille")) {
            Ok(t) => Value::obj(vec![("ok", Value::Bool(true)), ("thresholds", Value::Arr(t.into_iter().map(Value::Int).collect()))]),
            Err(_) => Value::obj(vec![("ok", Value::Bool(false))]),
        };
        check(format!("calibration/{}", s(c, "name")), got, &pick(c, &["ok", "thresholds"]));
    }

    let v = load(&dir, "monitor.json");
    for c in cases(&v) {
        let name = s(c, "name");
        let mut eng = Engine::new(Policy::from_value(c.get("policy").unwrap_or(null())).expect("a valid policy"));
        for (k, st) in c.get("steps").and_then(Value::as_arr).expect("steps").iter().enumerate() {
            let op = s(st, "op");
            let got = match op {
                "add" => outputs(add(&mut eng, st)),
                "flush" => outputs(match st.get("now_ms").and_then(Value::as_int) {
                    Some(now) => eng.flush(now),
                    None => Err(EventError("now_ms must be an integer".into())),
                }),
                _ => eng.snapshot().to_value(),
            };
            check(format!("monitor/{} step {} ({})", name, k, op), got, st.get("expect").unwrap_or(null()));
        }
    }

    let v = load(&dir, "audit.json");
    for c in cases(&v) {
        let recs = c.get("records").and_then(Value::as_arr).expect("records");
        let got = match audit::verify(recs) {
            Ok(_) => Value::obj(vec![("ok", Value::Bool(true)), ("index", Value::Null)]),
            Err((idx, _)) => Value::obj(vec![("ok", Value::Bool(false)), ("index", Value::Int(idx as i64))]),
        };
        check(format!("audit/{}", s(c, "name")), got, c.get("result").unwrap_or(null()));
    }

    for f in &fails {
        println!("FAIL {}", f);
    }
    if fails.is_empty() {
        println!("rust: {}/{} vectors passed", total, total);
    } else {
        println!("rust: {} of {} vectors failed", fails.len(), total);
        std::process::exit(1);
    }
}
