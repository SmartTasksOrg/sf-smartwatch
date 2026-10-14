//! Audit chain verification (spec/SEMANTICS.md, section 8). A record's `hash` is the lower-case hex
//! SHA-256 of the canonical JSON of the record without `hash`; `prev` is the hash of the record before
//! (64 zeros for record 0) and `seq` its index.
use crate::json::{canonical, Value};
use crate::sha256;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The hash of a record (its `hash` field left out), or an error when it has no canonical form.
pub fn record_hash(record: &Value) -> Result<String, String> {
    match record {
        Value::Obj(m) => {
            let mut body = m.clone();
            body.remove("hash");
            Ok(sha256::hex(canonical(&Value::Obj(body))?.as_bytes()))
        }
        _ => Err("a record is an object".into()),
    }
}

/// Ok(head hash) or Err((index of the first bad record, message)).
pub fn verify(records: &[Value]) -> Result<String, (usize, String)> {
    let mut prev = GENESIS.to_string();
    for (i, r) in records.iter().enumerate() {
        if r.get("seq") != Some(&Value::Int(i as i64)) {
            return Err((i, format!("record {}: seq is not {}", i, i)));
        }
        if r.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            return Err((i, format!("record {}: prev does not match the hash of the record before", i)));
        }
        let h = record_hash(r).map_err(|_| (i, format!("record {}: has no canonical form", i)))?;
        if r.get("hash").and_then(Value::as_str) != Some(h.as_str()) {
            return Err((i, format!("record {}: hash does not match its content", i)));
        }
        prev = h;
    }
    Ok(prev)
}
