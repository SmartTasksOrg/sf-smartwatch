//! A small JSON reader and the canonical writer (no dependencies).
//!
//! Integers and floats stay distinct: a number without `.`, `e` or `E` that fits in an i64 is
//! `Int`, everything else is `Float`. Objects keep the last value of a duplicated key (as Python does)
//! and iterate in byte order of their keys, which is the canonical order.
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, k: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.get(k),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Obj(m) => Some(m),
            _ => None,
        }
    }
    /// True when this is an object whose keys are exactly `fields`.
    pub fn has_exactly(&self, fields: &[&str]) -> bool {
        match self {
            Value::Obj(m) => m.len() == fields.len() && fields.iter().all(|f| m.contains_key(*f)),
            _ => false,
        }
    }
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn s(x: &str) -> Value {
        Value::Str(x.to_string())
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut p = P { b: text.as_bytes(), i: 0, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err("trailing data".into());
    }
    Ok(v)
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 128;

impl<'a> P<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }
    fn lit(&mut self, s: &str, v: Value) -> Result<Value, String> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(v)
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }
    fn value(&mut self) -> Result<Value, String> {
        match self.b.get(self.i) {
            None => Err("unexpected end".into()),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b'[') => {
                self.enter()?;
                self.i += 1;
                let mut out = vec![];
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Arr(out));
                }
                loop {
                    self.ws();
                    out.push(self.value()?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            self.depth -= 1;
                            return Ok(Value::Arr(out));
                        }
                        _ => return Err("bad array".into()),
                    }
                }
            }
            Some(b'{') => {
                self.enter()?;
                self.i += 1;
                let mut out = BTreeMap::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Obj(out));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err("expected :".into());
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value()?;
                    out.insert(k, v);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            self.depth -= 1;
                            return Ok(Value::Obj(out));
                        }
                        _ => return Err("bad object".into()),
                    }
                }
            }
            _ => self.number(),
        }
    }
    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("nested too deeply".into());
        }
        Ok(())
    }
    fn number(&mut self) -> Result<Value, String> {
        let st = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        let digits = |p: &mut Self| {
            let s = p.i;
            while p.i < p.b.len() && p.b[p.i].is_ascii_digit() {
                p.i += 1;
            }
            p.i - s
        };
        let int_start = self.i;
        let n = digits(self);
        if n == 0 || (n > 1 && self.b[int_start] == b'0') {
            return Err(format!("bad number at {}", st));
        }
        let mut is_int = true;
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            is_int = false;
            if digits(self) == 0 {
                return Err(format!("bad number at {}", st));
            }
        }
        if matches!(self.b.get(self.i), Some(b'e') | Some(b'E')) {
            self.i += 1;
            is_int = false;
            if matches!(self.b.get(self.i), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                return Err(format!("bad number at {}", st));
            }
        }
        let t = std::str::from_utf8(&self.b[st..self.i]).map_err(|_| "bad number")?;
        if is_int {
            if let Ok(i) = t.parse::<i64>() {
                return Ok(Value::Int(i));
            }
        }
        t.parse::<f64>().map(Value::Float).map_err(|_| format!("bad number {}", t))
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.b.get(self.i..self.i + 4).ok_or("short \\u escape")?;
        if !h.iter().all(|c| c.is_ascii_hexdigit()) {
            return Err("bad \\u escape".into());
        }
        self.i += 4;
        u32::from_str_radix(std::str::from_utf8(h).unwrap(), 16).map_err(|_| "bad \\u escape".to_string())
    }
    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return Err("expected string".into());
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or("unterminated string")?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let e = *self.b.get(self.i + 1).ok_or("bad escape")?;
                    self.i += 2;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                // A high surrogate must be followed by an escaped low surrogate.
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err("unpaired surrogate".into());
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("unpaired surrogate".into());
                                }
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            out.push(char::from_u32(cp).ok_or("unpaired surrogate")?);
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                c if c < 0x20 => return Err("control character in string".into()),
                _ => {
                    let st = self.i;
                    while self.i < self.b.len() && self.b[self.i] != b'"' && self.b[self.i] != b'\\' && self.b[self.i] >= 0x20 {
                        self.i += 1;
                    }
                    out.push_str(std::str::from_utf8(&self.b[st..self.i]).map_err(|_| "bad UTF-8")?);
                }
            }
        }
    }
}

fn canon_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Canonical JSON (spec/SEMANTICS.md, section 8). Floats and non-ASCII object keys are an error.
pub fn canonical(v: &Value) -> Result<String, String> {
    let mut out = String::new();
    canon(&mut out, v)?;
    Ok(out)
}

fn canon(out: &mut String, v: &Value) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(_) => return Err("canonical JSON allows integers only".into()),
        Value::Str(s) => canon_str(out, s),
        Value::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon(out, x)?;
            }
            out.push(']');
        }
        Value::Obj(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if !k.is_ascii() {
                    return Err("object keys must be ASCII".into());
                }
                if i > 0 {
                    out.push(',');
                }
                canon_str(out, k);
                out.push(':');
                canon(out, x)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_stay_typed() {
        assert_eq!(parse("2").unwrap(), Value::Int(2));
        assert_eq!(parse("2.5").unwrap(), Value::Float(2.5));
        assert_eq!(parse("1e3").unwrap(), Value::Float(1000.0));
        assert_eq!(parse("true").unwrap(), Value::Bool(true));
        assert_eq!(parse("\"1\"").unwrap(), Value::s("1"));
        assert!(parse("01").is_err());
    }

    #[test]
    fn surrogate_pairs() {
        assert_eq!(parse("\"\\ud83d\\ude42\"").unwrap(), Value::s("\u{1F642}"));
        assert!(parse("\"\\ud83d\"").is_err());
    }

    #[test]
    fn canonical_form() {
        let v = parse("{\"b\":1,\"a\":[true,null,\"\\u2028\\u007f\\u0001\"],\"B\":-3}").unwrap();
        assert_eq!(canonical(&v).unwrap(), "{\"B\":-3,\"a\":[true,null,\"\u{2028}\u{7f}\\u0001\"],\"b\":1}");
        assert!(canonical(&Value::Float(2.5)).is_err());
    }
}
