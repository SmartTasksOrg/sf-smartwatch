//! Calibration thresholds (spec/SEMANTICS.md, section 7): nearest-rank percentiles in permille,
//! made strictly increasing and at least 1.

/// prod: p95, p99, p99.9.
pub const PROD: [i64; 3] = [950, 990, 999];
/// staging: p90, p95, p99.
pub const STAGING: [i64; 3] = [900, 950, 990];

use crate::json::Value;

/// Refuses an empty list, a negative density and a percentile outside 1 … 1000.
pub fn thresholds(densities: &[i64], permille: &[i64]) -> Result<Vec<i64>, String> {
    if densities.is_empty() {
        return Err("no densities to calibrate from".into());
    }
    if densities.iter().any(|&d| d < 0) {
        return Err("densities are integers >= 0".into());
    }
    let mut xs = densities.to_vec();
    xs.sort_unstable();
    let n = xs.len() as i64;
    let mut out = vec![];
    let mut prev = 0i64;
    for &p in permille {
        if !(1..=1000).contains(&p) {
            return Err("percentiles are integers from 1 to 1000 (permille)".into());
        }
        let rank = (p * n + 999) / 1000;
        let v = xs[(rank.max(1) - 1) as usize].max(prev + 1).max(1);
        out.push(v);
        prev = v;
    }
    Ok(out)
}

/// `thresholds` over parsed JSON values: a density that is not an integer >= 0 (1.5, true, "5", -2) or a
/// percentile that is not an integer is refused.
pub fn thresholds_json(densities: &[Value], permille: &[Value]) -> Result<Vec<i64>, String> {
    let d: Vec<i64> = densities
        .iter()
        .map(|v| v.as_int().filter(|&i| i >= 0).ok_or_else(|| "densities are integers >= 0".to_string()))
        .collect::<Result<_, _>>()?;
    let p: Vec<i64> = permille
        .iter()
        .map(|v| v.as_int().ok_or_else(|| "percentiles are integers from 1 to 1000 (permille)".to_string()))
        .collect::<Result<_, _>>()?;
    thresholds(&d, &p)
}
