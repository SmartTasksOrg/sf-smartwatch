//! HyperLogLog, p = 14 (spec/SEMANTICS.md, section 5): 16,384 one-byte registers.
use crate::hashing::{fnv1a64, mix64};
use crate::sha256;

pub const P: u32 = 14;
pub const M: usize = 1 << P;
const MAXRHO: usize = 64 - P as usize + 1; // 51
pub const MAX_INT: i64 = (1i64 << 53) - 1;

#[derive(Clone)]
pub struct HyperLogLog {
    seed: String,
    reg: Vec<u8>,
}

impl HyperLogLog {
    pub fn new(seed: &str) -> HyperLogLog {
        HyperLogLog { seed: seed.to_string(), reg: vec![0u8; M] }
    }

    pub fn add(&mut self, item: &str) {
        let h = mix64(fnv1a64(&self.seed, item));
        let j = (h >> (64 - P)) as usize;
        let w = h & ((1u64 << (64 - P)) - 1);
        let bitlen = 64 - w.leading_zeros() as usize; // 0 for w == 0
        let rho = (MAXRHO - bitlen) as u8;
        if rho > self.reg[j] {
            self.reg[j] = rho;
        }
    }

    pub fn estimate(&self) -> i64 {
        let mut counts = [0u64; MAXRHO + 1];
        for &r in &self.reg {
            counts[r as usize] += 1;
        }
        let mut z = 0.0f64;
        for v in (0..=MAXRHO).rev() {
            if counts[v] > 0 {
                z += counts[v] as f64 * f64::from_bits(((1023 - v) as u64) << 52); // exactly 2^-v
            }
        }
        let m = M as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let mut e = alpha * m * m / z;
        let zeros = counts[0];
        if e <= 2.5 * m && zeros > 0 {
            e = m * (m / zeros as f64).ln();
        }
        let r = (e + 0.5).floor();
        if r >= MAX_INT as f64 {
            MAX_INT
        } else {
            r as i64
        }
    }

    /// Lower-case hex SHA-256 of the 16,384 registers.
    pub fn digest(&self) -> String {
        sha256::hex(&self.reg)
    }
}
