//! Seeded FNV-1a hashes (32 and 64 bit) and the MurmurHash3 fmix64 finalizer (spec/SEMANTICS.md, section 4).
//!
//! Both hashes run over UTF-8(seed) ‖ 0x00 ‖ UTF-8(text). Arithmetic wraps modulo 2^32 / 2^64.

fn feed32(mut h: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    h
}

fn feed64(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h = (h ^ b as u64).wrapping_mul(1099511628211);
    }
    h
}

pub fn fnv1a32(seed: &str, text: &str) -> u32 {
    let h = feed32(2166136261, seed.as_bytes());
    let h = feed32(h, &[0]);
    feed32(h, text.as_bytes())
}

pub fn fnv1a64(seed: &str, text: &str) -> u64 {
    let h = feed64(14695981039346656037, seed.as_bytes());
    let h = feed64(h, &[0]);
    feed64(h, text.as_bytes())
}

pub fn mix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51AFD7ED558CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CEB9FE1A85EC53);
    h ^= h >> 33;
    h
}

/// The bucket of a pair text: fnv1a32(seed, text) mod 2^20.
pub fn bucket(seed: &str, text: &str) -> usize {
    (fnv1a32(seed, text) & 0xFFFFF) as usize
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_values() {
        assert_eq!(super::fnv1a32("", ""), 84696351);
        assert_eq!(super::fnv1a64("", ""), 12638153115695167455);
        assert_eq!(super::mix64(12638153115695167455), 13331581593930102267);
    }
}
