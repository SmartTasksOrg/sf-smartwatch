package smartwatch

// Seeded FNV-1a 32/64 over UTF-8(seed) ‖ 0x00 ‖ UTF-8(text), and mix64 (MurmurHash3 fmix64)
// (spec/SEMANTICS.md section 4). Unsigned arithmetic wraps modulo 2^32 / 2^64.

// FNV1a32 is FNV-1a 32 over seed ‖ 0x00 ‖ text.
func FNV1a32(seed, text string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(seed); i++ {
		h = (h ^ uint32(seed[i])) * 16777619
	}
	h *= 16777619 // h ^ 0 == h
	for i := 0; i < len(text); i++ {
		h = (h ^ uint32(text[i])) * 16777619
	}
	return h
}

// FNV1a64 is FNV-1a 64 over seed ‖ 0x00 ‖ text.
func FNV1a64(seed, text string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(seed); i++ {
		h = (h ^ uint64(seed[i])) * 1099511628211
	}
	h *= 1099511628211
	for i := 0; i < len(text); i++ {
		h = (h ^ uint64(text[i])) * 1099511628211
	}
	return h
}

// Mix64 is MurmurHash3's 64-bit finalizer.
func Mix64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xFF51AFD7ED558CCD
	h ^= h >> 33
	h *= 0xC4CEB9FE1A85EC53
	h ^= h >> 33
	return h
}
