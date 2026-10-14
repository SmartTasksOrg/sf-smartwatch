package smartwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/bits"
)

// HyperLogLog, p = 14 (spec/SEMANTICS.md section 5): 16,384 one-byte registers.
const (
	hllP      = 14
	hllM      = 1 << hllP
	hllMaxRho = 64 - hllP + 1 // 51
)

var hllAlpha = 0.7213 / (1 + 1.079/float64(hllM))

// HyperLogLog is a distinct counter. The zero value is not usable; use NewHyperLogLog.
type HyperLogLog struct {
	seed string
	reg  [hllM]byte
}

// NewHyperLogLog returns an empty counter hashing with seed.
func NewHyperLogLog(seed string) *HyperLogLog { return &HyperLogLog{seed: seed} }

// Add counts item.
func (h *HyperLogLog) Add(item string) {
	x := Mix64(FNV1a64(h.seed, item))
	j := x >> (64 - hllP)
	w := x & (1<<(64-hllP) - 1)
	rho := byte(hllMaxRho - bits.Len64(w))
	if rho > h.reg[j] {
		h.reg[j] = rho
	}
}

// Estimate returns the distinct count estimate (doubles, summation order fixed by the spec).
func (h *HyperLogLog) Estimate() int64 {
	var counts [hllMaxRho + 1]int
	for _, r := range h.reg {
		counts[r]++
	}
	z := 0.0
	for v := hllMaxRho; v >= 0; v-- {
		if counts[v] > 0 {
			z += float64(counts[v]) * math.Ldexp(1, -v)
		}
	}
	m := float64(hllM)
	e := hllAlpha * m * m / z
	if e <= 2.5*m && counts[0] > 0 {
		e = m * math.Log(m/float64(counts[0]))
	}
	f := math.Floor(e + 0.5)
	if f >= float64(MaxInt) {
		return MaxInt
	}
	return int64(f)
}

// Digest is the lower-case hex SHA-256 of the registers.
func (h *HyperLogLog) Digest() string {
	s := sha256.Sum256(h.reg[:])
	return hex.EncodeToString(s[:])
}
