package smartwatch

import (
	"errors"
	"sort"
)

// Profiles are the permille percentiles of the calibration profiles (spec/SEMANTICS.md section 7).
var Profiles = map[string][]int64{"prod": {950, 990, 999}, "staging": {900, 950, 990}}

// Thresholds returns nearest-rank permille percentiles of densities, made strictly increasing and at
// least 1. It refuses an empty list, a negative density and percentiles outside 1 … 1000.
func Thresholds(densities []int64, permille []int64) ([]int64, error) {
	for _, d := range densities {
		if d < 0 {
			return nil, errors.New("densities are non-negative integers")
		}
	}
	if len(densities) == 0 {
		return nil, errors.New("no densities to calibrate from")
	}
	xs := append([]int64(nil), densities...)
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	n := int64(len(xs))
	out := make([]int64, 0, len(permille))
	var prev int64
	for _, p := range permille {
		if p < 1 || p > 1000 {
			return nil, errors.New("percentiles are integers from 1 to 1000 (permille)")
		}
		rank := (p*n + 999) / 1000
		if rank < 1 {
			rank = 1
		}
		v := xs[rank-1]
		if v < prev+1 {
			v = prev + 1
		}
		if v < 1 {
			v = 1
		}
		out = append(out, v)
		prev = v
	}
	return out, nil
}
