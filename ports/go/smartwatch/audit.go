package smartwatch

import (
	"fmt"
	"strings"
)

// Genesis is the prev of audit record 0.
var Genesis = strings.Repeat("0", 64)

// RecordHash is sha256(canonical(record without "hash")).
func RecordHash(record map[string]any) (string, error) {
	body := make(map[string]any, len(record))
	for k, v := range record {
		if k != "hash" {
			body[k] = v
		}
	}
	c, err := Canonical(body)
	if err != nil {
		return "", err
	}
	return SHA256Hex(c), nil
}

// VerifyAudit checks a chain of decoded records (spec/SEMANTICS.md section 8). It returns ok, the
// index of the first bad record (-1 when ok) and a message.
func VerifyAudit(records []any) (bool, int, string) {
	prev := Genesis
	for i, x := range records {
		r, ok := x.(map[string]any)
		if !ok {
			return false, i, fmt.Sprintf("record %d: seq is not %d", i, i)
		}
		if seq, ok := AsInt(r["seq"], int64(i), int64(i)); !ok || seq != int64(i) {
			return false, i, fmt.Sprintf("record %d: seq is not %d", i, i)
		}
		if p, ok := r["prev"].(string); !ok || p != prev {
			return false, i, fmt.Sprintf("record %d: prev does not match the hash of record %d", i, i-1)
		}
		h, err := RecordHash(r)
		if err != nil {
			return false, i, fmt.Sprintf("record %d: has no canonical form", i)
		}
		if got, ok := r["hash"].(string); !ok || got != h {
			return false, i, fmt.Sprintf("record %d: hash does not match its content", i)
		}
		prev = h
	}
	return true, -1, fmt.Sprintf("%d records, chain intact, head %s", len(records), prev)
}
