// Package smartwatch is the Go port of the SmartWatch engine and agent side: coupling density per
// window, levels and reset decisions (the deterministic engine), the audit chain check, and the
// reporter and command poller that talk to the Python monitor over HTTP.
// Semantics: spec/SEMANTICS.md; tests: spec/conformance.
//
// JSON values are handled as decoded by DecodeJSON (encoding/json with UseNumber): map[string]any,
// []any, string, json.Number, bool and nil, so that 2.5, 1.0, true and "1" can be told apart from
// integers.
package smartwatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// MaxInt is 2^53 - 1, the largest integer in any document or output.
const MaxInt int64 = 1<<53 - 1

// DecodeJSON parses one JSON value with UseNumber. Trailing data is an error.
func DecodeJSON(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

// AsInt returns v as an int64 when it is a JSON integer (json.Number without fraction or exponent, or a
// Go integer) within [lo, hi]. Booleans, strings and fractional numbers (also 1.0) are not integers.
func AsInt(v any, lo, hi int64) (int64, bool) {
	var n int64
	switch x := v.(type) {
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			return 0, false
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, false // outside int64: outside every allowed range
		}
		n = i
	case int:
		n = int64(x)
	case int64:
		n = x
	default:
		return 0, false
	}
	if n < lo || n > hi {
		return 0, false
	}
	return n, true
}

// Canonical returns the canonical JSON text of v (spec/SEMANTICS.md section 8): ASCII keys sorted
// byte-wise, no whitespace, strings escaped only as \" \\ \b \f \n \r \t and \u00XX for the other
// characters below U+0020, integers only. It does not use json.Marshal, which escapes <, >, &, U+2028
// and U+2029.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := canon(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// SHA256Hex is the lower-case hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func canonStr(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func canon(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			return errors.New("canonical JSON allows integers only")
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return fmt.Errorf("not a JSON integer: %q", s)
		}
		b.WriteString(n.String())
	case float32, float64:
		return errors.New("canonical JSON allows integers only")
	case string:
		canonStr(b, x)
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			canonStr(b, s)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []Output:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, map[string]any(e)); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case Output:
		return canon(b, map[string]any(x))
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			for i := 0; i < len(k); i++ {
				if k[i] > 0x7f {
					return errors.New("canonical JSON object keys must be ASCII")
				}
			}
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte-wise
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			canonStr(b, k)
			b.WriteByte(':')
			if err := canon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON cannot encode %T", v)
	}
	return nil
}
