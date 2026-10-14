package smartwatch

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// RunConformance runs the vectors in dir check for check as the Python runner
// (src/sf_smartwatch/conformance.py) does. It returns the number of checks and the failures.
func RunConformance(dir string) (int, []string, error) {
	total := 0
	var fails []string
	check := func(name string, got, want any) {
		total++
		g, err1 := Canonical(got)
		w, err2 := Canonical(want)
		if err1 != nil || err2 != nil || !bytes.Equal(g, w) {
			fails = append(fails, fmt.Sprintf("%s: got %.300s, want %.300s", name, show(got), show(want)))
		}
	}
	load := func(name string) ([]any, error) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		v, err := DecodeJSON(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: not an object", name)
		}
		cases, ok := m["cases"].([]any)
		if !ok {
			return nil, fmt.Errorf("%s: no cases", name)
		}
		return cases, nil
	}
	pick := func(c map[string]any, keys ...string) map[string]any {
		out := map[string]any{}
		for _, k := range keys {
			if v, ok := c[k]; ok {
				out[k] = v
			}
		}
		return out
	}
	str := func(v any) string { s, _ := v.(string); return s }
	num := func(v any) int64 { n, _ := AsInt(v, -1<<63, 1<<63-1); return n }

	cases, err := load("canonical.json")
	if err != nil {
		return 0, nil, err
	}
	for _, x := range cases {
		c := x.(map[string]any)
		var got any
		if t, err := Canonical(c["input"]); err != nil {
			got = "error: " + err.Error()
		} else {
			got = []any{string(t), SHA256Hex(t)}
		}
		check("canonical/"+str(c["name"]), got, []any{c["canonical"], c["sha256"]})
	}

	if cases, err = load("hashing.json"); err != nil {
		return 0, nil, err
	}
	for i, x := range cases {
		c := x.(map[string]any)
		seed, text := str(c["seed"]), str(c["text"])
		h64 := FNV1a64(seed, text)
		h32 := FNV1a32(seed, text)
		got := map[string]any{"fnv1a32": int64(h32), "fnv1a64": strconv.FormatUint(h64, 10),
			"mix64": strconv.FormatUint(Mix64(h64), 10), "bucket": int64(h32 % (1 << 20))}
		check(fmt.Sprintf("hashing/%d", i), got, pick(c, "fnv1a32", "fnv1a64", "mix64", "bucket"))
	}

	if cases, err = load("hll.json"); err != nil {
		return 0, nil, err
	}
	for _, x := range cases {
		c := x.(map[string]any)
		h := NewHyperLogLog(str(c["seed"]))
		switch it := c["items"].(type) {
		case []any:
			for _, s := range it {
				h.Add(str(s))
			}
		case map[string]any:
			prefix := str(it["prefix"])
			for i := num(it["from"]); i < num(it["to"]); i++ {
				h.Add(prefix + strconv.FormatInt(i, 10))
			}
		}
		check("hll/"+str(c["name"]), map[string]any{"estimate": h.Estimate(), "digest": h.Digest()},
			map[string]any{"estimate": c["estimate"], "digest": c["digest"]})
	}

	if cases, err = load("density.json"); err != nil {
		return 0, nil, err
	}
	for i, x := range cases {
		c := x.(map[string]any)
		check(fmt.Sprintf("density/%d", i), DensityMicro(num(c["messages"]), num(c["possible_pairs"]), num(c["window_ms"])),
			c["density_micro"])
	}

	if cases, err = load("policies.json"); err != nil {
		return 0, nil, err
	}
	for _, x := range cases {
		c := x.(map[string]any)
		got := map[string]any{"ok": true}
		if _, err := ValidatePolicy(c["policy"]); err != nil {
			got = map[string]any{"ok": false, "code": codeOf(err)}
		}
		check("policies/"+str(c["name"]), got, pick(c, "ok", "code"))
	}

	if cases, err = load("calibration.json"); err != nil {
		return 0, nil, err
	}
	for _, x := range cases {
		c := x.(map[string]any)
		got := map[string]any{"ok": false}
		ds, ok1 := intList(c["densities"])
		ps, ok2 := intList(c["permille"])
		if ok1 && ok2 {
			if th, err := Thresholds(ds, ps); err == nil {
				t := make([]any, len(th))
				for i, v := range th {
					t[i] = v
				}
				got = map[string]any{"ok": true, "thresholds": t}
			}
		}
		check("calibration/"+str(c["name"]), got, pick(c, "ok", "thresholds"))
	}

	if cases, err = load("monitor.json"); err != nil {
		return 0, nil, err
	}
	for _, x := range cases {
		c := x.(map[string]any)
		p, err := ValidatePolicy(c["policy"])
		if err != nil {
			return 0, nil, fmt.Errorf("monitor/%s: %v", str(c["name"]), err)
		}
		eng := NewEngine(p)
		for i, y := range c["steps"].([]any) {
			st := y.(map[string]any)
			op := str(st["op"])
			var got any
			var outs []Output
			var err error
			switch op {
			case "add":
				outs, err = eng.AddValue(st["src"], st["dst"], st["ts_ms"], st["count"])
			case "flush":
				outs, err = eng.FlushValue(st["now_ms"])
			default:
				got = eng.Snapshot()
			}
			if op == "add" || op == "flush" {
				if err != nil {
					got = map[string]any{"ok": false, "code": codeOf(err)}
				} else {
					got = map[string]any{"ok": true, "outputs": outs}
				}
			}
			check(fmt.Sprintf("monitor/%s step %d (%s)", str(c["name"]), i, op), got, st["expect"])
		}
	}

	if cases, err = load("audit.json"); err != nil {
		return 0, nil, err
	}
	for _, x := range cases {
		c := x.(map[string]any)
		recs, _ := c["records"].([]any)
		ok, idx, _ := VerifyAudit(recs)
		var index any
		if !ok {
			index = int64(idx)
		}
		check("audit/"+str(c["name"]), map[string]any{"ok": ok, "index": index}, c["result"])
	}
	return total, fails, nil
}

func codeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "error: " + err.Error()
}

func intList(v any) ([]int64, bool) {
	xs, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]int64, len(xs))
	for i, x := range xs {
		n, ok := AsInt(x, -1<<63, 1<<63-1)
		if !ok {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func show(v any) string {
	c, err := Canonical(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(c)
}
