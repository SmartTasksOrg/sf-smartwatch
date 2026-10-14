package smartwatch

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Error is a SmartWatch error with a stable code (WATCH-BAD-POLICY, WATCH-BAD-EVENT).
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func policyErr(format string, a ...any) error {
	return &Error{Code: "WATCH-BAD-POLICY", Msg: fmt.Sprintf(format, a...)}
}

func eventErr(msg string) error { return &Error{Code: "WATCH-BAD-EVENT", Msg: msg} }

// Level is one grading level.
type Level struct {
	Name            string
	MinDensityMicro int64
}

// ResetPolicy is the policy's reset object.
type ResetPolicy struct {
	Level            string
	SustainMs        int64
	Mode             string
	ConfirmTimeoutMs int64
	OnTimeout        string
	CooldownMs       int64
	MaxAgents        int64
	HotPairMinCount  int64
}

// Limits is the policy's limits object.
type Limits struct {
	MaxPairsExact  int64
	MaxAgentsExact int64
	TopK           int64
	Candidates     int64
}

// Policy is a validated policy document (spec/SEMANTICS.md section 3).
type Policy struct {
	Environment        string
	WindowMs           int64
	LateWindows        int64
	MaxEmptyWindows    int64
	MinAgents          int64
	Levels             []Level
	HysteresisPermille int64
	Reset              ResetPolicy
	Limits             Limits
	HashSeed           string
}

// DefaultPolicyJSON is the reference's default policy (its thresholds are placeholders: calibrate them).
const DefaultPolicyJSON = `{"schema":"smartwatch.policy/v1","environment":"default","window_ms":1000,"late_windows":2,
"max_empty_windows":10,"min_agents":3,"levels":[{"name":"elevated","min_density_micro":2000000},
{"name":"high","min_density_micro":5000000},{"name":"critical","min_density_micro":10000000}],
"hysteresis_permille":100,"reset":{"level":"critical","sustain_ms":5000,"mode":"confirm","confirm_timeout_ms":5000,
"on_timeout":"reset","cooldown_ms":60000,"max_agents":10,"hot_pair_min_count":1},
"limits":{"max_pairs_exact":100000,"max_agents_exact":50000,"top_k":10,"candidates":1024},"hash_seed":"default/smartwatch"}`

var (
	policyFields = []string{"schema", "environment", "window_ms", "late_windows", "max_empty_windows", "min_agents",
		"levels", "hysteresis_permille", "reset", "limits", "hash_seed"}
	resetFields = []string{"level", "sustain_ms", "mode", "confirm_timeout_ms", "on_timeout", "cooldown_ms",
		"max_agents", "hot_pair_min_count"}
	limitFields = []string{"max_pairs_exact", "max_agents_exact", "top_k", "candidates"}
	levelFields = []string{"name", "min_density_micro"}
)

// ValidID reports whether s matches [A-Za-z0-9._:@/-]{1,128}.
func ValidID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '@' || c == '/' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func validLevelName(s string) bool {
	if len(s) < 1 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func exactFields(v any, fields []string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(fields) {
		return nil, false
	}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			return nil, false
		}
	}
	return m, true
}

func sortedJoin(fields []string) string {
	s := append([]string(nil), fields...)
	sort.Strings(s)
	return strings.Join(s, ", ")
}

// ParsePolicy decodes and validates a policy document.
func ParsePolicy(data []byte) (*Policy, error) {
	v, err := DecodeJSON(data)
	if err != nil {
		return nil, policyErr("not JSON (%v)", err)
	}
	return ValidatePolicy(v)
}

// DefaultPolicy returns the validated default policy.
func DefaultPolicy() *Policy {
	p, err := ParsePolicy([]byte(DefaultPolicyJSON))
	if err != nil {
		panic(err)
	}
	return p
}

// ValidatePolicy checks a decoded policy document (from DecodeJSON) and returns it typed. Any
// violation is an *Error with code WATCH-BAD-POLICY.
func ValidatePolicy(doc any) (*Policy, error) {
	d, ok := exactFields(doc, policyFields)
	if !ok {
		return nil, policyErr("the policy must have exactly the fields %s", sortedJoin(policyFields))
	}
	p := &Policy{}
	if s, ok := d["schema"].(string); !ok || s != "smartwatch.policy/v1" {
		return nil, policyErr(`schema must be "smartwatch.policy/v1"`)
	}
	env, ok := d["environment"].(string)
	if !ok || !ValidID(env) {
		return nil, policyErr("environment must match [A-Za-z0-9._:@/-]{1,128}")
	}
	p.Environment = env
	for _, f := range []struct {
		k      string
		lo, hi int64
		dst    *int64
	}{{"window_ms", 100, 60000, &p.WindowMs}, {"late_windows", 0, 60, &p.LateWindows},
		{"max_empty_windows", 0, 3600, &p.MaxEmptyWindows}, {"min_agents", 2, 1000000, &p.MinAgents},
		{"hysteresis_permille", 0, 900, &p.HysteresisPermille}} {
		n, ok := AsInt(d[f.k], f.lo, f.hi)
		if !ok {
			return nil, policyErr("%s must be an integer from %d to %d", f.k, f.lo, f.hi)
		}
		*f.dst = n
	}
	lv, ok := d["levels"].([]any)
	if !ok || len(lv) < 1 || len(lv) > 8 {
		return nil, policyErr("levels must be a list of 1 to 8 levels")
	}
	names := map[string]bool{}
	var prev int64
	for _, x := range lv {
		m, ok := exactFields(x, levelFields)
		if !ok {
			return nil, policyErr(`each level must be {"name", "min_density_micro"}`)
		}
		name, ok := m["name"].(string)
		if !ok || !validLevelName(name) || name == "normal" || names[name] {
			return nil, policyErr(`level names must match [a-z][a-z0-9_-]{0,31}, be unique and not "normal"`)
		}
		t, ok := AsInt(m["min_density_micro"], 1, MaxInt)
		if !ok || t <= prev {
			return nil, policyErr("min_density_micro must be a positive integer, strictly increasing from level to level")
		}
		names[name] = true
		prev = t
		p.Levels = append(p.Levels, Level{Name: name, MinDensityMicro: t})
	}
	r, ok := exactFields(d["reset"], resetFields)
	if !ok {
		return nil, policyErr("reset must have exactly the fields %s", sortedJoin(resetFields))
	}
	if s, ok := r["level"].(string); !ok || !names[s] {
		return nil, policyErr("reset.level must be one of the level names")
	} else {
		p.Reset.Level = s
	}
	if s, ok := r["mode"].(string); !ok || (s != "auto" && s != "confirm" && s != "off") {
		return nil, policyErr("reset.mode must be auto, confirm or off")
	} else {
		p.Reset.Mode = s
	}
	if s, ok := r["on_timeout"].(string); !ok || (s != "reset" && s != "cancel") {
		return nil, policyErr("reset.on_timeout must be reset or cancel")
	} else {
		p.Reset.OnTimeout = s
	}
	for _, f := range []struct {
		k      string
		lo, hi int64
		dst    *int64
	}{{"sustain_ms", 0, 3600000, &p.Reset.SustainMs}, {"confirm_timeout_ms", 0, 3600000, &p.Reset.ConfirmTimeoutMs},
		{"cooldown_ms", 0, 86400000, &p.Reset.CooldownMs}, {"max_agents", 1, 1000, &p.Reset.MaxAgents},
		{"hot_pair_min_count", 1, 1000000000, &p.Reset.HotPairMinCount}} {
		n, ok := AsInt(r[f.k], f.lo, f.hi)
		if !ok {
			return nil, policyErr("reset.%s must be an integer from %d to %d", f.k, f.lo, f.hi)
		}
		*f.dst = n
	}
	li, ok := exactFields(d["limits"], limitFields)
	if !ok {
		return nil, policyErr("limits must have exactly the fields %s", sortedJoin(limitFields))
	}
	for _, f := range []struct {
		k      string
		lo, hi int64
		dst    *int64
	}{{"max_pairs_exact", 1, 10000000, &p.Limits.MaxPairsExact}, {"max_agents_exact", 1, 10000000, &p.Limits.MaxAgentsExact},
		{"top_k", 1, 100, &p.Limits.TopK}, {"candidates", 1, 65536, &p.Limits.Candidates}} {
		n, ok := AsInt(li[f.k], f.lo, f.hi)
		if !ok {
			return nil, policyErr("limits.%s must be an integer from %d to %d", f.k, f.lo, f.hi)
		}
		*f.dst = n
	}
	seed, ok := d["hash_seed"].(string)
	if !ok || len(seed) < 1 || len(seed) > 256 || !utf8.ValidString(seed) {
		return nil, policyErr("hash_seed must be a string of 1 to 256 UTF-8 bytes")
	}
	p.HashSeed = seed
	return p, nil
}

// LevelIndex returns the index of the named level, or -1.
func (p *Policy) LevelIndex(name string) int {
	for i, l := range p.Levels {
		if l.Name == name {
			return i
		}
	}
	return -1
}
