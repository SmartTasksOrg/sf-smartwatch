package smartwatch

import (
	"container/heap"
	"math"
	"sort"
)

// The SmartWatch engine (spec/SEMANTICS.md section 6): count messages between agents per window,
// compute coupling density, grade it and decide when a reset is due. Deterministic: no clock, no
// randomness. An Engine is not safe for concurrent use.

const (
	// Buckets is the number of bucket counters a window allocates when it goes over the exact pair limit.
	Buckets   = 1 << 20
	micro     = 1000000
	maxAgents = 100000000
)

// Output is one engine output: {"kind": "window" | "level" | "reset", ...}, with int64, string, bool,
// nil and []any values (the shape of SEMANTICS.md section 6).
type Output map[string]any

// CheckEvent checks an event (spec/SEMANTICS.md section 2).
func CheckEvent(src, dst string, tsMs, count int64) error {
	if !ValidID(src) || !ValidID(dst) {
		return eventErr("src and dst must match [A-Za-z0-9._:@/-]{1,128}")
	}
	if tsMs < 0 || tsMs > MaxInt {
		return eventErr("ts_ms must be an integer from 0 to 2^53 - 1")
	}
	if count < 1 || count > 1000000000 {
		return eventErr("count must be an integer from 1 to 10^9")
	}
	return nil
}

// DensityMicro is min(2^53 - 1, floor((double(messages) × 1e9) / (double(possible_pairs) × double(window_ms)))),
// 0 without possible pairs.
func DensityMicro(messages, possiblePairs, windowMs int64) int64 {
	if possiblePairs <= 0 {
		return 0
	}
	f := math.Floor((float64(messages) * 1e9) / (float64(possiblePairs) * float64(windowMs)))
	if f >= float64(MaxInt) {
		return MaxInt
	}
	return int64(f)
}

func sat(a, b int64) int64 {
	if a+b > MaxInt {
		return MaxInt
	}
	return a + b
}

type pairKey struct{ a, b string }

type cand struct {
	key pairKey
	est int64
}

func candLess(x, y cand) bool {
	if x.est != y.est {
		return x.est < y.est
	}
	if x.key.a != y.key.a {
		return x.key.a < y.key.a
	}
	return x.key.b < y.key.b
}

type candHeap []cand

func (h candHeap) Len() int           { return len(h) }
func (h candHeap) Less(i, j int) bool { return candLess(h[i], h[j]) }
func (h candHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *candHeap) Push(x any)        { *h = append(*h, x.(cand)) }
func (h *candHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

type window struct {
	pairs        map[pairKey]int64
	agents       map[string]struct{}
	total        int64
	selfMessages int64
	buckets      []int64
	cand         map[pairKey]int64
	heap         candHeap // candidate entries; entries whose estimate is no longer current are stale
	hllPairs     *HyperLogLog
	hllAgents    *HyperLogLog
	pairsOver    bool
	agentsOver   bool
}

func newWindow() *window {
	return &window{pairs: map[pairKey]int64{}, agents: map[string]struct{}{}, cand: map[pairKey]int64{}}
}

// Stats are the engine's counters.
type Stats struct {
	Events, Messages, LateDropped, SkippedWindows, Windows int64
}

// Engine is the deterministic SmartWatch engine.
type Engine struct {
	p           *Policy
	resetIdx    int
	acc         map[int64]*window
	started     bool
	nextEmit    int64
	high        int64
	empties     int64
	level       int
	streakStart int64
	hasStreak   bool
	triggered   bool
	lastTrigger int64
	hasTrigger  bool
	stats       Stats
}

// NewEngine returns an engine for a validated policy.
func NewEngine(p *Policy) *Engine {
	return &Engine{p: p, resetIdx: p.LevelIndex(p.Reset.Level), acc: map[int64]*window{}, level: -1}
}

// Add counts count messages from src to dst at tsMs and returns the outputs of the windows it closes.
func (e *Engine) Add(src, dst string, tsMs, count int64) ([]Output, error) {
	if err := CheckEvent(src, dst, tsMs, count); err != nil {
		return nil, err
	}
	w := tsMs / e.p.WindowMs
	if !e.started {
		e.started = true
		e.nextEmit, e.high = w, w
	}
	if w < e.nextEmit {
		e.stats.LateDropped = sat(e.stats.LateDropped, count)
		return []Output{}, nil
	}
	e.stats.Events = sat(e.stats.Events, 1)
	e.stats.Messages = sat(e.stats.Messages, count)
	acc := e.acc[w]
	if acc == nil {
		acc = newWindow()
		e.acc[w] = acc
	}
	e.count(acc, src, dst, count)
	if w > e.high {
		e.high = w
	}
	return e.close(), nil
}

// AddValue is Add for decoded JSON values (from DecodeJSON): anything but ASCII-id strings and
// integers in range is WATCH-BAD-EVENT.
func (e *Engine) AddValue(src, dst, tsMs, count any) ([]Output, error) {
	s, ok1 := src.(string)
	d, ok2 := dst.(string)
	if !ok1 || !ok2 || !ValidID(s) || !ValidID(d) {
		return nil, eventErr("src and dst must match [A-Za-z0-9._:@/-]{1,128}")
	}
	ts, ok := AsInt(tsMs, 0, MaxInt)
	if !ok {
		return nil, eventErr("ts_ms must be an integer from 0 to 2^53 - 1")
	}
	c, ok := AsInt(count, 1, 1000000000)
	if !ok {
		return nil, eventErr("count must be an integer from 1 to 10^9")
	}
	return e.Add(s, d, ts, c)
}

// Flush closes the windows that the clock (nowMs) says are complete.
func (e *Engine) Flush(nowMs int64) ([]Output, error) {
	if nowMs < 0 || nowMs > MaxInt {
		return nil, eventErr("now_ms must be an integer from 0 to 2^53 - 1")
	}
	if !e.started {
		return []Output{}, nil
	}
	if w := nowMs / e.p.WindowMs; w > e.high {
		e.high = w
	}
	return e.close(), nil
}

// FlushValue is Flush for a decoded JSON value.
func (e *Engine) FlushValue(nowMs any) ([]Output, error) {
	n, ok := AsInt(nowMs, 0, MaxInt)
	if !ok {
		return nil, eventErr("now_ms must be an integer from 0 to 2^53 - 1")
	}
	return e.Flush(n)
}

func (e *Engine) count(acc *window, src, dst string, count int64) {
	if src == dst {
		acc.selfMessages = sat(acc.selfMessages, count)
		return
	}
	acc.total = sat(acc.total, count)
	lim := e.p.Limits
	for _, a := range [2]string{src, dst} {
		if _, ok := acc.agents[a]; ok {
			continue
		}
		switch {
		case acc.agentsOver:
			acc.hllAgents.Add(a)
		case int64(len(acc.agents)) < lim.MaxAgentsExact:
			acc.agents[a] = struct{}{}
		default:
			acc.agentsOver = true
			acc.hllAgents = NewHyperLogLog(e.p.HashSeed)
			for x := range acc.agents {
				acc.hllAgents.Add(x)
			}
			acc.hllAgents.Add(a)
		}
	}
	key := pairKey{src, dst}
	if dst < src {
		key = pairKey{dst, src}
	}
	if c, ok := acc.pairs[key]; ok {
		acc.pairs[key] = sat(c, count)
		return
	}
	if !acc.pairsOver && int64(len(acc.pairs)) < lim.MaxPairsExact {
		acc.pairs[key] = count
		return
	}
	text := key.a + "\n" + key.b
	if !acc.pairsOver {
		acc.pairsOver = true
		acc.hllPairs = NewHyperLogLog(e.p.HashSeed)
		for k := range acc.pairs {
			acc.hllPairs.Add(k.a + "\n" + k.b)
		}
		acc.buckets = make([]int64, Buckets)
	}
	acc.hllPairs.Add(text)
	i := FNV1a32(e.p.HashSeed, text) % Buckets
	acc.buckets[i] = sat(acc.buckets[i], count)
	est := acc.buckets[i]
	_, in := acc.cand[key]
	if in || int64(len(acc.cand)) < lim.Candidates {
		acc.cand[key] = est
		heap.Push(&acc.heap, cand{key, est})
	} else {
		for {
			top := acc.heap[0]
			if v, ok := acc.cand[top.key]; ok && v == top.est {
				break
			}
			heap.Pop(&acc.heap)
		}
		low := acc.heap[0]
		mine := cand{key, est}
		if candLess(low, mine) {
			heap.Pop(&acc.heap)
			delete(acc.cand, low.key)
			acc.cand[key] = est
			heap.Push(&acc.heap, mine)
		}
	}
	if len(acc.heap) > 4*len(acc.cand)+64 {
		acc.heap = acc.heap[:0]
		for k, v := range acc.cand {
			acc.heap = append(acc.heap, cand{k, v})
		}
		heap.Init(&acc.heap)
	}
}

func (e *Engine) close() []Output {
	out := []Output{}
	late := e.p.LateWindows
	for e.nextEmit+late < e.high {
		w := e.nextEmit
		if acc, ok := e.acc[w]; ok {
			delete(e.acc, w)
			e.empties = 0
			out = append(out, e.emit(w, acc)...)
			e.nextEmit = w + 1
		} else if e.empties < e.p.MaxEmptyWindows {
			e.empties++
			out = append(out, e.emit(w, newWindow())...)
			e.nextEmit = w + 1
		} else {
			nxt := e.high - late
			for k := range e.acc {
				if k >= w && k < nxt {
					nxt = k
				}
			}
			e.stats.SkippedWindows += nxt - w
			e.nextEmit = nxt
			e.hasStreak, e.triggered = false, false
			if e.level != -1 {
				out = append(out, Output{"kind": "level", "window": w, "from": e.name(e.level), "to": "normal",
					"density_micro": int64(0)})
				e.level = -1
			}
		}
	}
	return out
}

type entry struct {
	count int64
	a, b  string
	exact bool
}

func (e *Engine) emit(w int64, acc *window) []Output {
	e.stats.Windows++
	var n int64
	if acc.agentsOver {
		n = acc.hllAgents.Estimate()
		if n > maxAgents {
			n = maxAgents
		}
	} else {
		n = int64(len(acc.agents))
	}
	possible := n * (n - 1) / 2
	var distinct int64
	if acc.pairsOver {
		distinct = acc.hllPairs.Estimate()
		if distinct > possible {
			distinct = possible
		}
	} else {
		distinct = int64(len(acc.pairs))
	}
	density := DensityMicro(acc.total, possible, e.p.WindowMs)
	var ratio int64
	if possible > 0 {
		ratio = int64(math.Floor(float64(distinct) * 1e6 / float64(possible)))
		if ratio > micro {
			ratio = micro
		}
	}
	entries := make([]entry, 0, len(acc.pairs)+len(acc.cand))
	for k, c := range acc.pairs {
		entries = append(entries, entry{c, k.a, k.b, true})
	}
	for k, c := range acc.cand {
		if _, ok := acc.pairs[k]; !ok {
			entries = append(entries, entry{c, k.a, k.b, false})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		x, y := entries[i], entries[j]
		if x.count != y.count {
			return x.count > y.count
		}
		if x.a != y.a {
			return x.a < y.a
		}
		return x.b < y.b
	})
	if int64(len(entries)) > e.p.Limits.TopK {
		entries = entries[:e.p.Limits.TopK]
	}
	top := make([]any, len(entries))
	for i, t := range entries {
		top[i] = map[string]any{"a": t.a, "b": t.b, "count": t.count, "exact": t.exact}
	}
	before := e.level
	e.level = e.grade(density, n)
	name := e.name(e.level)
	out := []Output{{"kind": "window", "window": w, "start_ms": w * e.p.WindowMs, "messages": acc.total,
		"self_messages": acc.selfMessages, "agents": n, "pairs": distinct, "possible_pairs": possible,
		"density_micro": density, "pair_ratio_micro": ratio, "exact": !(acc.pairsOver || acc.agentsOver),
		"level": name, "top": top}}
	if e.level != before {
		out = append(out, Output{"kind": "level", "window": w, "from": e.name(before), "to": name, "density_micro": density})
	}
	if r := e.resetDue(w, entries, density); r != nil {
		out = append(out, r)
	}
	return out
}

func (e *Engine) name(i int) string {
	if i < 0 {
		return "normal"
	}
	return e.p.Levels[i].Name
}

func (e *Engine) grade(density, agents int64) int {
	if agents < e.p.MinAgents {
		return -1
	}
	raw := -1
	for i, lv := range e.p.Levels {
		if density >= lv.MinDensityMicro {
			raw = i
		}
	}
	if raw >= e.level {
		return raw
	}
	h := e.p.HysteresisPermille
	for j := e.level; j > raw; j-- { // both products stay below 2^63
		if density*1000 >= e.p.Levels[j].MinDensityMicro*(1000-h) {
			return j
		}
	}
	return raw
}

func (e *Engine) resetDue(w int64, top []entry, density int64) Output {
	r := e.p.Reset
	if e.level < e.resetIdx {
		e.hasStreak, e.triggered = false, false
		return nil
	}
	if !e.hasStreak {
		e.hasStreak, e.streakStart = true, w
	}
	if r.Mode == "off" || e.triggered {
		return nil
	}
	if (w-e.streakStart+1)*e.p.WindowMs < r.SustainMs {
		return nil
	}
	if e.hasTrigger && (w-e.lastTrigger)*e.p.WindowMs < r.CooldownMs {
		return nil
	}
	e.triggered = true
	e.hasTrigger, e.lastTrigger = true, w
	agents := []any{}
	seen := map[string]bool{}
	for _, t := range top {
		if t.count < r.HotPairMinCount {
			break
		}
		for _, a := range [2]string{t.a, t.b} {
			if !seen[a] && int64(len(agents)) < r.MaxAgents {
				seen[a] = true
				agents = append(agents, a)
			}
		}
	}
	return Output{"kind": "reset", "window": w, "mode": r.Mode, "level": e.name(e.level), "density_micro": density,
		"sustained_ms": (w - e.streakStart + 1) * e.p.WindowMs, "agents": agents}
}

// Snapshot returns {level, next_window, open_windows, events, messages, late_dropped, skipped_windows, windows}.
func (e *Engine) Snapshot() Output {
	var next any
	if e.started {
		next = e.nextEmit
	}
	return Output{"level": e.name(e.level), "next_window": next, "open_windows": int64(len(e.acc)),
		"events": e.stats.Events, "messages": e.stats.Messages, "late_dropped": e.stats.LateDropped,
		"skipped_windows": e.stats.SkippedWindows, "windows": e.stats.Windows}
}

// Stats returns the counters.
func (e *Engine) Stats() Stats { return e.stats }
