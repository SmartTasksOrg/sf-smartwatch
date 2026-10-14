package smartwatch

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConformance(t *testing.T) {
	total, fails, err := RunConformance(filepath.Join("..", "..", "..", "spec", "conformance"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fails {
		t.Error(f)
	}
	if total != 1472 {
		t.Errorf("%d vectors, want 1472", total)
	}
}

func TestQuoteID(t *testing.T) {
	if got := QuoteID("team/tester:a@b c~"); got != "team%2Ftester%3Aa%40b%20c~" {
		t.Errorf("QuoteID: %s", got)
	}
}

// A fake monitor: answers 503 once, then 400 once, then 207 rejecting index 0.
func TestReporterRetryRefuseReject(t *testing.T) {
	var mu sync.Mutex
	n := 0
	var bodies []map[string][]Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Path != "/v1/events" {
			w.WriteHeader(401)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var b map[string][]Event
		_ = json.Unmarshal(raw, &b)
		bodies = append(bodies, b)
		n++
		switch n {
		case 1:
			w.WriteHeader(503)
		case 2:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"code":"WATCH-BAD-EVENT","error":"no"}`))
		default:
			w.WriteHeader(207)
			_, _ = w.Write([]byte(`{"accepted":1,"rejected":[{"index":0,"code":"WATCH-CLOCK-SKEW","error":"x"}]}`))
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok", time.Second)
	rep := NewReporter(c)
	_ = rep.RecordAt("b", "a", 2, 1500)
	_ = rep.RecordAt("a", "b", 3, 1999) // same second as 1500
	_ = rep.RecordAt("a", "b", 1, 500)
	if got := rep.Flush(); got != 0 { // 503: kept
		t.Fatalf("after 503: %d", got)
	}
	if got := rep.Flush(); got != 0 { // 400: dropped as refused
		t.Fatalf("after 400: %d", got)
	}
	st := rep.Stats()
	if st.Errors != 1 || st.Rejected != 6 || st.Sent != 0 {
		t.Fatalf("stats %+v", st)
	}
	want := []Event{{"a", "b", 0, 1}, {"a", "b", 1000, 3}, {"b", "a", 1000, 2}}
	for i, e := range bodies[1]["events"] {
		if e != want[i] {
			t.Errorf("event %d: %+v want %+v", i, e, want[i])
		}
	}
	_ = rep.RecordAt("a", "b", 4, 3000)
	_ = rep.RecordAt("a", "c", 5, 3000)
	if got := rep.Flush(); got != 5 {
		t.Fatalf("207: accepted %d, want 5", got)
	}
}

func TestCommandPoller(t *testing.T) {
	var mu sync.Mutex
	var acks []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.EscapedPath() == "/v1/agents/team%2Ftester/commands":
			_, _ = w.Write([]byte(`{"commands":[{"type":"reset","reset_id":"r1","reason":"","created_ms":1},` +
				`{"type":"reset","reset_id":"r2","reason":"","created_ms":2}]}`))
		case r.Method == "POST":
			raw, _ := io.ReadAll(r.Body)
			acks = append(acks, r.URL.Path+" "+string(raw))
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok", time.Second)
	p := NewCommandPoller(c, "team/tester", func(cmd Command) error {
		if cmd["reset_id"] == "r2" {
			panic("handler failed")
		}
		return nil
	}, 0)
	n, err := p.PollOnce()
	if err != nil || n != 1 {
		t.Fatalf("PollOnce: %d %v", n, err)
	}
	if len(acks) != 1 || acks[0] != `/v1/resets/r1/ack {"agent_id":"team/tester"}` {
		t.Fatalf("acks %v", acks)
	}
}
