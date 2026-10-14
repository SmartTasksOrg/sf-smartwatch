package smartwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// The agent side over HTTP (spec/PORTING.md items 9 and 10): a small JSON client, the Reporter and
// the CommandPoller. Redirects are never followed (they would carry the bearer token elsewhere); one
// connection per request.

const (
	maxResponse = 32 << 20
	batchSize   = 10000
)

// ClientError is a non-2xx answer from the monitor.
type ClientError struct {
	Status int
	Body   any
	Code   string
}

func (e *ClientError) Error() string {
	msg := fmt.Sprint(e.Body)
	if m, ok := e.Body.(map[string]any); ok {
		msg = fmt.Sprint(m["error"])
	}
	return fmt.Sprintf("HTTP %d: %.300s", e.Status, msg)
}

// Client is a JSON client for the monitor. It is safe for concurrent use.
type Client struct {
	URL   string
	Token string
	http  *http.Client
}

// NewClient returns a client for url (http:// or https://) with a per-request timeout.
func NewClient(rawURL, token string, timeout time.Duration) (*Client, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil, errors.New("the monitor URL must start with http:// or https://")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}
	hc := &http.Client{Timeout: timeout, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{URL: strings.TrimRight(rawURL, "/"), Token: token, http: hc}, nil
}

// QuoteID percent-encodes an id for one path segment as Python's quote(id, safe=""): everything but
// A-Z a-z 0-9 _ . - ~ becomes %XX ("/" becomes %2F).
func QuoteID(id string) string {
	var b strings.Builder
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Request sends one request. body (if not nil) is sent as JSON. The answer is decoded with
// DecodeJSON when it starts with { or [, else returned as a string. A non-2xx status is a *ClientError.
func (c *Client) Request(method, path string, body any) (any, error) {
	var rd io.Reader
	if method == "POST" {
		data := []byte{}
		if body != nil {
			var err error
			if data, err = json.Marshal(body); err != nil {
				return nil, err
			}
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.URL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxResponse {
		return nil, &ClientError{Status: res.StatusCode, Body: "answer larger than 32 MiB"}
	}
	var v any = string(raw)
	if len(raw) > 0 && (raw[0] == '{' || raw[0] == '[') {
		if d, err := DecodeJSON(raw); err == nil {
			v = d
		} else if res.StatusCode >= 200 && res.StatusCode < 300 {
			return nil, err
		}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		ce := &ClientError{Status: res.StatusCode, Body: v}
		if m, ok := v.(map[string]any); ok {
			ce.Code, _ = m["code"].(string)
		}
		return nil, ce
	}
	return v, nil
}

// Event is one event as sent to POST /v1/events.
type Event struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	TsMs  int64  `json:"ts_ms"`
	Count int64  `json:"count"`
}

// Events sends POST /v1/events.
func (c *Client) Events(events []Event) (any, error) {
	return c.Request("POST", "/v1/events", map[string]any{"events": events})
}

// Commands returns the pending commands of an agent.
func (c *Client) Commands(agentID string) ([]any, error) {
	v, err := c.Request("GET", "/v1/agents/"+QuoteID(agentID)+"/commands", nil)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("malformed commands answer")
	}
	cmds, ok := m["commands"].([]any)
	if !ok {
		return nil, errors.New("malformed commands answer")
	}
	return cmds, nil
}

// Ack acknowledges a reset.
func (c *Client) Ack(resetID, agentID string) error {
	body := map[string]any{}
	if agentID != "" {
		body["agent_id"] = agentID
	}
	_, err := c.Request("POST", "/v1/resets/"+QuoteID(resetID)+"/ack", body)
	return err
}

type repKey struct {
	src, dst string
	ts       int64
}

// Reporter adds up messages per (src, dst, second) in memory and sends them in the background every
// Interval ± Jitter. Record never blocks on the network. Safe for concurrent use.
type Reporter struct {
	Client   *Client
	Interval time.Duration
	Jitter   time.Duration
	MaxKeys  int
	BucketMs int64
	Clock    func() int64 // milliseconds since the epoch

	mu       sync.Mutex
	buf      map[repKey]int64
	sendMu   sync.Mutex
	stop     chan struct{}
	done     chan struct{}
	started  bool
	sent     int64
	dropped  int64
	rejected int64
	errs     int64
	lastErr  error
}

// NewReporter returns a reporter with the defaults (1 s ± 200 ms, 100,000 keys, 1 s buckets).
func NewReporter(c *Client) *Reporter {
	return &Reporter{Client: c, Interval: time.Second, Jitter: 200 * time.Millisecond, MaxKeys: 100000, BucketMs: 1000,
		Clock: func() int64 { return time.Now().UnixMilli() }, buf: map[repKey]int64{}}
}

// Record counts count messages from src to dst now.
func (r *Reporter) Record(src, dst string, count int64) error {
	return r.RecordAt(src, dst, count, r.Clock())
}

// RecordAt counts count messages from src to dst at tsMs.
func (r *Reporter) RecordAt(src, dst string, count, tsMs int64) error {
	if err := CheckEvent(src, dst, tsMs, count); err != nil {
		return err
	}
	r.mu.Lock()
	r.put(repKey{src, dst, tsMs - tsMs%r.BucketMs}, count)
	r.mu.Unlock()
	return nil
}

func (r *Reporter) put(k repKey, count int64) {
	if c, ok := r.buf[k]; ok {
		if c+count > 1000000000 {
			r.buf[k] = 1000000000
		} else {
			r.buf[k] = c + count
		}
	} else if len(r.buf) < r.MaxKeys {
		r.buf[k] = count
	} else {
		r.dropped += count
	}
}

// Flush sends everything recorded so far and returns the messages accepted.
func (r *Reporter) Flush() int64 {
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	r.mu.Lock()
	buf := r.buf
	r.buf = map[repKey]int64{}
	r.mu.Unlock()
	keys := make([]repKey, 0, len(buf))
	for k := range buf {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.ts != b.ts {
			return a.ts < b.ts
		}
		if a.src != b.src {
			return a.src < b.src
		}
		return a.dst < b.dst
	})
	var accepted int64
	for i := 0; i < len(keys); i += batchSize {
		part := keys[i:min(i+batchSize, len(keys))]
		evs := make([]Event, len(part))
		var sum int64
		for j, k := range part {
			evs[j] = Event{k.src, k.dst, k.ts, buf[k]}
			sum += buf[k]
		}
		res, err := r.Client.Events(evs)
		if err != nil {
			r.mu.Lock()
			r.lastErr = err
			var ce *ClientError
			if errors.As(err, &ce) && (ce.Status == 400 || ce.Status == 401 || ce.Status == 403 || ce.Status == 413) {
				r.rejected += sum
				r.mu.Unlock()
				continue
			}
			r.errs++
			for _, k := range keys[i:] {
				r.put(k, buf[k])
			}
			r.mu.Unlock()
			break
		}
		bad := map[int64]bool{}
		if m, ok := res.(map[string]any); ok {
			if rej, ok := m["rejected"].([]any); ok {
				for _, x := range rej {
					if o, ok := x.(map[string]any); ok {
						if idx, ok := AsInt(o["index"], 0, int64(len(evs)-1)); ok {
							bad[idx] = true
						}
					}
				}
			}
		}
		var nBad int64
		for j := range bad {
			nBad += evs[j].Count
		}
		r.mu.Lock()
		r.rejected += nBad
		r.sent += sum - nBad
		r.mu.Unlock()
		accepted += sum - nBad
	}
	return accepted
}

// Start runs the background loop.
func (r *Reporter) Start() *Reporter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return r
	}
	r.started = true
	r.stop, r.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(r.done)
		for {
			wait := r.Interval
			if r.Jitter > 0 {
				wait += time.Duration(rand.Int63n(int64(2*r.Jitter)+1)) - r.Jitter
			}
			select {
			case <-r.stop:
				return
			case <-time.After(wait):
				r.Flush()
			}
		}
	}()
	return r
}

// Close stops the loop and sends what is left; it returns the messages accepted by this last send.
func (r *Reporter) Close() int64 {
	r.mu.Lock()
	started := r.started
	if started {
		r.started = false
		close(r.stop)
	}
	r.mu.Unlock()
	if started {
		<-r.done
	}
	return r.Flush()
}

// ReporterStats are the reporter's counters.
type ReporterStats struct {
	Sent, Dropped, Rejected, Errors int64
	LastError                       error
}

// Stats returns the counters: messages accepted, dropped (key bound), rejected by the monitor, and
// failed sends.
func (r *Reporter) Stats() ReporterStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return ReporterStats{r.sent, r.dropped, r.rejected, r.errs, r.lastErr}
}

// Command is a reset command as received from the monitor.
type Command map[string]any

// CommandPoller pulls reset commands for one agent, runs OnReset and acknowledges each command once
// OnReset returned nil (a panic counts as an error). A command whose handler failed is not
// acknowledged and comes back on the next poll.
type CommandPoller struct {
	Client   *Client
	AgentID  string
	OnReset  func(Command) error
	OnError  func(error) // optional
	Interval time.Duration

	mu      sync.Mutex
	stop    chan struct{}
	done    chan struct{}
	started bool
}

// NewCommandPoller returns a poller with the given interval (1 s when 0).
func NewCommandPoller(c *Client, agentID string, onReset func(Command) error, interval time.Duration) *CommandPoller {
	if interval <= 0 {
		interval = time.Second
	}
	return &CommandPoller{Client: c, AgentID: agentID, OnReset: onReset, Interval: interval}
}

func (p *CommandPoller) handle(cmd Command) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("on_reset panicked: %v", x)
		}
	}()
	return p.OnReset(cmd)
}

func (p *CommandPoller) report(err error) {
	if p.OnError != nil && err != nil {
		p.OnError(err)
	}
}

// PollOnce fetches the commands once; it returns how many were handled and acknowledged.
func (p *CommandPoller) PollOnce() (int, error) {
	cmds, err := p.Client.Commands(p.AgentID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range cmds {
		m, ok := x.(map[string]any)
		if !ok || m["type"] != "reset" {
			continue
		}
		if err := p.handle(Command(m)); err != nil {
			p.report(err)
			continue
		}
		id, _ := m["reset_id"].(string)
		if err := p.Client.Ack(id, p.AgentID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Start polls every Interval in a goroutine until Stop.
func (p *CommandPoller) Start() *CommandPoller {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return p
	}
	p.started = true
	p.stop, p.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(p.done)
		for {
			select {
			case <-p.stop:
				return
			case <-time.After(p.Interval):
				if _, err := p.PollOnce(); err != nil {
					p.report(err)
				}
			}
		}
	}()
	return p
}

// Stop ends the loop and waits for it.
func (p *CommandPoller) Stop() {
	p.mu.Lock()
	started := p.started
	if started {
		p.started = false
		close(p.stop)
	}
	p.mu.Unlock()
	if started {
		<-p.done
	}
}
