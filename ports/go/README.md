# SmartWatch for Go (engine and agent side)

This is the SmartWatch engine and agent side in Go. The engine is the deterministic part of
`spec/SEMANTICS.md`: it counts messages between agents per window, computes the coupling density,
grades it into levels and decides when a reset is due. The agent side is a reporter that sends message
counts to the Python monitor and a command poller that receives reset commands and acknowledges them.
The shared vectors in `spec/conformance` test the engine. The HTTP monitor itself (proposals, webhooks,
audit file, JWT) stays in the Python reference.

It uses only the Go standard library and has no dependencies. JSON is parsed with `encoding/json` and
`UseNumber`, so `2.5`, `1.0`, `true` and `"1"` are rejected where an integer is required. Canonical JSON
uses the port's own encoder, because `json.Marshal` escapes `<`, `>`, `&`, U+2028 and U+2029.

Module path: `github.com/SmartTasksOrg/sf-smartwatch/ports/go`, package `smartwatch`. It is not
published on any registry or module proxy. Use it from a clone, for example with a `replace` directive
that points at `ports/go`.

## Layout

| Path | What |
|---|---|
| `smartwatch/json.go` | `DecodeJSON`, `AsInt`, `Canonical`, `SHA256Hex` |
| `smartwatch/hashing.go` | `FNV1a32`, `FNV1a64`, `Mix64` |
| `smartwatch/hll.go` | `HyperLogLog` (p = 14) |
| `smartwatch/policy.go` | `ValidatePolicy`, `ParsePolicy`, `DefaultPolicy`, `Error` |
| `smartwatch/calibrate.go` | `Thresholds`, `Profiles` |
| `smartwatch/engine.go` | `Engine` (Add / Flush / Snapshot), `DensityMicro`, `CheckEvent` |
| `smartwatch/audit.go` | `VerifyAudit`, `RecordHash` |
| `smartwatch/client.go` | `Client`, `Reporter`, `CommandPoller` |
| `smartwatch/conformance.go` | `RunConformance`, shared by the runner and the tests |
| `smartwatch/smartwatch_test.go` | the vectors, plus the reporter and poller against a fake monitor |
| `cmd/conformance` | the vector runner |
| `cmd/interop` | the interop program for `ports/conformance/interop.py` |

## Conformance, tests and interop

```sh
cd ports/go
go vet ./... && go run ./cmd/conformance ../../spec/conformance   # last line: go: 1472/1472 vectors passed
go test ./...
cd ../..
ports/conformance/run.sh go
ports/conformance/interop.sh go   # builds /tmp/smartwatch-go-interop, runs it against the Python monitor
```

The interop test needs Python 3 and the Python reference installed (see the repository README).

## Using it

```go
import sw "github.com/SmartTasksOrg/sf-smartwatch/ports/go/smartwatch"

p, err := sw.ParsePolicy(policyJSON) // *sw.Error with Code "WATCH-BAD-POLICY"
eng := sw.NewEngine(p)
outs, err := eng.Add("planner", "coder", 1700000000123, 4) // []sw.Output; *sw.Error "WATCH-BAD-EVENT"
outs, err = eng.Flush(time.Now().UnixMilli())
snap := eng.Snapshot()

c, err := sw.NewClient("http://watch.example:8730", os.Getenv("SMARTWATCH_INGEST_TOKEN"), 5*time.Second)
rep := sw.NewReporter(c).Start()
rep.Record("planner", "coder", 1) // never blocks on the network
rep.Close()                       // stops the loop and sends what is left

poller := sw.NewCommandPoller(c, "coder", func(cmd sw.Command) error { return restartMyAgent() }, time.Second).Start()
defer poller.Stop()
```

- `Output` is a `map[string]any` with `int64`, `string`, `bool`, `nil` and `[]any` values, the shape of
  SEMANTICS.md section 6. `AddValue` and `FlushValue` take decoded JSON values.
- `Reporter` keeps one counter per (src, dst, second), sends every 1 s ± 200 ms, at most 10,000 events
  per request, and keeps at most 100,000 keys. A network error or any other failed answer keeps the
  events for the next send; 400, 401, 403 and 413 drop them. `Stats()` gives sent, dropped, rejected
  and failed sends. `Reporter` is safe for concurrent use; `Engine` is not.
- `CommandPoller` acknowledges a command when the handler returned nil. An error or a panic in the
  handler means no acknowledgement; the command comes back on the next poll.
- Each request uses its own connection (no keep-alive). Redirects are not followed. The proxy comes
  from the environment (`http.ProxyFromEnvironment`, which skips loopback addresses).

## What was tested

Go 1.24.7 on Linux x86-64 (the module declares `go 1.22`), with the Python reference on Python 3.13.16
for the interop test: the 1472 vectors, `go vet`, `go test`, `interop.sh go` (run repeatedly), and a
differential run of about 13,800 random engine steps (sketch mode, evictions, late events, silences,
resets) generated with the Python engine. The HyperLogLog's linear counting uses Go's `math.Log`, which
gave the same results as the reference on every vector.

## Limits

- Integers that do not fit in int64 are rejected wherever an integer is required (every allowed range
  fits). `Thresholds` takes `[]int64` and refuses a negative density; the runner turns a
  non-integer density in the vectors into `{ok: false}`.
- `encoding/json` replaces an invalid UTF-16 surrogate escape with U+FFFD, so a `hash_seed` with a lone
  surrogate is accepted here; the Python reference refuses it.
- A window over the exact pair limit allocates 2^20 counters (8 MiB).
