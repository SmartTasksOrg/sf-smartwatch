# SmartWatch for Rust

The SmartWatch engine and agent side in Rust: canonical JSON, FNV-1a and mix64, the p = 14 HyperLogLog,
density, policy validation, calibration thresholds, the engine (add / flush / snapshot), audit chain
verification (`spec/SEMANTICS.md`), and a reporter and a command poller that talk to the Python monitor
over HTTP (`spec/PORTING.md`). The HTTP monitor itself stays in Python.

The crate (`sf-smartwatch`, library name `smartwatch`) has no dependencies (empty `[dependencies]`) and
builds with `--offline`. It is not published on crates.io (`publish = false`); use it from a clone.

| Path | What it is |
|---|---|
| `src/json.rs` | JSON reader and canonical JSON writer |
| `src/sha256.rs` | SHA-256 (own implementation; the standard library has none) |
| `src/hashing.rs` | FNV-1a 32/64, mix64, pair bucket |
| `src/hll.rs` | HyperLogLog, p = 14 |
| `src/policy.rs` | policy validation (`WATCH-BAD-POLICY`), `DEFAULT_POLICY` |
| `src/engine.rs` | the engine, `density_micro`, event checks (`WATCH-BAD-EVENT`) |
| `src/calibrate.rs` | percentile thresholds |
| `src/audit.rs` | audit chain verification |
| `src/client.rs` | HTTP client, `Reporter`, `CommandPoller` |
| `src/bin/conformance.rs` | runs the shared vectors |
| `src/bin/interop.rs` | the interop program for `ports/conformance/interop.py` |

## Tests

    cd ports/rust
    cargo test --offline
    cargo run --quiet --offline --release --bin conformance ../../spec/conformance
    # rust: 1472/1472 vectors passed

From the repository root, `ports/conformance/run.sh rust` runs the vectors and
`ports/conformance/interop.sh rust` runs the interop program against the Python monitor (messages sent
and counted, automatic resets received and acknowledged by every agent, a manual reset to `team/tester`).

Tested with rustc and cargo 1.97.0 on Linux x86_64, with Python 3.13.16 running the monitor for the
interop test. The vectors run in well under a second in a release build (the 100,000-item HyperLogLog
case included). The engine was also compared with the Python reference on about 12,000 randomly
generated monitor steps with small exact limits (sketch mode, skipped windows, resets); that script is
not part of the repository.

## Usage

Add the crate from a clone as a path dependency:

    [dependencies]
    sf-smartwatch = { path = "../sf-smartwatch/ports/rust" }

```rust
use smartwatch::{Engine, Policy};

let mut eng = Engine::new(Policy::load("policy.json")?);
for out in eng.add("planner", "coder", ts_ms, 1)? {       // Err(EventError) for a bad event
    println!("{}", smartwatch::json::canonical(&out.to_value()).unwrap());
}
let closed = eng.flush(now_ms)?;
let stats = eng.snapshot();
```

Agent side:

```rust
use smartwatch::client::{Client, CommandPoller, Reporter};
use std::time::Duration;

let token = std::env::var("SMARTWATCH_INGEST_TOKEN").ok();
let rep = Reporter::new("http://10.0.0.5:8730", token.as_deref())?;
rep.start();                                    // sends every 1 s +- 200 ms
rep.record("planner", "coder", 1)?;             // never blocks on the network
rep.close();                                    // sends what is left; rep.sent() = messages accepted

let client = Client::new("http://10.0.0.5:8730", token.as_deref())?;
let poller = CommandPoller::new(client, "coder", Duration::from_secs(1),
    Box::new(|cmd| { restart_my_agent(); Ok(()) }));   // Ok acknowledges; Err or a panic does not
poller.start();
```

## Limits

- The HTTP client speaks **plain HTTP only** (HTTP/1.1 over `std::net::TcpStream`, one connection per
  request with `Connection: close`). There is no TLS: run it on a private network or next to a local
  TLS-terminating proxy; the bearer token travels in clear otherwise. Redirects are never followed.
- The JSON reader refuses unpaired UTF-16 surrogate escapes (`"\ud800"`), which Python's reader accepts;
  integers outside the i64 range are read as floats (so they are not integers for the engine or the
  policy, which matches the 2^53 − 1 bounds).
- A 2xx answer to `POST /v1/events` that is not a JSON object is counted in `errors()` and its events are not
  resent (they may have been counted).
- The jitter of the reporter comes from a small non-cryptographic generator seeded from the clock.
