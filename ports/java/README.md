# SmartWatch for Java

This is the Java port of SmartWatch. It implements the engine of `spec/SEMANTICS.md` and the agent side of
`spec/PORTING.md`:

- canonical JSON and SHA-256
- seeded FNV-1a 32/64 and mix64
- HyperLogLog (p = 14)
- `density_micro`
- policy validation
- calibration thresholds
- the engine: `add`, `flush`, `snapshot`
- audit chain verification
- a reporter (`POST /v1/events`) and a command poller (`GET /v1/agents/{id}/commands`, then the acknowledgement)

The HTTP monitor itself (proposals, webhooks, the audit file, JWT) stays in Python.

It uses only the JDK and has no dependencies. It needs JDK 17 or newer and is tested here with OpenJDK 21.0.12.

It is not published to Maven Central or any other repository. Use it from a clone of this repository.

## Layout

| Path | Contents |
|---|---|
| `src/main/java/cloud/smarttasks/smartwatch/Json.java` | JSON parser and canonical writer |
| `.../Hashing.java` | FNV-1a 32/64, mix64, bucket, SHA-256 |
| `.../HyperLogLog.java` | HyperLogLog, p = 14 |
| `.../Policy.java` | policy validation (`WATCH-BAD-POLICY`) |
| `.../Engine.java` | the engine, `densityMicro`, `checkEvent` (`WATCH-BAD-EVENT`) |
| `.../Calibrate.java` | calibration thresholds |
| `.../Audit.java` | audit chain verification |
| `.../WatchError.java` | the exception with the `WATCH-*` code |
| `.../Client.java`, `Reporter.java`, `CommandPoller.java` | the agent side over HTTP |
| `.../Conformance.java`, `Interop.java` | the test programs |
| `build.sh` | builds into `build/classes` without Maven |
| `pom.xml` | the same build for Maven users (no dependencies) |

## Build, vectors and interop

From the repository root:

```sh
ports/java/build.sh
java -cp ports/java/build/classes cloud.smarttasks.smartwatch.Conformance spec/conformance
# last line: java: 1468/1468 vectors passed
ports/conformance/run.sh java        # the same, through the shared harness
ports/conformance/interop.sh java    # reporter and command poller against the Python monitor over HTTP
```

`build.sh` runs `javac -Xlint:all,-serial -Werror --release 17` into `ports/java/build/classes`. The `pom.xml`
(`mvn -q compile`, output in `target/`) is not used by this repository's checks and was not run here (no access to
Maven Central from the test machine).

## Using it

The engine:

```java
import cloud.smarttasks.smartwatch.*;
import java.nio.file.Path;

Engine eng = new Engine(Policy.load(Path.of("policy.json")));
List<Map<String, Object>> out = eng.add("planner", "coder", 1700000000123L, 4);   // often empty
out = eng.flush(System.currentTimeMillis());                                    // close windows by the clock
Map<String, Object> stats = eng.snapshot();
```

Outputs are `LinkedHashMap<String, Object>` with `Long`, `String`, `Boolean` and `List` values, with exactly
the fields of SEMANTICS.md section 6. An invalid event or policy throws `WatchError`; its `code` field holds
the `WATCH-*` code. The engine is not thread-safe. `addValues` and `flushValue` take parsed JSON values and
refuse anything that is not a JSON integer, such as `1.5` or `true`.

The agent side:

```java
Client client = new Client("http://127.0.0.1:8730", System.getenv("SMARTWATCH_INGEST_TOKEN"), Duration.ofSeconds(5));
Reporter rep = new Reporter(client).start();
rep.record("planner", "coder");          // never blocks on the network
CommandPoller poller = new CommandPoller(client, "coder", cmd -> restartMyAgent(), 1000).start();
...
rep.close();                             // stops the thread and sends what is left
poller.close();
```

- `Reporter` sends every 1 s, plus or minus up to 200 ms of random jitter, from a daemon thread. Each request
  holds at most 10,000 events, sorted by time, then src, then dst.
- A network error or a 5xx answer keeps the events for the next send. A 400, 401, 403 or 413 answer drops
  them, and they are counted in `rejected()`. At most 100,000 keys are kept; later messages are counted in
  `dropped()`. `sent()` counts the messages the monitor accepted.
- `CommandPoller` acknowledges a command only when the handler returns normally. A handler that throws gets
  the command again on the next poll.
- Each request opens a new connection, and redirects are not followed. Answers longer than 32 MiB are
  refused.
- Errors are reported on standard error.

## Limits

- `Math.log` is used for the HyperLogLog small-range correction. It agrees with the Python reference on every
  vector, and on the extra random traffic checked here, but the JDK allows it to differ from the correctly
  rounded result by one ulp.
- The JSON parser accepts at most 64 levels of nesting.
- The bucket array (2^20 `long`, 8 MiB) is allocated per window only when that window goes over
  `limits.max_pairs_exact`.
