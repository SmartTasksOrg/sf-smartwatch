# SmartWatch for .NET

The SmartWatch engine and agent side in C#: canonical JSON, FNV-1a and mix64, the p = 14 HyperLogLog,
density, policy validation, calibration thresholds, the engine (add / flush / snapshot), audit chain
verification (`spec/SEMANTICS.md`), and a reporter and a command poller that talk to the Python monitor
over HTTP (`spec/PORTING.md`). The HTTP monitor itself stays in Python.

| Project | What it is |
|---|---|
| `SmartWatch` | the library (assembly `SfSmartWatch`, namespace `SmartWatch`), net8.0 |
| `Conformance` | runs the shared vectors in `spec/conformance` |
| `Interop` | the interop program used by `ports/conformance/interop.py` |

| File in `SmartWatch/` | What it is |
|---|---|
| `Json.cs` | JSON values (System.Text.Json reader), canonical JSON, SHA-256 helper |
| `Hashing.cs` | FNV-1a 32/64, mix64, pair bucket |
| `HyperLogLog.cs` | HyperLogLog, p = 14 |
| `Policy.cs` | policy validation (`WATCH-BAD-POLICY`), `Policy.DefaultJson` |
| `Engine.cs` | the engine, `DensityMicro`, event checks (`WATCH-BAD-EVENT`) |
| `Calibrate.cs` | percentile thresholds |
| `Audit.cs` | audit chain verification |
| `Client.cs` | HTTP client, `Reporter`, `CommandPoller` |

There are no package dependencies: `nuget.config` clears every package source, so a restore never pulls
code from a registry. It uses only the base class library (System.Text.Json to read JSON,
System.Security.Cryptography for SHA-256, HttpClient). It is not published on NuGet (`IsPackable` is
false); reference the project from a clone.

## Tests

    cd ports/csharp
    dotnet run -c Release --project Conformance -- ../../spec/conformance
    # csharp: 1472/1472 vectors passed

From the repository root, `ports/conformance/run.sh csharp` runs the vectors and
`ports/conformance/interop.sh csharp` runs the interop program against the Python monitor (messages
sent and counted, automatic resets received and acknowledged by every agent, a manual reset to
`team/tester`).

Tested with the .NET SDK 8.0.131 on Linux x86_64, with Python 3.13.16 running the monitor for the
interop test. The vectors run in about 0.3 s from a Release build (the 100,000-item HyperLogLog case
included). The engine was also compared with the Python reference on about 12,000 randomly generated
monitor steps with small exact limits (sketch mode, skipped windows, resets); that script is not part of
the repository.

## Usage

Reference the library from a clone:

```xml
<ProjectReference Include="../sf-smartwatch/ports/csharp/SmartWatch/SmartWatch.csproj" />
```

```csharp
using SmartWatch;

var eng = new Engine(Policy.Load("policy.json"));       // PolicyException (WATCH-BAD-POLICY)
foreach (var o in eng.Add("planner", "coder", tsMs, 1))   // EventException (WATCH-BAD-EVENT)
    Console.WriteLine(Json.Canonical(o));                 // {"kind": "window" | "level" | "reset", ...}
var closed = eng.Flush(nowMs);
var stats = eng.Snapshot();

using var client = new Client("https://watch.example:8730", Environment.GetEnvironmentVariable("SMARTWATCH_INGEST_TOKEN"));
using var rep = new Reporter(client);
rep.Start();                                              // sends every 1 s +- 200 ms
rep.Record("planner", "coder");                           // never blocks on the network
rep.Close();                                              // sends what is left; rep.Sent = messages accepted

var poller = new CommandPoller(client, "coder", cmd => RestartMyAgent(), TimeSpan.FromSeconds(1));
poller.Start();                                           // acknowledges each command whose handler did not throw
```

Engine outputs and the snapshot are JSON objects in the `Json` representation
(`SortedDictionary<string, object?>` with `long`, `bool`, `string`, `List<object?>` values).

## Limits

- `Engine` is not thread-safe; `Reporter`, `CommandPoller` and `Client` are.
- The client accepts http:// and https:// URLs (the interop test uses http:// only), never follows
  redirects and closes the connection after every request.
- Answers are streamed (`HttpCompletionOption.ResponseHeadersRead`) and read with a bound: a 2xx answer
  above 32 MiB is an error (refused from its Content-Length when it has one), and at most 64 KiB of an
  error answer is read. Checked by hand against a local server sending 400 MiB bodies (with and without
  Content-Length, status 200 and 400): the client stopped at the bound, with a peak working set of about
  105 MiB for the case without Content-Length. There is no test project in this port for that check.
- A 2xx answer to `POST /v1/events` that is not a JSON object is counted in `Errors` and its events are not resent (they may
  have been counted).
