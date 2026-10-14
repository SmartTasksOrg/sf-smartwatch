# SmartWatch for PHP

This is the PHP port of SmartWatch. It implements the engine of `spec/SEMANTICS.md` and the agent side of
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

It needs PHP 8.1 or newer with `ext-json`, and is tested here with PHP 8.3.6. It uses no Composer packages.
HTTP goes through PHP's built-in `http` stream wrapper, so curl is not needed.

It is not published on Packagist. Use it from a clone of this repository:
`require 'ports/php/src/SmartWatch.php';`. You can also add the clone as a Composer `path` repository
(`smarttasksorg/sf-smartwatch`).

## Layout

| Path | Contents |
|---|---|
| `src/SmartWatch.php` | everything, in namespace `SmartTasks\SmartWatch` |
| `bin/conformance.php` | the vector runner |
| `bin/interop.php` | the interop program for `ports/conformance/interop.py` |
| `composer.json` | package metadata (not published) |

## Vectors and interop

From the repository root:

```sh
php ports/php/bin/conformance.php spec/conformance   # last line: php: 1468/1468 vectors passed
ports/conformance/run.sh php                         # the same, through the shared harness
ports/conformance/interop.sh php                     # reporter and command poller against the Python monitor
```

## Using it

```php
require 'ports/php/src/SmartWatch.php';

use SmartTasks\SmartWatch\{Client, CommandPoller, Engine, Reporter, WatchError};
use function SmartTasks\SmartWatch\load_policy;

$eng = new Engine(load_policy('policy.json'));
$out = $eng->add('planner', 'coder', 1700000000123, 4);   // list of outputs, often empty
$out = $eng->flush((int) floor(microtime(true) * 1000));
$stats = $eng->snapshot();

$client = new Client('http://127.0.0.1:8730', getenv('SMARTWATCH_INGEST_TOKEN') ?: null);
$rep = new Reporter($client);
$poller = new CommandPoller($client, 'coder', fn (\stdClass $cmd) => restart_my_agent(), 1000);
while (working()) {
    do_one_step();
    $rep->record('planner', 'coder');   // in memory only
    $rep->tick();                       // sends when a send is due
    $poller->tick();                    // polls when a poll is due
}
$rep->close();                          // sends what is left
```

- Documents are decoded with `SmartTasks\SmartWatch\decode()`. JSON objects become `\stdClass`, so `{}` and
  `[]` stay distinct. Engine outputs are PHP arrays.
- An invalid event or policy throws `WatchError`. The code is in `$watchCode`, because `Exception::$code`
  is an integer in PHP.
- PHP has no background thread here. `Reporter::tick()` sends when 1 s, plus or minus up to 200 ms of jitter,
  has passed. `CommandPoller::tick()` polls every `$intervalMs`. You can also call `flush()` and `pollOnce()`
  yourself. `bin/interop.php` shows a loop that does both.
- A send holds at most 10,000 events, sorted by time, then src, then dst. A network error or a 5xx answer
  keeps the events for the next send.
- A 400, 401, 403 or 413 answer drops the events, and they are counted in `$rejected`. At most 100,000 keys
  are kept; later messages are counted in `$dropped`. `$sent` counts the messages the monitor accepted.
- A command is acknowledged only when the handler returns normally.
- Requests use HTTP/1.0, so each one opens a new connection. Redirects are not followed. Answers longer than
  32 MiB are refused.

## Implementation notes and limits

- PHP integers are signed 64-bit, and an overflowing product becomes a float.
  - FNV-1a 64 keeps its state in two 32-bit halves. Its prime is 2^40 + 0x1b3, so no product overflows.
  - mix64 multiplies in 16-bit limbs.
  - Right shifts are masked to make them logical.
  - The 64-bit hashes are the bit patterns in an `int`. `u64_string()` prints them unsigned.
- Agent ids that look like decimal integers, such as `"10"`, become integer keys in PHP arrays. The engine
  casts them back to strings and compares ids with `strcmp`, so the ordering stays byte-wise.
- The 2^20 bucket counters are a sparse array, holding only the buckets that were touched. A missing bucket
  counts as 0, which matches the specification.
- `Client` reads the status line from `$http_response_header`. This was tested with PHP 8.3 only.
