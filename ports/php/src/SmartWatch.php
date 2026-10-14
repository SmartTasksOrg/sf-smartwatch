<?php
// SmartWatch for PHP (spec/SEMANTICS.md, spec/PORTING.md): canonical JSON, seeded FNV-1a and mix64,
// HyperLogLog, density, policy validation, calibration, the engine, audit chain verification, and the agent
// side (a Reporter and a CommandPoller that talk to the Python monitor over HTTP).
//
// Documents are decoded with SmartTasks\SmartWatch\decode(): JSON objects become \stdClass (so {} and [] stay
// different), integers int, other numbers float. Engine outputs and other results are PHP arrays.
//
// PHP integers are signed 64-bit and an overflowing product becomes a float, so the 64-bit hashes multiply in
// 32-bit halves or 16-bit limbs and shift right with a mask (logical shifts).
declare(strict_types=1);

namespace SmartTasks\SmartWatch;

const MAX_INT = 9007199254740991; // 2^53 - 1
const MAX_COUNT = 1000000000;
const BUCKETS = 1048576;          // 2^20
const MICRO = 1000000;
const MAX_AGENTS = 100000000;
const M32 = 0xFFFFFFFF;
const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';
const ID_RE = '#\A[A-Za-z0-9._:@/-]{1,128}\z#';
const LEVEL_NAME_RE = '#\A[a-z][a-z0-9_-]{0,31}\z#';
const POLICY_FIELDS = ['schema', 'environment', 'window_ms', 'late_windows', 'max_empty_windows', 'min_agents', 'levels',
    'hysteresis_permille', 'reset', 'limits', 'hash_seed'];
const RESET_FIELDS = ['level', 'sustain_ms', 'mode', 'confirm_timeout_ms', 'on_timeout', 'cooldown_ms', 'max_agents',
    'hot_pair_min_count'];
const LIMIT_FIELDS = ['max_pairs_exact', 'max_agents_exact', 'top_k', 'candidates'];
const PROFILES = ['prod' => [950, 990, 999], 'staging' => [900, 950, 990]];

/** A refused input; $watchCode is the stable WATCH-* code (Exception::$code is an integer in PHP). */
final class WatchError extends \InvalidArgumentException {
    public function __construct(public readonly string $watchCode, string $message = '') {
        parent::__construct($message === '' ? $watchCode : "$watchCode: $message");
    }
}

// ------------------------------------------------------------------ JSON

/** Decode JSON keeping objects (\stdClass) distinct from lists. Throws \JsonException. */
function decode(string $json): mixed {
    return json_decode($json, false, 512, JSON_THROW_ON_ERROR);
}

/** True when $s is valid UTF-8 text (json_decode only produces such strings). */
function valid_text(string $s): bool { return preg_match('//u', $s) === 1; }

function canon_str(string $s): string {
    if (!valid_text($s)) throw new \InvalidArgumentException('canonical JSON strings must be valid UTF-8');
    static $map = null;
    if ($map === null) {
        $map = ['"' => '\\"', '\\' => '\\\\', "\x08" => '\\b', "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t'];
        for ($c = 0; $c < 0x20; $c++) if (!isset($map[chr($c)])) $map[chr($c)] = sprintf('\\u%04x', $c);
    }
    return '"' . strtr($s, $map) . '"';
}

/** Canonical JSON (SEMANTICS.md section 8). \stdClass and non-list arrays are objects. Floats, non-ASCII keys,
 *  strings that are not valid UTF-8 and other types throw \InvalidArgumentException. */
function canonical(mixed $v): string {
    if ($v === null) return 'null';
    if ($v === true) return 'true';
    if ($v === false) return 'false';
    if (is_int($v)) return (string) $v;
    if (is_string($v)) return canon_str($v);
    if (is_array($v) && array_is_list($v)) {
        return '[' . implode(',', array_map(__NAMESPACE__ . '\canonical', $v)) . ']';
    }
    if (is_array($v) || $v instanceof \stdClass) {
        $a = is_array($v) ? $v : get_object_vars($v);
        $pairs = [];
        foreach ($a as $k => $x) {
            $k = (string) $k;
            if (preg_match('/[^\x00-\x7f]/', $k)) throw new \InvalidArgumentException('object keys must be ASCII');
            $pairs[$k] = $x;
        }
        $keys = array_map('strval', array_keys($pairs));
        sort($keys, SORT_STRING);
        $parts = [];
        foreach ($keys as $k) $parts[] = canon_str($k) . ':' . canonical($pairs[$k]);
        return '{' . implode(',', $parts) . '}';
    }
    if (is_float($v)) throw new \InvalidArgumentException('canonical JSON allows integers only');
    throw new \InvalidArgumentException('canonical JSON cannot encode ' . get_debug_type($v));
}

function sha256_hex(string $bytes): string { return hash('sha256', $bytes); }

// ------------------------------------------------------------------ hashes

/** Logical right shift of a 64-bit pattern by 1 <= $n <= 63. */
function lsr(int $x, int $n): int { return ($x >> $n) & (PHP_INT_MAX >> ($n - 1)); }

/** FNV-1a 32 over UTF-8(seed) || 0x00 || UTF-8(text): 0 .. 2^32 - 1. */
function fnv1a32(string $seed, string $text): int {
    $h = 2166136261;
    $bytes = $seed . "\x00" . $text;
    $n = strlen($bytes);
    for ($i = 0; $i < $n; $i++) $h = (($h ^ ord($bytes[$i])) * 16777619) & M32;
    return $h;
}

/** FNV-1a 64 over the same bytes, as the 64-bit pattern in a (signed) PHP int. The prime is 2^40 + 0x1b3:
 *  the state is kept in two 32-bit halves so that no product overflows. */
function fnv1a64(string $seed, string $text): int {
    $hi = 0xcbf29ce4;
    $lo = 0x84222325;
    $bytes = $seed . "\x00" . $text;
    $n = strlen($bytes);
    for ($i = 0; $i < $n; $i++) {
        $lo ^= ord($bytes[$i]);
        $t = $lo * 0x1b3;
        $hi = ($hi * 0x1b3 + ($t >> 32) + ($lo << 8)) & M32;
        $lo = $t & M32;
    }
    return ($hi << 32) | $lo;
}

/** $a * $b mod 2^64 with $b given as four 16-bit limbs, least significant first. */
function mul64(int $a, array $b): int {
    $a0 = $a & 0xffff;
    $a1 = ($a >> 16) & 0xffff;
    $a2 = ($a >> 32) & 0xffff;
    $a3 = ($a >> 48) & 0xffff;
    [$b0, $b1, $b2, $b3] = $b;
    $r = $a0 * $b0;
    $r0 = $r & 0xffff;
    $r = ($r >> 16) + $a0 * $b1 + $a1 * $b0;
    $r1 = $r & 0xffff;
    $r = ($r >> 16) + $a0 * $b2 + $a1 * $b1 + $a2 * $b0;
    $r2 = $r & 0xffff;
    $r = ($r >> 16) + $a0 * $b3 + $a1 * $b2 + $a2 * $b1 + $a3 * $b0;
    return (($r & 0xffff) << 48) | ($r2 << 32) | ($r1 << 16) | $r0;
}

const MIX_C1 = [0x8ccd, 0xed55, 0xafd7, 0xff51]; // 0xFF51AFD7ED558CCD
const MIX_C2 = [0xec53, 0x1a85, 0xb9fe, 0xc4ce]; // 0xC4CEB9FE1A85EC53

/** MurmurHash3 fmix64 on a 64-bit pattern. */
function mix64(int $h): int {
    $h ^= lsr($h, 33);
    $h = mul64($h, MIX_C1);
    $h ^= lsr($h, 33);
    $h = mul64($h, MIX_C2);
    $h ^= lsr($h, 33);
    return $h;
}

/** The decimal text of a 64-bit pattern read as unsigned. */
function u64_string(int $h): string {
    if ($h >= 0) return (string) $h;
    $u = lsr($h, 1);                 // floor(value / 2), below 2^63
    $q = intdiv($u, 5);              // value = 10 q + r
    $r = 2 * ($u - 5 * $q) + ($h & 1);
    return $q . $r;
}

/** A pair's bucket: fnv1a32(seed, text) mod 2^20. */
function bucket(string $seed, string $text): int { return fnv1a32($seed, $text) & (BUCKETS - 1); }

// ------------------------------------------------------------------ HyperLogLog

/** HyperLogLog, p = 14 (SEMANTICS.md section 5). The registers are a 16,384-byte string. */
final class HyperLogLog {
    public const P = 14;
    public const M = 16384;
    public const MAXRHO = 51;
    private const W_MASK = (1 << 50) - 1;
    private string $reg;

    public function __construct(public readonly string $seed) { $this->reg = str_repeat("\x00", self::M); }

    public function add(string $item): void {
        $h = mix64(fnv1a64($this->seed, $item));
        $j = ($h >> 50) & 0x3fff;
        $w = $h & self::W_MASK;
        $rho = self::MAXRHO - ($w === 0 ? 0 : strlen(decbin($w)));
        if ($rho > ord($this->reg[$j])) $this->reg[$j] = chr($rho);
    }

    public function estimate(): int {
        $counts = count_chars($this->reg, 1);   // byte value => occurrences, only those present
        $z = 0.0;
        for ($v = self::MAXRHO; $v >= 0; $v--) {
            if (isset($counts[$v])) $z += $counts[$v] * (2.0 ** -$v);
        }
        $m = self::M;
        $alpha = 0.7213 / (1 + 1.079 / $m);
        $e = $alpha * $m * $m / $z;
        $zeros = $counts[0] ?? 0;
        if ($e <= 2.5 * $m && $zeros > 0) $e = $m * log($m / $zeros);
        $r = floor($e + 0.5);
        return $r >= MAX_INT ? MAX_INT : (int) $r;
    }

    /** Lower-case hex SHA-256 of the register bytes. */
    public function digest(): string { return sha256_hex($this->reg); }
}

// ------------------------------------------------------------------ density, policy, calibration

/** min(2^53 - 1, floor((double(messages) * 1e9) / (double(possible) * double(window_ms)))), 0 without pairs. */
function density_micro(int $messages, int $possiblePairs, int $windowMs): int {
    if ($possiblePairs <= 0) return 0;
    $d = floor(((float) $messages * 1e9) / ((float) $possiblePairs * (float) $windowMs));
    return $d >= MAX_INT ? MAX_INT : (int) $d;
}

/** min(2^53 - 1, a + b). */
function sat(int $a, int $b): int { return min(MAX_INT, $a + $b); }

function int_in(mixed $v, int $lo, int $hi): bool { return is_int($v) && $v >= $lo && $v <= $hi; }

function is_id(mixed $v): bool { return is_string($v) && preg_match(ID_RE, $v) === 1; }

/** True when $o is a JSON object with exactly these field names. */
function exactly(mixed $o, array $fields): bool {
    if (!($o instanceof \stdClass)) return false;
    $k = array_map('strval', array_keys(get_object_vars($o)));
    sort($k, SORT_STRING);
    sort($fields, SORT_STRING);
    return $k === $fields;
}

/** Check a policy document (decoded with decode()); returns it or throws WatchError('WATCH-BAD-POLICY'). */
function validate_policy(mixed $doc): \stdClass {
    $bad = fn (string $m) => new WatchError('WATCH-BAD-POLICY', $m);
    if (!exactly($doc, POLICY_FIELDS)) throw $bad('the policy must have exactly the fields ' . implode(', ', POLICY_FIELDS));
    if ($doc->schema !== 'smartwatch.policy/v1') throw $bad('schema must be "smartwatch.policy/v1"');
    if (!is_id($doc->environment)) throw $bad('environment must match [A-Za-z0-9._:@/-]{1,128}');
    foreach ([['window_ms', 100, 60000], ['late_windows', 0, 60], ['max_empty_windows', 0, 3600], ['min_agents', 2, 1000000],
                 ['hysteresis_permille', 0, 900]] as [$k, $lo, $hi]) {
        if (!int_in($doc->{$k}, $lo, $hi)) throw $bad("$k must be an integer from $lo to $hi");
    }
    $lv = $doc->levels;
    if (!is_array($lv) || count($lv) < 1 || count($lv) > 8) throw $bad('levels must be a list of 1 to 8 levels');
    $names = [];
    $prev = 0;
    foreach ($lv as $x) {
        if (!exactly($x, ['name', 'min_density_micro'])) throw $bad('each level must be {"name", "min_density_micro"}');
        if (!is_string($x->name) || preg_match(LEVEL_NAME_RE, $x->name) !== 1 || $x->name === 'normal' || isset($names[$x->name])) {
            throw $bad('level names must match [a-z][a-z0-9_-]{0,31}, be unique and not "normal"');
        }
        if (!int_in($x->min_density_micro, 1, MAX_INT) || $x->min_density_micro <= $prev) {
            throw $bad('min_density_micro must be a positive integer, strictly increasing from level to level');
        }
        $names[$x->name] = true;
        $prev = $x->min_density_micro;
    }
    $r = $doc->reset;
    if (!exactly($r, RESET_FIELDS)) throw $bad('reset must have exactly the fields ' . implode(', ', RESET_FIELDS));
    if (!is_string($r->level) || !isset($names[$r->level])) throw $bad('reset.level must be one of the level names');
    if (!in_array($r->mode, ['auto', 'confirm', 'off'], true)) throw $bad('reset.mode must be auto, confirm or off');
    if (!in_array($r->on_timeout, ['reset', 'cancel'], true)) throw $bad('reset.on_timeout must be reset or cancel');
    foreach ([['sustain_ms', 0, 3600000], ['confirm_timeout_ms', 0, 3600000], ['cooldown_ms', 0, 86400000], ['max_agents', 1, 1000],
                 ['hot_pair_min_count', 1, 1000000000]] as [$k, $lo, $hi]) {
        if (!int_in($r->{$k}, $lo, $hi)) throw $bad("reset.$k must be an integer from $lo to $hi");
    }
    $li = $doc->limits;
    if (!exactly($li, LIMIT_FIELDS)) throw $bad('limits must have exactly the fields ' . implode(', ', LIMIT_FIELDS));
    foreach ([['max_pairs_exact', 1, 10000000], ['max_agents_exact', 1, 10000000], ['top_k', 1, 100], ['candidates', 1, 65536]]
             as [$k, $lo, $hi]) {
        if (!int_in($li->{$k}, $lo, $hi)) throw $bad("limits.$k must be an integer from $lo to $hi");
    }
    $seed = $doc->hash_seed;
    if (!is_string($seed) || !valid_text($seed) || strlen($seed) < 1 || strlen($seed) > 256) {
        throw $bad('hash_seed must be a string of 1 to 256 bytes');
    }
    return $doc;
}

/** Read and validate a policy file (WatchError when invalid or not JSON). */
function load_policy(string $path): \stdClass {
    $text = @file_get_contents($path);
    if ($text === false) throw new \RuntimeException("cannot read $path");
    try {
        $doc = decode($text);
    } catch (\JsonException $e) {
        throw new WatchError('WATCH-BAD-POLICY', "$path: not JSON ({$e->getMessage()})");
    }
    return validate_policy($doc);
}

/** Calibration thresholds (SEMANTICS.md section 7). \InvalidArgumentException when densities is empty, a density
 *  is not an integer >= 0, or a percentile is not an integer from 1 to 1000. */
function thresholds(array $densities, array $permille): array {
    foreach ($densities as $d) if (!is_int($d) || $d < 0) throw new \InvalidArgumentException('densities are integers >= 0');
    $xs = array_values($densities);
    if (!$xs) throw new \InvalidArgumentException('no densities to calibrate from');
    sort($xs, SORT_NUMERIC);
    $n = count($xs);
    $out = [];
    $prev = 0;
    foreach ($permille as $p) {
        if (!int_in($p, 1, 1000)) throw new \InvalidArgumentException('percentiles are integers from 1 to 1000 (permille)');
        $rank = intdiv($p * $n + 999, 1000);
        $v = $xs[max($rank, 1) - 1];
        $v = max($v, $prev + 1, 1);
        $out[] = $v;
        $prev = $v;
    }
    return $out;
}

// ------------------------------------------------------------------ engine

/** Candidates ordered by (estimate, pair text) ascending; "a\nb" orders as (a, b) since "\n" is below every id
 *  byte. Entries are [estimate, text]; stale ones are skipped by the engine (as the Python reference does). */
final class CandHeap extends \SplHeap {
    protected function compare(mixed $x, mixed $y): int {
        // SplHeap keeps the greatest on top: invert to keep the smallest
        if ($x[0] !== $y[0]) return $x[0] < $y[0] ? 1 : -1;
        return -strcmp($x[1], $y[1]) <=> 0;
    }
}

/** One open window. */
final class Window {
    /** @var array<string,int> pair text "a\nb" => exact count */
    public array $pairs = [];
    /** @var array<string,true> agent id => true (keys may come back as int: cast with (string)) */
    public array $agents = [];
    public int $total = 0;
    public int $selfMessages = 0;
    /** @var ?array<int,int> bucket counters, sparse (a missing bucket is 0) */
    public ?array $buckets = null;
    /** @var array<string,int> pair text => bucket estimate */
    public array $cand = [];
    public ?CandHeap $heap = null;
    public ?HyperLogLog $hllPairs = null;
    public ?HyperLogLog $hllAgents = null;
    public bool $pairsOver = false;
    public bool $agentsOver = false;
}

/** Check an event (SEMANTICS.md section 2); throws WatchError('WATCH-BAD-EVENT'). */
function check_event(mixed $src, mixed $dst, mixed $tsMs, mixed $count): void {
    if (!is_id($src) || !is_id($dst)) throw new WatchError('WATCH-BAD-EVENT', 'src and dst must match [A-Za-z0-9._:@/-]{1,128}');
    if (!int_in($tsMs, 0, MAX_INT)) throw new WatchError('WATCH-BAD-EVENT', 'ts_ms must be an integer from 0 to 2^53 - 1');
    if (!int_in($count, 1, MAX_COUNT)) throw new WatchError('WATCH-BAD-EVENT', 'count must be an integer from 1 to 10^9');
}

/**
 * The SmartWatch engine (SEMANTICS.md section 6). Deterministic: time comes from the events and from flush().
 * add() and flush() return the outputs (arrays) of the windows they closed.
 */
final class Engine {
    public readonly \stdClass $policy;
    private int $windowMs;
    private int $late;
    private int $maxEmpty;
    private string $seed;
    /** @var list<array{0:string,1:int}> */
    private array $levels = [];
    private int $resetIdx;
    /** @var array<int,Window> */
    private array $acc = [];
    private ?int $nextEmit = null;
    private int $high = 0;
    private int $empties = 0;
    private int $level = -1;
    private ?int $streakStart = null;
    private bool $triggered = false;
    private ?int $lastTrigger = null;
    private int $events = 0;
    private int $messages = 0;
    private int $lateDropped = 0;
    private int $skippedWindows = 0;
    private int $windows = 0;

    public function __construct(mixed $policy) {
        $this->policy = validate_policy($policy);
        $p = $this->policy;
        $this->windowMs = $p->window_ms;
        $this->late = $p->late_windows;
        $this->maxEmpty = $p->max_empty_windows;
        $this->seed = $p->hash_seed;
        foreach ($p->levels as $i => $lv) {
            $this->levels[] = [$lv->name, $lv->min_density_micro];
            if ($lv->name === $p->reset->level) $this->resetIdx = $i;
        }
    }

    public function add(mixed $src, mixed $dst, mixed $tsMs, mixed $count = 1): array {
        check_event($src, $dst, $tsMs, $count);
        $w = intdiv($tsMs, $this->windowMs);
        if ($this->nextEmit === null) {
            $this->nextEmit = $w;
            $this->high = $w;
        }
        if ($w < $this->nextEmit) {
            $this->lateDropped = sat($this->lateDropped, $count);
            return [];
        }
        $this->events = sat($this->events, 1);
        $this->messages = sat($this->messages, $count);
        $acc = $this->acc[$w] ??= new Window();
        $this->count($acc, $src, $dst, $count);
        if ($w > $this->high) $this->high = $w;
        return $this->close();
    }

    public function flush(mixed $nowMs): array {
        if (!int_in($nowMs, 0, MAX_INT)) throw new WatchError('WATCH-BAD-EVENT', 'now_ms must be an integer from 0 to 2^53 - 1');
        if ($this->nextEmit === null) return [];
        $w = intdiv($nowMs, $this->windowMs);
        if ($w > $this->high) $this->high = $w;
        return $this->close();
    }

    private function count(Window $a, string $src, string $dst, int $count): void {
        if ($src === $dst) {
            $a->selfMessages = sat($a->selfMessages, $count);
            return;
        }
        $a->total = sat($a->total, $count);
        $lim = $this->policy->limits;
        foreach ([$src, $dst] as $x) {
            if (isset($a->agents[$x])) continue;
            if ($a->agentsOver) {
                $a->hllAgents->add($x);
            } elseif (count($a->agents) < $lim->max_agents_exact) {
                $a->agents[$x] = true;
            } else {
                $a->agentsOver = true;
                $a->hllAgents = new HyperLogLog($this->seed);
                foreach ($a->agents as $y => $_) $a->hllAgents->add((string) $y);
                $a->hllAgents->add($x);
            }
        }
        $key = strcmp($src, $dst) < 0 ? "$src\n$dst" : "$dst\n$src";
        if (isset($a->pairs[$key])) {
            $a->pairs[$key] = sat($a->pairs[$key], $count);
            return;
        }
        if (!$a->pairsOver && count($a->pairs) < $lim->max_pairs_exact) {
            $a->pairs[$key] = $count;
            return;
        }
        if (!$a->pairsOver) {
            $a->pairsOver = true;
            $a->hllPairs = new HyperLogLog($this->seed);
            foreach ($a->pairs as $k => $_) $a->hllPairs->add((string) $k);
            $a->buckets = [];
            $a->heap = new CandHeap();
        }
        $a->hllPairs->add($key);
        $i = bucket($this->seed, $key);
        $est = sat($a->buckets[$i] ?? 0, $count);
        $a->buckets[$i] = $est;
        $cand = &$a->cand;
        if (isset($cand[$key]) || count($cand) < $lim->candidates) {
            $cand[$key] = $est;
            $a->heap->insert([$est, $key]);
        } else {
            $heap = $a->heap;
            while (true) {
                [$lowEst, $lowKey] = $heap->top();
                if (isset($cand[$lowKey]) && $cand[$lowKey] === $lowEst) break;
                $heap->extract();
            }
            if ($est > $lowEst || ($est === $lowEst && strcmp($key, $lowKey) > 0)) {
                $heap->extract();
                unset($cand[$lowKey]);
                $cand[$key] = $est;
                $heap->insert([$est, $key]);
            }
        }
        if (count($a->heap) > 4 * count($cand) + 64) {
            $a->heap = new CandHeap();
            foreach ($cand as $k => $v) $a->heap->insert([$v, (string) $k]);
        }
    }

    private function close(): array {
        $out = [];
        while ($this->nextEmit + $this->late < $this->high) {
            $w = $this->nextEmit;
            if (isset($this->acc[$w])) {
                $a = $this->acc[$w];
                unset($this->acc[$w]);
                $this->empties = 0;
                array_push($out, ...$this->emit($w, $a));
                $this->nextEmit = $w + 1;
            } elseif ($this->empties < $this->maxEmpty) {
                $this->empties++;
                array_push($out, ...$this->emit($w, new Window()));
                $this->nextEmit = $w + 1;
            } else {
                $nxt = $this->high - $this->late;
                foreach ($this->acc as $k => $_) if ($k >= $w && $k < $nxt) $nxt = $k;
                $this->skippedWindows += $nxt - $w;
                $this->nextEmit = $nxt;
                $this->streakStart = null;
                $this->triggered = false;
                if ($this->level !== -1) {
                    $out[] = ['kind' => 'level', 'window' => $w, 'from' => $this->name($this->level), 'to' => 'normal', 'density_micro' => 0];
                    $this->level = -1;
                }
            }
        }
        return $out;
    }

    private function emit(int $w, Window $a): array {
        $this->windows++;
        $n = $a->agentsOver ? min($a->hllAgents->estimate(), MAX_AGENTS) : count($a->agents);
        $possible = intdiv($n * ($n - 1), 2);
        $distinct = $a->pairsOver ? min($a->hllPairs->estimate(), $possible) : count($a->pairs);
        $density = density_micro($a->total, $possible, $this->windowMs);
        $ratio = 0;
        if ($possible > 0) {
            $f = floor((float) $distinct * 1e6 / (float) $possible);
            $ratio = $f >= MICRO ? MICRO : (int) $f;
        }
        $entries = [];
        foreach ($a->pairs as $k => $c) $entries[] = [$c, (string) $k, true];
        foreach ($a->cand as $k => $c) if (!isset($a->pairs[$k])) $entries[] = [$c, (string) $k, false];
        usort($entries, fn ($x, $y) => $y[0] <=> $x[0] ?: strcmp($x[1], $y[1]));
        $top = [];
        $topK = $this->policy->limits->top_k;
        foreach (array_slice($entries, 0, $topK) as [$c, $k, $ex]) {
            [$pa, $pb] = explode("\n", $k, 2);
            $top[] = ['a' => $pa, 'b' => $pb, 'count' => $c, 'exact' => $ex];
        }
        $before = $this->level;
        $this->level = $this->grade($density, $n);
        $name = $this->name($this->level);
        $out = [['kind' => 'window', 'window' => $w, 'start_ms' => $w * $this->windowMs, 'messages' => $a->total,
            'self_messages' => $a->selfMessages, 'agents' => $n, 'pairs' => $distinct, 'possible_pairs' => $possible,
            'density_micro' => $density, 'pair_ratio_micro' => $ratio, 'exact' => !($a->pairsOver || $a->agentsOver),
            'level' => $name, 'top' => $top]];
        if ($this->level !== $before) {
            $out[] = ['kind' => 'level', 'window' => $w, 'from' => $this->name($before), 'to' => $name, 'density_micro' => $density];
        }
        $r = $this->resetDue($w, $top, $density);
        if ($r !== null) $out[] = $r;
        return $out;
    }

    private function name(int $i): string { return $i < 0 ? 'normal' : $this->levels[$i][0]; }

    private function grade(int $density, int $agents): int {
        if ($agents < $this->policy->min_agents) return -1;
        $raw = -1;
        foreach ($this->levels as $i => [, $min]) if ($density >= $min) $raw = $i;
        if ($raw >= $this->level) return $raw;
        $h = $this->policy->hysteresis_permille;
        for ($j = $this->level; $j > $raw; $j--) {
            // both products stay below 2^63 for every allowed value
            if ($density * 1000 >= $this->levels[$j][1] * (1000 - $h)) return $j;
        }
        return $raw;
    }

    private function resetDue(int $w, array $top, int $density): ?array {
        $r = $this->policy->reset;
        if ($this->level < $this->resetIdx) {
            $this->streakStart = null;
            $this->triggered = false;
            return null;
        }
        $this->streakStart ??= $w;
        if ($r->mode === 'off' || $this->triggered) return null;
        $sustained = ($w - $this->streakStart + 1) * $this->windowMs;
        if ($sustained < $r->sustain_ms) return null;
        if ($this->lastTrigger !== null && ($w - $this->lastTrigger) * $this->windowMs < $r->cooldown_ms) return null;
        $this->triggered = true;
        $this->lastTrigger = $w;
        $agents = [];
        foreach ($top as $t) {
            if ($t['count'] < $r->hot_pair_min_count) break;
            foreach ([$t['a'], $t['b']] as $x) {
                if (!in_array($x, $agents, true) && count($agents) < $r->max_agents) $agents[] = $x;
            }
        }
        return ['kind' => 'reset', 'window' => $w, 'mode' => $r->mode, 'level' => $this->name($this->level),
            'density_micro' => $density, 'sustained_ms' => $sustained, 'agents' => $agents];
    }

    public function snapshot(): array {
        return ['level' => $this->name($this->level), 'next_window' => $this->nextEmit, 'open_windows' => count($this->acc),
            'events' => $this->events, 'messages' => $this->messages, 'late_dropped' => $this->lateDropped,
            'skipped_windows' => $this->skippedWindows, 'windows' => $this->windows];
    }
}

// ------------------------------------------------------------------ audit chain

/** sha256 of the canonical JSON of the record without "hash" (\InvalidArgumentException when it has none). */
function record_hash(\stdClass $record): string {
    $body = clone $record;
    unset($body->hash);
    return sha256_hex(canonical($body));
}

/** Verify an audit chain: ['ok' => bool, 'index' => ?int, 'message' => string]. */
function verify_audit(array $records): array {
    $prev = GENESIS;
    foreach (array_values($records) as $i => $r) {
        $fail = fn (string $m) => ['ok' => false, 'index' => $i, 'message' => "record $i: $m"];
        if (!($r instanceof \stdClass) || !property_exists($r, 'seq') || $r->seq !== $i) return $fail("seq is not $i");
        if (($r->prev ?? null) !== $prev) return $fail('prev does not match the hash of record ' . ($i - 1));
        try {
            $h = record_hash($r);
        } catch (\InvalidArgumentException) {
            return $fail('has no canonical form');
        }
        if (($r->hash ?? null) !== $h) return $fail('hash does not match its content');
        $prev = $h;
    }
    return ['ok' => true, 'index' => null, 'message' => count($records) . " records, chain intact, head $prev"];
}

// ------------------------------------------------------------------ agent side: HTTP

/** The monitor could not be reached (or answered something unreadable): retry later. */
class NetworkError extends \RuntimeException {}

/** The monitor answered with a status other than 2xx. */
final class ClientError extends \RuntimeException {
    public function __construct(public readonly int $status, public readonly mixed $body, string $text) {
        parent::__construct("HTTP $status: " . substr($text, 0, 300));
    }
}

/** Percent-encode one path segment (RFC 3986 unreserved characters kept; "/" becomes %2F). */
function quote_id(string $s): string { return rawurlencode($s); }

/** Calls to the Python monitor through PHP's http stream wrapper (HTTP/1.0: one connection per request;
 *  redirects are never followed, they would carry the bearer token elsewhere). */
final class Client {
    /** The largest answer read; a longer one is an error. */
    public const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
    public readonly string $url;

    public function __construct(string $url, private readonly ?string $token = null, private readonly float $timeout = 5.0) {
        if (!str_starts_with($url, 'http://') && !str_starts_with($url, 'https://')) {
            throw new \InvalidArgumentException('the monitor URL must start with http:// or https://');
        }
        $this->url = rtrim($url, '/');
    }

    /** One request. Returns the decoded JSON answer (or the text when it is not a JSON object or array).
     *  Throws NetworkError or ClientError. */
    public function request(string $method, string $path, mixed $body = null): mixed {
        $hdr = "Accept: application/json\r\n";
        if ($this->token !== null && $this->token !== '') $hdr .= "Authorization: Bearer {$this->token}\r\n";
        $opts = ['method' => $method, 'timeout' => $this->timeout, 'ignore_errors' => true, 'follow_location' => 0,
            'max_redirects' => 1];
        if ($method === 'POST') {
            $opts['content'] = $body === null ? '' : canonical($body);
            $hdr .= "Content-Type: application/json\r\n";
        }
        $opts['header'] = $hdr;
        $ctx = stream_context_create(['http' => $opts]);
        $text = @file_get_contents($this->url . $path, false, $ctx, 0, self::MAX_RESPONSE_BYTES + 1);
        if ($text === false) throw new NetworkError('monitor unreachable: ' . (error_get_last()['message'] ?? ''));
        if (strlen($text) > self::MAX_RESPONSE_BYTES) throw new NetworkError('the answer is longer than ' . self::MAX_RESPONSE_BYTES . ' bytes');
        $status = 0;
        foreach ($http_response_header ?? [] as $h) if (preg_match('#^HTTP/\S+ (\d+)#', $h, $m)) $status = (int) $m[1];
        if ($status < 200 || $status >= 300) {
            try {
                $b = decode($text);
            } catch (\JsonException) {
                $b = $text;
            }
            throw new ClientError($status, $b, $text);
        }
        if ($text !== '' && ($text[0] === '{' || $text[0] === '[')) {
            try {
                return decode($text);
            } catch (\JsonException $e) {
                throw new NetworkError('the monitor answered with invalid JSON: ' . $e->getMessage());
            }
        }
        return $text;
    }

    /** POST /v1/events with {"events": [...]}. */
    public function events(array $events): mixed { return $this->request('POST', '/v1/events', ['events' => $events]); }

    /** GET /v1/agents/{id}/commands: the pending commands (list of \stdClass). */
    public function commands(string $agentId): array {
        $r = $this->request('GET', '/v1/agents/' . quote_id($agentId) . '/commands');
        if (!($r instanceof \stdClass) || !isset($r->commands) || !is_array($r->commands)) {
            throw new NetworkError('the monitor answered the commands request without a commands list');
        }
        return $r->commands;
    }

    /** POST /v1/resets/{reset_id}/ack with {"agent_id": id}. */
    public function ack(string $resetId, ?string $agentId = null): mixed {
        return $this->request('POST', '/v1/resets/' . quote_id($resetId) . '/ack',
            $agentId === null ? new \stdClass() : ['agent_id' => $agentId]);
    }
}

/** Monotonic milliseconds. */
function mono_ms(): int { return intdiv(hrtime(true), 1000000); }

/** Wall-clock milliseconds (event timestamps). */
function wall_ms(): int { return (int) floor(microtime(true) * 1000); }

/**
 * The agent-side reporter (spec/PORTING.md item 9). record() adds to an in-memory map keyed by
 * (src, dst, ts_ms - ts_ms mod 1000) and never touches the network. PHP has no background thread here: call
 * tick() often (it sends when the interval, 1 s plus or minus up to 200 ms of jitter, has passed), or flush()
 * yourself. Sends are POST /v1/events, at most 10,000 events per request, sorted by time, src, dst. A network
 * failure or a 5xx answer keeps the events for the next send; 400/401/403/413 drops them (counted in
 * $rejected). At most $maxKeys keys are kept; messages beyond that are counted in $dropped. close() sends
 * what is left.
 */
final class Reporter {
    public const BATCH = 10000;
    public int $sent = 0;       // messages the monitor accepted
    public int $dropped = 0;    // messages lost to the maxKeys bound
    public int $rejected = 0;   // messages the monitor refused
    public int $errors = 0;     // failed sends (kept for the next one)
    public readonly Client $client;
    /** @var array<string,array{0:string,1:string,2:int,3:int}> "ts\0src\0dst" => [src, dst, ts, count] */
    private array $buf = [];
    private ?int $due = null;
    private bool $closed = false;

    public function __construct(Client|string $urlOrClient, ?string $token = null, private readonly int $intervalMs = 1000,
                                private readonly int $jitterMs = 200, private readonly int $maxKeys = 100000,
                                private readonly int $bucketMs = 1000) {
        $this->client = $urlOrClient instanceof Client ? $urlOrClient : new Client($urlOrClient, $token);
        if ($bucketMs < 1 || $bucketMs > 60000) throw new \InvalidArgumentException('bucketMs must be from 1 to 60000');
    }

    /** $count messages from $src to $dst at $tsMs (now when null); WatchError for an invalid event. */
    public function record(string $src, string $dst, int $count = 1, ?int $tsMs = null): void {
        $ts = $tsMs ?? wall_ms();
        check_event($src, $dst, $ts, $count);
        $this->put($src, $dst, $ts - $ts % $this->bucketMs, $count);
        $this->due ??= $this->nextDue();
    }

    private function put(string $src, string $dst, int $ts, int $count): void {
        $k = "$ts\0$src\0$dst";
        if (isset($this->buf[$k])) $this->buf[$k][3] = min($this->buf[$k][3] + $count, MAX_COUNT);
        elseif (count($this->buf) < $this->maxKeys) $this->buf[$k] = [$src, $dst, $ts, $count];
        else $this->dropped += $count;
    }

    private function nextDue(): int {
        $j = $this->jitterMs > 0 ? random_int(-$this->jitterMs, $this->jitterMs) : 0;
        return mono_ms() + $this->intervalMs + $j;
    }

    /** Send when a send is due; returns the messages accepted (0 when nothing was sent). Never throws on
     *  network errors. */
    public function tick(): int {
        if ($this->closed) return 0;
        $this->due ??= $this->nextDue();
        if (mono_ms() < $this->due) return 0;
        $this->due = $this->nextDue();
        try {
            return $this->flush();
        } catch (\Throwable $e) {
            fwrite(STDERR, "smartwatch: reporter flush failed: {$e->getMessage()}\n");
            return 0;
        }
    }

    /** Send everything recorded so far; returns the messages accepted. */
    public function flush(): int {
        $items = array_values($this->buf);
        $this->buf = [];
        usort($items, fn ($x, $y) => $x[2] <=> $y[2] ?: (strcmp($x[0], $y[0]) ?: strcmp($x[1], $y[1])));
        $accepted = 0;
        $n = count($items);
        for ($i = 0; $i < $n; $i += self::BATCH) {
            $part = array_slice($items, $i, self::BATCH);
            $evs = [];
            $sum = 0;
            foreach ($part as [$s, $d, $t, $c]) {
                $evs[] = ['src' => $s, 'dst' => $d, 'ts_ms' => $t, 'count' => $c];
                $sum += $c;
            }
            try {
                $res = $this->client->events($evs);
            } catch (ClientError $e) {
                if (in_array($e->status, [400, 401, 403, 413], true)) {
                    fwrite(STDERR, "smartwatch: the monitor refused a batch: {$e->getMessage()}\n");
                    $this->rejected += $sum;
                    continue;
                }
                $this->keep(array_slice($items, $i), $e);
                break;
            } catch (NetworkError $e) {
                $this->keep(array_slice($items, $i), $e);
                break;
            }
            $bad = [];
            if ($res instanceof \stdClass && isset($res->rejected) && is_array($res->rejected)) {
                foreach ($res->rejected as $r) {
                    if ($r instanceof \stdClass && isset($r->index) && is_int($r->index) && isset($evs[$r->index])) $bad[$r->index] = true;
                }
            }
            $nBad = 0;
            foreach ($bad as $j => $_) $nBad += $evs[$j]['count'];
            $this->rejected += $nBad;
            $acc = $sum - $nBad;
            $accepted += $acc;
            $this->sent += $acc;
        }
        return $accepted;
    }

    private function keep(array $rest, \Throwable $e): void {
        $this->errors++;
        fwrite(STDERR, "smartwatch: sending to the monitor failed (kept for the next send): {$e->getMessage()}\n");
        foreach ($rest as [$s, $d, $t, $c]) $this->put($s, $d, $t, $c);
    }

    /** Stop sending on tick() and send what is left; returns the messages accepted by this last send. */
    public function close(): int {
        $this->closed = true;
        return $this->flush();
    }
}

/**
 * Pulls reset commands for one agent (spec/PORTING.md item 10): GET /v1/agents/{id}/commands; for each
 * {"type": "reset", ...} command the handler runs, and when it returns normally the command is acknowledged
 * (POST /v1/resets/{reset_id}/ack). A handler that throws: no acknowledgement, the command comes again (the
 * handler must tolerate repeats; reset_id tells them apart). No background thread: call tick() often (it polls
 * every $intervalMs) or pollOnce() yourself.
 */
final class CommandPoller {
    /** @var list<string> reset_ids handled and acknowledged */
    public array $handled = [];
    private ?int $due = null;
    /** @var callable(\stdClass): void */
    private $onReset;

    public function __construct(private readonly Client $client, public readonly string $agentId, callable $onReset,
                                private readonly int $intervalMs = 1000) {
        $this->onReset = $onReset;
    }

    /** One poll; returns the number of commands handled and acknowledged. Throws NetworkError, ClientError. */
    public function pollOnce(): int {
        $n = 0;
        foreach ($this->client->commands($this->agentId) as $cmd) {
            if (!($cmd instanceof \stdClass) || ($cmd->type ?? null) !== 'reset' || !is_string($cmd->reset_id ?? null)) continue;
            try {
                ($this->onReset)($cmd);
            } catch (\Throwable $e) {
                fwrite(STDERR, "smartwatch: on_reset failed for {$cmd->reset_id}; not acknowledged: {$e->getMessage()}\n");
                continue;
            }
            $this->client->ack($cmd->reset_id, $this->agentId);
            $this->handled[] = $cmd->reset_id;
            $n++;
        }
        return $n;
    }

    /** Poll when a poll is due; network errors are reported on standard error and otherwise ignored. */
    public function tick(): int {
        $now = mono_ms();
        $this->due ??= $now + $this->intervalMs;
        if ($now < $this->due) return 0;
        $this->due = $now + $this->intervalMs;
        try {
            return $this->pollOnce();
        } catch (NetworkError | ClientError $e) {
            fwrite(STDERR, "smartwatch: polling commands failed: {$e->getMessage()}\n");
            return 0;
        }
    }
}
