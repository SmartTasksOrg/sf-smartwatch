<?php
// php bin/conformance.php DIR: runs spec/conformance/*.json against the PHP port, as the Python runner does.
declare(strict_types=1);
require __DIR__ . '/../src/SmartWatch.php';

use SmartTasks\SmartWatch\{Engine, HyperLogLog, WatchError};
use function SmartTasks\SmartWatch\{bucket, canonical, decode, density_micro, fnv1a32, fnv1a64, mix64, sha256_hex, thresholds,
    u64_string, validate_policy, verify_audit};

$dir = $argv[1] ?? __DIR__ . '/../../../spec/conformance';
$load = fn (string $n) => decode(file_get_contents("$dir/$n"));
$c = function (mixed $v): string {
    try {
        return canonical($v);
    } catch (\InvalidArgumentException $e) {
        return '<not canonical: ' . $e->getMessage() . '>';
    }
};
$total = 0;
$fails = [];
$check = function (string $name, mixed $got, mixed $want) use (&$total, &$fails, $c): void {
    $total++;
    $g = $c($got);
    $w = $c($want);
    if ($g !== $w) $fails[] = "$name: got " . substr($g, 0, 300) . ', want ' . substr($w, 0, 300);
};
$pick = function (\stdClass $cs, array $keys): array {
    $out = [];
    foreach ($keys as $k) if (property_exists($cs, $k)) $out[$k] = $cs->{$k};
    return $out;
};
$expand = function (mixed $items): array {
    if (!($items instanceof \stdClass)) return $items;
    $out = [];
    for ($i = $items->from; $i < $items->to; $i++) $out[] = $items->prefix . $i;
    return $out;
};

foreach ($load('canonical.json')->cases as $cs) {
    $text = $c($cs->input);
    $check("canonical/{$cs->name}", [$text, sha256_hex($text)], [$cs->canonical, $cs->sha256]);
}

foreach ($load('hashing.json')->cases as $i => $cs) {
    $h64 = fnv1a64($cs->seed, $cs->text);
    $got = ['fnv1a32' => fnv1a32($cs->seed, $cs->text), 'fnv1a64' => u64_string($h64), 'mix64' => u64_string(mix64($h64)),
        'bucket' => bucket($cs->seed, $cs->text)];
    $check("hashing/$i", $got, $pick($cs, array_keys($got)));
}

foreach ($load('hll.json')->cases as $cs) {
    $h = new HyperLogLog($cs->seed);
    foreach ($expand($cs->items) as $x) $h->add($x);
    $check("hll/{$cs->name}", ['estimate' => $h->estimate(), 'digest' => $h->digest()], $pick($cs, ['estimate', 'digest']));
}

foreach ($load('density.json')->cases as $i => $cs) {
    $check("density/$i", density_micro($cs->messages, $cs->possible_pairs, $cs->window_ms), $cs->density_micro);
}

foreach ($load('policies.json')->cases as $cs) {
    try {
        validate_policy($cs->policy);
        $got = ['ok' => true];
    } catch (WatchError $e) {
        $got = ['ok' => false, 'code' => $e->watchCode];
    }
    $check("policies/{$cs->name}", $got, $pick($cs, ['ok', 'code']));
}

foreach ($load('calibration.json')->cases as $cs) {
    try {
        $got = ['ok' => true, 'thresholds' => thresholds($cs->densities, $cs->permille)];
    } catch (\InvalidArgumentException) {
        $got = ['ok' => false];
    }
    $check("calibration/{$cs->name}", $got, $pick($cs, ['ok', 'thresholds']));
}

foreach ($load('monitor.json')->cases as $cs) {
    $eng = new Engine($cs->policy);
    foreach ($cs->steps as $i => $st) {
        try {
            $got = match ($st->op) {
                'add' => ['ok' => true, 'outputs' => $eng->add($st->src, $st->dst, $st->ts_ms, $st->count)],
                'flush' => ['ok' => true, 'outputs' => $eng->flush($st->now_ms)],
                default => $eng->snapshot(),
            };
        } catch (WatchError $e) {
            $got = ['ok' => false, 'code' => $e->watchCode];
        }
        $check("monitor/{$cs->name} step $i ({$st->op})", $got, $st->expect);
    }
}

foreach ($load('audit.json')->cases as $cs) {
    $r = verify_audit($cs->records);
    $check("audit/{$cs->name}", ['ok' => $r['ok'], 'index' => $r['index']], $cs->result);
}

foreach ($fails as $f) echo "FAIL $f\n";
if ($fails) {
    echo 'php: ' . count($fails) . " of $total vectors FAILED\n";
    exit(1);
}
echo "php: $total/$total vectors passed\n";
