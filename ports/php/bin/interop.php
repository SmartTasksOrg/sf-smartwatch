<?php
// The interop program for ports/conformance/interop.py (spec/PORTING.md, "The interop program"):
// php bin/interop.php URL AGENT_IDS SECONDS, the ingest token in SMARTWATCH_INGEST_TOKEN.
// PHP has no threads here: one loop records the rounds and calls the reporter's and pollers' tick().
declare(strict_types=1);
require __DIR__ . '/../src/SmartWatch.php';

use SmartTasks\SmartWatch\{Client, CommandPoller, Reporter};
use function SmartTasks\SmartWatch\mono_ms;

if ($argc !== 4) {
    fwrite(STDERR, "usage: php bin/interop.php URL AGENT_IDS SECONDS\n");
    exit(2);
}
[, $url, $idList, $seconds] = $argv;
$ids = explode(',', $idList);
$seconds = (int) $seconds;
$token = getenv('SMARTWATCH_INGEST_TOKEN');
$token = $token === false ? null : $token;

$pollers = [];
foreach ($ids as $a) {
    $pollers[] = new CommandPoller(new Client($url, $token), $a, function (\stdClass $cmd) use ($a): void {
        echo "RESET $a {$cmd->reset_id}\n";
        fflush(STDOUT);
    }, 200);
}
$rep = new Reporter($url, $token);
$service = function () use ($rep, $pollers): void {
    $rep->tick();
    foreach ($pollers as $p) $p->tick();
};

$t0 = mono_ms();
for ($r = 0; $r < $seconds * 10; $r++) {
    foreach ($ids as $a) {
        foreach ($ids as $b) {
            if ($a !== $b) $rep->record($a, $b, 1);
        }
    }
    $end = $t0 + ($r + 1) * 100;
    while (($left = $end - mono_ms()) > 0) {
        $service();
        usleep(min($left, 10) * 1000);
    }
}
$rep->close();
echo "SENT {$rep->sent}\n";
fflush(STDOUT);

// keep polling until standard input closes
stream_set_blocking(STDIN, false);
while (true) {
    foreach ($pollers as $p) $p->tick();
    $rd = [STDIN];
    $wr = null;
    $ex = null;
    if (@stream_select($rd, $wr, $ex, 0, 50000) > 0) {
        $data = fread(STDIN, 8192);
        if (($data === '' || $data === false) && feof(STDIN)) break;
    }
}
exit(0);
