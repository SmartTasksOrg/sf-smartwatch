#!/usr/bin/env node
'use strict';
// Interop program for ports/conformance/interop.py (spec/PORTING.md, "The interop program"):
//   interop.js URL AGENT_IDS SECONDS      (token in SMARTWATCH_INGEST_TOKEN)
// Starts the reporter and one command poller per agent (200 ms), prints "RESET <agent> <reset_id>" for
// every command, records every ordered pair once per 100 ms round for SECONDS × 10 rounds, closes the
// reporter and prints "SENT <accepted>", then keeps polling until standard input closes.
const { Client, Reporter, CommandPoller } = require('../src');

const [url, idList, secondsArg] = process.argv.slice(2);
if (!url || !idList || !secondsArg) {
  process.stderr.write('usage: interop.js URL AGENT_IDS SECONDS\n');
  process.exit(2);
}
const ids = idList.split(',');
const seconds = parseInt(secondsArg, 10);
const token = process.env.SMARTWATCH_INGEST_TOKEN || null;

const print = (line) => new Promise((resolve) => { if (!process.stdout.write(line + '\n')) process.stdout.once('drain', resolve); else resolve(); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mono = () => Number(process.hrtime.bigint() / 1000000n);

let stdinDone = false;
const stdinClosed = new Promise((resolve) => {
  const done = () => { stdinDone = true; resolve(); };
  process.stdin.on('end', done);
  process.stdin.on('close', done);
  process.stdin.on('error', done);
});
process.stdin.resume();

(async () => {
  const pollers = ids.map((a) => new CommandPoller(new Client(url, token), a, (cmd) => print(`RESET ${a} ${cmd.reset_id}`), 200,
    (e) => process.stderr.write(`polling ${a} failed: ${e.message}\n`)).start());
  const rep = new Reporter(url, token).start();
  const t0 = mono();
  for (let r = 0; r < seconds * 10; r++) {
    for (const a of ids) for (const b of ids) if (a !== b) rep.record(a, b, 1);
    await sleep(Math.max(0, t0 + (r + 1) * 100 - mono()));
  }
  await rep.close();
  if (rep.lastError) process.stderr.write(`reporter: last error ${rep.lastError.message}\n`);
  await print(`SENT ${rep.sent}`);
  if (!stdinDone) await stdinClosed;
  for (const p of pollers) p.stop();
  process.exit(0);
})().catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + '\n');
  process.exit(1);
});
