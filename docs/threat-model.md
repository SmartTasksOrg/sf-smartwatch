# Threat model

SmartWatch watches cooperating agents and asks for a reset when they coordinate more densely than the
policy allows. It is an oversight signal. It is not a sandbox, a firewall or a kill switch.

## Assets

- **The decision to reset:** who can cause one, and who can prevent one.
- **The record:** the audit log of levels, proposals, decisions and resets.
- **Traffic metadata:** which agents talk to which, and how much. This is sensitive in some systems.

## Actors and trust

| Actor | Trusted for | Credential |
|---|---|---|
| Reporter / agent side | reporting its own messages honestly; acknowledging resets | ingest token |
| Operator | reading state; nothing that changes it (and resets, only when no JWT key is configured) | operator token |
| Person with reset authority | resets and decisions | JWT with `reset:agent` from your identity provider |
| The monitor host | everything (it holds the tokens and writes the log) | — |

## What is defended

- **Unauthenticated access:** every endpoint except `/healthz` and `/metrics` needs a credential. Tokens
  are compared in constant time. Failed attempts are rate-limited per address: after 20 failures in a
  minute an address gets 429 for every further wrong credential (a valid one still passes, so a stranger
  behind the same NAT cannot lock reporters out). At most 32 open connections per address.
- **Resets by the wrong people:** with a JWT key configured, only tokens with the scope `reset:agent`,
  a valid signature in the one algorithm the key allows (never `none`, no switching between algorithms),
  an unexpired `exp` and matching `iss`/`aud` (when configured) can reset or decide. The operator and
  ingest tokens cannot. Tokens with a non-finite `exp`, or one more than 24 hours ahead, are refused.
- **Role confusion:** each token opens only its own endpoints. The operator token cannot ingest or
  acknowledge, and the ingest token cannot read state.
- **Cross-site requests from a browser:** HTTP Basic (which browsers remember) is accepted only for
  `GET /ui`; every POST must be `application/json`; requests with an `Origin` header or a cross-site
  `Sec-Fetch-Site` are refused.
- **Replayed reset requests:** `Idempotency-Key` per caller returns the first result instead of a second
  reset.
- **Forged webhooks:** HMAC-SHA256 over the timestamp and body. Receivers must check the signature and
  how fresh the timestamp is.
- **Oversized or slow requests:** body limits (1 MiB for events, 256 KiB otherwise), Content-Length
  required, 10 s socket timeout, 30 s per connection, at most 256 connections, at most 10,000 events per
  batch.
- **Memory exhaustion by many ids:** exact counting is bounded by the policy limits, beyond which the
  fixed-size sketches take over. The reporter buffer, the proposal, reset, idempotency and webhook
  queues are all bounded.
- **A reporter clock that runs ahead:** events more than 2 s ahead are refused, and none can move the
  windows ahead of the monitor's clock.
- **A failed audit write:** a partial record is cut back and the monitor refuses further changes, so no
  reset happens without its record.
- **Tampering with the log in place:** the hash chain shows the first edited, removed or reordered
  record.
- **Credential leaks through redirects:** the clients never follow redirects.
- **Status page:** HTML-escaped, no script, a Content-Security-Policy of `default-src 'none'`, no
  framing.

## What is not defended (by design or not yet)

- **Lying reporters.** A holder of the ingest token can report any traffic for any agent. It can inflate
  density, which may trigger a proposal naming chosen agents, or under-report it, which hides
  coordination. Give each agent group its own monitor or accept that reporters are trusted. In `confirm`
  mode a person sees the proposal before anything happens.
- **Dilution by invented agents.** Density divides by all possible pairs (the council's definition). A
  holder of the ingest token can report a few messages between many invented agents. That inflates the
  number of possible pairs and pulls the whole window's density down, hiding a real burst between
  other agents. The hot pair still shows in `top` and in `smartwatch_pair_messages`. Alert on that too,
  for example `max(smartwatch_pair_messages) > N` for a count N that your agents never reach. A
  hot-subgraph density is an open decision for a later version.
- **One shared ingest token.** Any holder can read and acknowledge any agent's reset commands (the
  acknowledgement must name the right agent, but the token does not prove it is that agent). An
  acknowledgement removes the command from the queue; webhooks are not affected. Give separate trust
  domains separate monitors.
- **Agents that coordinate outside the reported channels.** Shared files, shared memory, side channels
  and payload content are invisible. Density measures message counts, not what the messages mean.
- **Hash collisions.** `hash_seed` is not secret, and FNV-1a is not a cryptographic hash. Collisions
  only over-count, so they can make a pair look hotter but cannot hide one.
- **A compromised monitor host** can do anything, including rewriting the whole log. Ship the log or its
  head hash elsewhere.
- **Truncation of the audit log** followed by a new tail is not detectable from the file alone.
- **Plain HTTP:** TLS is the proxy's job.
- **`/metrics` is open:** it names the top pairs. Restrict it at the network level if that matters.
- **Agents that ignore a reset.** SmartWatch issues commands; enforcement is yours (or SmartSwitch's).
