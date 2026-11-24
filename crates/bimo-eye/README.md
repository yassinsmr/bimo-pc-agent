# bimo-eye — the Eye, safe core (Track A Unit 2)

Local event log + file watcher + background hash worker + process
snapshots + stop file + heartbeat. No window titles, no screenshots,
no window events in this core — those come with their own spikes
afterwards (council condition 10: log+files first, windows second,
screenshots last).

## How it maps to the council conditions (unit 2, 13 conditions)

| Condition | Where it is met |
|---|---|
| 1. blind-spot closure | `snapshot.rs`: Toolhelp32Snapshot every 10 s + folder reconciliation is the watcher itself; v1 promise narrowed in the `agent.start` scope note |
| 2. spike gate before build | passed in cycle 9 (`verdict: pass`) |
| 3. hash cap | `hash_worker.rs`: async, ~2 GiB cap, off during game mode |
| 4. `install.detected` low confidence | `eye.rs`: always `"low"`, never a trigger on its own |
| 5. window titles | NOT in this core — exe + PID only; full titles come with the window spike |
| 6. alert screenshots local + notice | NOT in this core — comes with the screenshot spike |
| 7. watch scope | `agent.start` scope note: v1 watches ONLY the configured folders; anything outside is NOT covered |
| 8. local encryption + log integrity | `crypto.rs` (DPAPI per line, FAIL-CLOSED: no silent plaintext fallback — refusal or explicit opt-in only) + `log.rs` (hash chain, rotation at 50 MB, 30-day retention) |
| 9. eye stop / heartbeat | `control.rs`: `eye.stop` / `eye.pause` flag files, `eye.heartbeat` every 30 s + `heartbeat.json` marker file and `eye.stopped` marker (condition 5: a stop leaves a trace outside the log) |
| 10. build order | this core first |
| 11. measurement gates | `src/bin/self_test.rs` + `windows-eye.yml` |
| 12. backpressure + game mode | bounded 10,000-event queue; routine `proc.*` drops first, critical file events block; hashing/sync stop in game mode; drops are recorded as `log.gap` events (condition 4) |
| 13. deferred to v2 | SQLite FTS, `correlation_id`, daily summary — not here |

## Threat model (honest — eye-core council condition 3)

What this core does and does NOT guarantee. The same two sentences
are written into every `agent.start` scope note, so the log itself
carries them:

- **The hash chain is tamper-EVIDENCE, not integrity.** It proves a
  log line was changed after the fact — it does not stop an attacker
  running with the same privileges from rewriting the whole file and
  recomputing the chain. A same-privilege attacker can also write
  `eye.stop` / `eye.pause`: there is no privilege boundary here.
- **DPAPI protects against another user / a stolen disk**, not
  against malware running as Yassin. If DPAPI is unavailable the eye
  refuses to write (fail-closed) unless the operator explicitly opts
  into plaintext with `BIMO_EYE_PLAINTEXT_OK=1`, and that opt-in is
  itself recorded in the log.
- **A stop is detectable from outside the log** (condition 5): the
  alerts unit watches `heartbeat.json` freshness in the data dir;
  while stopped, `heartbeat.json` is removed and `eye.stopped`
  (`{"ts", "reason"}`) is written instead. A stale heartbeat file
  means a crash; a missing one + `eye.stopped` means a deliberate
  stop.
- **A hash is only a decision on a stable, closed file**
  (condition 4): the worker stats size + mtime twice 500 ms apart
  before hashing, defers a still-changing file (max 3 attempts, then
  a named skip), and re-hashes a file that changes after its first
  hash. Queue overflows are recorded as `log.gap` events with the
  count and the cause.

## Build

Standalone on purpose (cycle 14): this crate carries its own
`[workspace]` table so it builds without touching the workspace
root — the browser uploads it as new files only.

```sh
cd crates/bimo-eye
cargo build --release --target x86_64-pc-windows-msvc --locked
```

## Self-test

```sh
.\target\x86_64-pc-windows-msvc\release\bimo-eye-self-test.exe --out eye-self-test.json
```

Runs the whole core in a throwaway temp dir (fake `setup.exe`,
a text file, Notepad on Windows, the stop-file round-trip) and
verifies the JSONL log: hash chain, continuous sequence, every
expected event present. Exit 0 = pass, 1 = fail. The JSON report
carries `verdict`, per-check status, resources, and honest limits.

New checks added in cycle 15 (council conditions 2, 4, 5):
fail-closed crypto (simulated DPAPI failure refuses without
opt-in), re-hash after a later change, heartbeat marker file
present before the stop, gone + `eye.stopped` present while
stopped, fresh again after resume. Unit tests (`cargo test`)
cover the gap-event helper, the file-stability check, and the
crypto fail-closed branches. Honest limit: a full-queue flood
(10,000 events) is not reproducible inside the self-test window —
the overflow mechanism is verified by unit test, not end to end.

## Integration (next step, after this core passes CI + council)

1. Add `crates/bimo-eye` to the workspace members in the root
   `Cargo.toml` and remove the `[workspace]` table here.
2. Wire it into `apps/bimo-agent` as its own thread behind the
   `--eye-self-test` flag (the flag is already expected by
   `.github/workflows/windows-eye.yml`).
