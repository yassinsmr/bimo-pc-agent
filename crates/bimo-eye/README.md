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
| 8. local encryption + log integrity | `crypto.rs` (DPAPI per line, plaintext fallback with a warning event) + `log.rs` (hash chain, rotation at 50 MB, 30-day retention) |
| 9. eye stop / heartbeat | `control.rs`: `eye.stop` / `eye.pause` flag files, `eye.heartbeat` every 30 s |
| 10. build order | this core first |
| 11. measurement gates | `src/bin/self_test.rs` + `windows-eye.yml` |
| 12. backpressure + game mode | bounded 10,000-event queue; routine `proc.*` drops first, critical file events block; hashing/sync stop in game mode |
| 13. deferred to v2 | SQLite FTS, `correlation_id`, daily summary — not here |

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

## Integration (next step, after this core passes CI + council)

1. Add `crates/bimo-eye` to the workspace members in the root
   `Cargo.toml` and remove the `[workspace]` table here.
2. Wire it into `apps/bimo-agent` as its own thread behind the
   `--eye-self-test` flag (the flag is already expected by
   `.github/workflows/windows-eye.yml`).
