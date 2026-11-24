# bimo-wintrack — window-event spike (Track A Unit 2)

Proves, on real Windows, that `SetWinEventHook` delivers real window
events before the eye unit is built on top of it (council condition 2
on Unit 2; spec `track-a-unit2-eye-window-spike.md`).

## What it proves (3 substantive checks + 1 regression guard)

1. **hook-fires** — opening Notepad + calc produces at least one
   `app.focus` event per launched process family; 0 events = the hook is blind.
2. **proc-link** — every event links a correct exe + PID (verified
   against `GetWindowThreadProcessId` + `Toolhelp32Snapshot`); one
   wrong link = fail.
3. **hook-resilience** — killing the hook thread and letting the
   internal watchdog re-register it brings events back in under 10 s.
4. **titles-flag-off** (regression guard, not a substantive pass) —
   with `eye.full-titles` off (the default), the trial log contains 0
   full window titles. The spike never calls `GetWindowText` at all
   while the flag is off. It is trivially true by construction, so it
   is not counted in the headline verdict.

**Verdict (restated cycle 18, council condition 2): 3/3 substantive
checks pass + titles-flag-off as regression guard + Defender check
suspended.** The old "4/4" wording is withdrawn: the Defender check is
void as evidence (realtime protection off on the runner,
`realtime: false`) and stays suspended until a check with realtime
protection runs (arrival-day list). The core self-test runs no Defender
check at all.

## Frozen naming (cycle 16 — council improvement on the eye core; definitions + count rule frozen cycle 18, council condition 1)

Two layers, never mixed:

| Type | Source | Fields |
|---|---|---|
| `proc.seen` / `proc.gone` | snapshotter (process list) | `pid` + `exe` |
| `app.open` / `app.close` / `app.focus` | this hook | `pid` + `exe` + `hwnd` |
| `hook.recovered` | internal watchdog | `reason` + `after_ms` |

The snapshotter never emits `app.*`; the hook never emits `proc.*`.
Renaming later means a log-format version bump + a council note.

**Frozen definitions (schema 1 — full text in §12 of
`track-a-unit2-eye-core-build.md`):** `app.open` = one top-level
window creation (`EVENT_OBJECT_CREATE`, `id_object == 0 &&
id_child == 0`) — one event per window created, **not** per app launch.
`app.focus` = foreground changed to a top-level window
(`EVENT_SYSTEM_FOREGROUND`). `app.close` = one top-level window
destroyed (`EVENT_OBJECT_DESTROY`).

**Count rule (resolves the 47 anomaly):** check 1 counts per process
family (launched pid + same-exe pids + children of the launched pid).
One launch can produce many `app.open` events: the calc family
recorded **open 47 / focus 1** in spike run #6 (main a57052c,
spike-results be713e5) — 47 top-level window creations from `calc.exe`
+ `win32calc.exe` (UWP apps spawn many top-level windows). Documented
expected behaviour, not an anomaly and not a hook failure.
**`app.open` count is never a launch count** — any protection decision
treating it as one is wrong. A real launch counter would need a new
`app.launch` event (not in v1).

**Schema version field:** every JSONL line carries `"schema": 1`.
The writer emits it; the reader/verifier rejects lines with a missing
or unknown version (fail-closed, explicit event). Code enforcement
(writer + verifier + unit test) is cycle-19 work with council
conditions 3–4, verified by a CI run on Windows.

## Honest limits

- The runner has no real display: a headless failure is recorded as
  such in the JSON fragment, not silently treated as a design failure
  (same rule as the eye spike §8).
- No real fullscreen game exists on the runner; capture over a real
  exclusive-fullscreen game is decided on the Legion (second gate).
- Runner numbers never prove device performance (flawhunt amendment
  11-z); the performance budget is decided on the Legion.
- Window titles are never captured in the routine log while
  `eye.full-titles` is off. Title capture is a separate step behind
  that flag, not part of this spike.

## Usage (on real Windows)

```text
eye-window-spike --check hook-fires
eye-window-spike --check proc-link
eye-window-spike --check hook-resilience
eye-window-spike --check titles-flag-off
eye-window-spike --merge
```

Each check writes one fragment `winspike-<check>.json`; `--merge`
combines them into `window-spike-results.json`. The merge reads the
Defender before/after files for the record only — it never lets them
change the verdict (cycle 19, council condition 2, proven by a unit
test: a Defender rise on an otherwise passing run still merges
`pass`). `--merge` is the gate (cycle 19, council condition 3): it
exits 1 on any failure and the workflow lets that fail the run.
Events also append to the trial log `winspike-trial.jsonl` in the eye
format (`schema` + `seq` + `ts` + `prev_hash` + `hash`); the merge
verifies every line carries `schema` 1, fail-closed (cycle 19,
council condition 1). A failed hook recovery leaves an explicit
`hook.recovery_failed` event in the trial log (cycle 19, council
condition 3). Runner numbers in the merged JSON are tagged
`perf_tag: runner-only — does not prove device performance`
(cycle 19, council condition 4).
