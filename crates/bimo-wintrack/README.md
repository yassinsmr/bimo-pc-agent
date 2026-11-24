# bimo-wintrack — window-event spike (Track A Unit 2)

Proves, on real Windows, that `SetWinEventHook` delivers real window
events before the eye unit is built on top of it (council condition 2
on Unit 2; spec `track-a-unit2-eye-window-spike.md`).

## What it proves (4 independent checks, one process each)

1. **hook-fires** — opening Notepad + calc produces at least one
   `app.focus` event per launched app; 0 events = the hook is blind.
2. **proc-link** — every event links a correct exe + PID (verified
   against `GetWindowThreadProcessId` + `Toolhelp32Snapshot`); one
   wrong link = fail.
3. **hook-resilience** — killing the hook thread and letting the
   internal watchdog re-register it brings events back in under 10 s.
4. **titles-flag-off** — with `eye.full-titles` off (the default), the
   trial log contains 0 full window titles. The spike never calls
   `GetWindowText` at all while the flag is off.

## Frozen naming (cycle 16 — council improvement on the eye core)

Two layers, never mixed:

| Type | Source | Fields |
|---|---|---|
| `proc.seen` / `proc.gone` | snapshotter (process list) | `pid` + `exe` |
| `app.open` / `app.close` / `app.focus` | this hook | `pid` + `exe` + `hwnd` |
| `hook.recovered` | internal watchdog | `reason` + `after_ms` |

The snapshotter never emits `app.*`; the hook never emits `proc.*`.
Renaming later means a log-format version bump + a council note.

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
combines them plus the Defender before/after files into
`window-spike-results.json`. Events also append to the trial log
`winspike-trial.jsonl` in the eye format (`seq` + `ts` + `prev_hash`
+ `hash`).
