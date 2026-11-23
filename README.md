# bimo-pc-agent

BIMO PC agent for Windows — a single native Rust agent for Yassin's future
Legion laptop: a secure link to BIMO, a live event feed, on-demand
screenshots, installs and file work, a quarantine-only guard, speed
tooling, and a glass Dynamic Island with BIMO's avatar.

**Status: Windows proof gate in progress.** The gate (`bimo-agent --gate`)
opens one island capsule, draws it with the frozen glass starting values,
measures 60 s idle + a 10 s continuous morph, and prints JSON with the
verdict. See `.github/workflows/windows-gate.yml`.

## Build

```sh
# Native (Linux dev): cargo test
# Windows cross-build (reproducible, from a clean checkout):
./build-windows.sh   # produces bimo-agent.exe (PE32+, imports d2d1.dll + dwmapi.dll)
```

## Architecture

- `crates/bimo-core` — event bus + island state machine (std only).
- `crates/bimo-island` — Direct2D island renderer + `--gate` harness (Windows).
- `apps/bimo-agent` — the single agent binary.

Native Rust + Direct2D only. No Electron, no webview. Performance budget:
idle ~0% CPU, ~1 GB RAM max, ~5% CPU max — the governing rule is that the
tool must never affect the machine's gaming or work performance.

## License

MIT
