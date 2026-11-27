# Eye diagnostic control — pulse loop (council 15, cycle 58, measurement run 4).
#
# Run 3's control slept silently for 45 s and died with it: its death
# time was only bounded by a ~20 s window (last seen alive vs first
# seen dead), which is exactly the fact council 15 ruled missing.
# This control does the SAME job — a trivial process launched the
# EXACT same way (same step, same Start-Process form, same 45 s
# window) — but it writes a timestamped disk pulse every 500 ms
# instead of sleeping silently, so its own death is dated within a
# second: while alive it writes every 500 ms, so the last pulse is at
# most ~500 ms before death. A torn final line (killed mid-flush) is
# expected: readers take the last PARSEABLE line, never invent one.
#
# The pulse file is appended (one line per pulse, ~90 lines max), so
# the full cadence history survives for the regularity check in D7:
# a max inter-pulse gap > 1 s while alive breaks the regularity
# assumption the death bound rests on, and the verdict must then be
# inconclusive-by-design (M1), not a killer claim.
#
# Usage: pwsh -NoProfile -File diag-control-pulse.ps1 -PulseFile <path> -Seconds 45
param(
  [string]$PulseFile,
  [int]$Seconds = 45
)
$ErrorActionPreference = "Continue"
$end = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $end) {
  [DateTimeOffset]::UtcNow.ToString("o") | Add-Content -Path $PulseFile -Encoding utf8
  Start-Sleep -Milliseconds 500
}
