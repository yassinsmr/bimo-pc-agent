# Shared log-reading helpers for the hand thin-slice spike workflow.
#
# The eye appends to eye-events.jsonl while it runs; every read
# retries on a sharing violation instead of failing the step.
# Lines that are not JSON (a torn write mid-flush) are skipped —
# the writer flushes after every line (log.rs), so a torn line is
# transient, never the steady state.
#
# SHARING RULE (council fix, run 3 — read this before touching the
# open call): the eye holds the log open with WRITE access for the
# whole run (log.rs: LogWriter keeps the handle; closed only in
# close()). Windows sharing is checked BOTH ways: a new open must
# share every access the existing handle holds. .NET's
# File.ReadAllLines opens with FileShare.Read only, so Windows
# rejects it against the live writer (ERROR_SHARING_VIOLATION —
# run 3 failed F3 on exactly this). FileShare.ReadWrite accommodates
# the writer's access. A Rust reader (File::open, share
# Read|Write|Delete) succeeds for the same reason — the eye self-test
# reads its own log live on Windows CI (22/22). Never go back to
# ReadAllLines / Get-Content defaults for this file while the eye
# is alive.

# Read all lines of a file the eye may still be appending to.
# Returns @() after 5 failed attempts (transient lock / torn write),
# never throws — polling callers rely on that.
function Read-EyeLogLines {
  param([string]$Path)
  $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
  $sr = New-Object System.IO.StreamReader($fs)
  try {
    return @($sr.ReadToEnd() -split "`r?`n")
  } finally {
    $sr.Close()
  }
}

function Read-EyeLog {
  param([string]$Path)
  $tries = 0
  while ($true) {
    try {
      $lines = Read-EyeLogLines -Path $Path
      break
    } catch {
      $tries++
      if ($tries -ge 5) { return @() }
      Start-Sleep -Milliseconds 200
    }
  }
  $out = @()
  foreach ($line in $lines) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    try { $out += ($line | ConvertFrom-Json) } catch {}
  }
  return $out
}

# True if an event of $Type for exactly $ExactPath appears within
# $TimeoutSecs. Returns a bool (latency discarded).
function Wait-EyeEvent {
  param([string]$Path, [string]$Type, [string]$ExactPath, [int]$TimeoutSecs)
  $ms = Wait-EyeEventMs -Path $Path -Type $Type -ExactPath $ExactPath -TimeoutSecs $TimeoutSecs -Since $null
  return ($null -ne $ms)
}

# Milliseconds from call time until the event appears, or $null on
# timeout. $Since (a [DateTimeOffset], optional) ignores events
# older than that instant — used after a rename, so a pre-rename
# completion of the OLD name cannot satisfy the NEW name.
function Wait-EyeEventMs {
  param([string]$Path, [string]$Type, [string]$ExactPath, [int]$TimeoutSecs, $Since)
  $t0 = [DateTimeOffset]::UtcNow
  $deadline = (Get-Date).AddSeconds($TimeoutSecs)
  while ((Get-Date) -lt $deadline) {
    $events = Read-EyeLog -Path $Path
    $hit = @($events | Where-Object {
      $_.type -eq $Type -and $_.path -eq $ExactPath -and
      ($null -eq $Since -or ([DateTimeOffset]::Parse($_.ts) -ge $Since))
    })
    if ($hit.Count -gt 0) { return [int]([DateTimeOffset]::UtcNow - $t0).TotalMilliseconds }
    Start-Sleep -Milliseconds 500
  }
  return $null
}

# F3/F4 (council fix, run 2): the LOUD readability probe. Unlike
# Read-EyeLog (a polling helper that silently returns @() while the
# file is still appearing), this throws when the log file is missing
# and otherwise reports counts, so a run can never again mistake an
# unreadable log for a quiet tree. Returns a hashtable:
# @{ exists; total_lines; json_lines; has_agent_start }.
function Test-EyeLogReadable {
  param([string]$Path)
  if (-not (Test-Path $Path)) {
    throw "eye log missing: $Path"
  }
  $total = 0; $json = 0; $hasStart = $false
  try {
    $lines = Read-EyeLogLines -Path $Path
  } catch {
    throw "eye log unreadable: $Path ($($_.Exception.Message))"
  }
  foreach ($line in $lines) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $total++
    try {
      $ev = ($line | ConvertFrom-Json)
      $json++
      if ($ev.type -eq "agent.start") { $hasStart = $true }
    } catch {}
  }
  return @{ exists = $true; total_lines = $total; json_lines = $json; has_agent_start = $hasStart }
}
