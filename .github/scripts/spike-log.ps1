# Shared log-reading helpers for the hand thin-slice spike workflow.
#
# The eye appends to eye-events.jsonl while it runs; every read
# retries on a sharing violation instead of failing the step.
# Lines that are not JSON (a torn write mid-flush) are skipped —
# the writer flushes after every line (log.rs), so a torn line is
# transient, never the steady state.

function Read-EyeLog {
  param([string]$Path)
  $tries = 0
  while ($true) {
    try {
      $lines = [System.IO.File]::ReadAllLines($Path)
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
    $lines = [System.IO.File]::ReadAllLines($Path)
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
