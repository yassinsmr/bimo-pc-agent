# Eye diagnostic monitor (council 14, cycle 57, condition C2; pulse
# extension council 15, cycle 58, measurement run 4).
#
# Launched from the SAME step that arms the eye (D1), as a detached
# process, so the exit-code capture survives step boundaries by design:
# the $proc object from Start-Process does NOT survive across steps
# (reviewer 1's correction), so a monitor process inside the arming
# step is the only way the exit code persists.
#
# The monitor holds a Process object for each pid (eye + control) and
# waits for exit; on exit it writes the exit code + exit timestamp to
# a JSON file in the diag dir. If a process already died before the
# monitor attached, that is recorded honestly (exited_before_monitor,
# no code) instead of invented. If a process does not exit within
# 150 s, the monitor records timed_out and moves on (never hangs the
# job: the monitor's own life is bounded, the job timeout is 20 min).
#
# MEASUREMENT RUN 4 (council 15): run 3's monitor died with the
# arming step and left no trace of its own death — its death time was
# unknown. Now, while waiting, the monitor writes a timestamped disk
# pulse every 500 ms (WaitForExit(500) polling loop), so its own death
# is dated within a second exactly like the control's: while alive it
# writes every 500 ms. The pulse file is appended (~1 line per 500 ms
# of waiting); D7 checks the max inter-pulse gap — a gap > 1 s while
# alive breaks the regularity assumption and the verdict must then be
# inconclusive-by-design (M1).
#
# Usage: pwsh -NoProfile -File diag-monitor.ps1 -EyePid <pid> -ControlPid <pid> -DiagDir <dir>
param(
  [int]$EyePid,
  [int]$ControlPid,
  [string]$DiagDir
)
$ErrorActionPreference = "Continue"

$startTs = [DateTimeOffset]::UtcNow
@{ monitor_pid = $PID; start_ts = $startTs.ToString("o"); eye_pid = $EyePid; control_pid = $ControlPid } | ConvertTo-Json | Out-File -FilePath "$DiagDir\monitor-started.json" -Encoding utf8

function Write-Pulse {
  param([string]$PulseFile)
  [DateTimeOffset]::UtcNow.ToString("o") | Add-Content -Path $PulseFile -Encoding utf8
}

function Wait-One {
  param([int]$TargetPid, [string]$OutFile, [string]$PulseFile)
  $rec = @{ pid = $TargetPid; exit_code = $null; exit_ts = $null; exited_before_monitor = $false; timed_out = $false }
  try {
    $p = Get-Process -Id $TargetPid -ErrorAction Stop
  } catch {
    # Already dead before the monitor could attach: no handle, no code.
    # Recorded as such; the D2/D4 liveness reads are the backstop.
    $rec.exited_before_monitor = $true
    $rec | ConvertTo-Json | Out-File -FilePath $OutFile -Encoding utf8
    return
  }
  # Pulse while waiting: every 500 ms the monitor itself timestamps a
  # disk pulse, so its own death is dated even if it dies mid-wait.
  # WaitForExit(500) returns $false each 500 ms while the target lives,
  # which is exactly the pulse cadence — no thread, no timer, no new
  # mechanism (M3: workflow change only).
  Write-Pulse -PulseFile $PulseFile
  $deadline = (Get-Date).AddSeconds(150)
  while ((Get-Date) -lt $deadline) {
    if ($p.WaitForExit(500)) {
      $rec.exit_code = $p.ExitCode
      $rec.exit_ts = [DateTimeOffset]::UtcNow.ToString("o")
      break
    }
    Write-Pulse -PulseFile $PulseFile
  }
  if ($null -eq $rec.exit_ts -and -not $rec.exited_before_monitor) { $rec.timed_out = $true }
  $rec | ConvertTo-Json | Out-File -FilePath $OutFile -Encoding utf8
}

# Eye first: it is the one expected to die early (~4 s). Then the
# control (45 s pulse loop): the monitor lives ~45 s total and is gone
# before the job ends. One shared pulse file covers both waits, so the
# monitor's pulse history is continuous from its own start until both
# targets exit (or it dies — which is itself the dated event).
$monitorPulseFile = "$DiagDir\monitor-pulse.log"
Wait-One -TargetPid $EyePid -OutFile "$DiagDir\eye-exit.json" -PulseFile $monitorPulseFile
Wait-One -TargetPid $ControlPid -OutFile "$DiagDir\control-exit.json" -PulseFile $monitorPulseFile
