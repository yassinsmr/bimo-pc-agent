# Eye diagnostic monitor (council 14, cycle 57, condition C2).
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
# Usage: pwsh -NoProfile -File diag-monitor.ps1 -EyePid <pid> -ControlPid <pid> -DiagDir <dir>
param(
  [int]$EyePid,
  [int]$ControlPid,
  [string]$DiagDir
)
$ErrorActionPreference = "Continue"

$startTs = [DateTimeOffset]::UtcNow
@{ monitor_pid = $PID; start_ts = $startTs.ToString("o"); eye_pid = $EyePid; control_pid = $ControlPid } | ConvertTo-Json | Out-File -FilePath "$DiagDir\monitor-started.json" -Encoding utf8

function Wait-One {
  param([int]$TargetPid, [string]$OutFile)
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
  $exited = $p.WaitForExit(150000)
  if ($exited) {
    $rec.exit_code = $p.ExitCode
    $rec.exit_ts = [DateTimeOffset]::UtcNow.ToString("o")
  } else {
    $rec.timed_out = $true
  }
  $rec | ConvertTo-Json | Out-File -FilePath $OutFile -Encoding utf8
}

# Eye first: it is the one expected to die early (~4 s). Then the
# control (45 s sleep): the monitor lives ~45 s total and is gone
# before the job ends.
Wait-One -TargetPid $EyePid -OutFile "$DiagDir\eye-exit.json"
Wait-One -TargetPid $ControlPid -OutFile "$DiagDir\control-exit.json"
