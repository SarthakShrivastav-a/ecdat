# Records an actual `ecdat scan` running in its own console window.
#
#   powershell -ExecutionPolicy Bypass -File media\record_terminal.ps1
#
# Windows Terminal absorbs a plain `cmd` into an existing tab, which would put unrelated work on
# screen, so we force a brand-new window (`wt -w -1`), park it at a known rectangle, and crop the
# desktop capture to exactly that rectangle. Nothing else on the desktop is recorded.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$raw = Join-Path $PSScriptRoot "raw"
New-Item -ItemType Directory -Force $raw | Out-Null
$out = Join-Path $raw "terminal.mp4"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int t, bool repaint);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

$py = "C:\customize\SIH2026\demo\ecdat\.venv\Scripts\python.exe"
$mark = "ECDAT-SCAN-CAPTURE"
$inner = "title $mark & cd /d `"$root`" & set COLUMNS=100 & cls & " +
         "`"$py`" -m ecdat.cli scan -c tests/fixtures/zoo/ecdat.yaml -o out/demo --no-external-tools & timeout /t 6 > nul"

# -w -1 = always a new window, never a tab in an existing one
Start-Process wt.exe -ArgumentList "-w", "-1", "--title", $mark, "cmd.exe", "/c", $inner
Start-Sleep -Seconds 5

$proc = Get-Process WindowsTerminal -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowTitle -like "*$mark*" } |
        Sort-Object StartTime -Descending | Select-Object -First 1
if (-not $proc) { throw "could not find the capture window" }
$h = $proc.MainWindowHandle
[void][Win]::MoveWindow($h, 80, 60, 1160, 880, $true)
[void][Win]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 900

$r = New-Object Win+RECT
[void][Win]::GetWindowRect($h, [ref]$r)
$w = [math]::Floor(($r.Right - $r.Left) / 2) * 2
$ht = [math]::Floor(($r.Bottom - $r.Top) / 2) * 2
Write-Output "capturing ${w}x${ht} at $($r.Left),$($r.Top) (window: $($proc.MainWindowTitle))"

& ffmpeg -hide_banner -loglevel error -f gdigrab -framerate 12 `
    -offset_x $r.Left -offset_y $r.Top -video_size "${w}x${ht}" -i desktop `
    -t 60 -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p -y $out
Write-Output "wrote $out"
