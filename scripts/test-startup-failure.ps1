$ErrorActionPreference = 'Stop'
$taskWorkspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskTemp = Join-Path ([IO.Path]::GetTempPath()) ('rustsign-startup-failure-' + [guid]::NewGuid().ToString('N'))
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class RustSignStartupFailure {
    private delegate bool EnumProc(IntPtr h, IntPtr p);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc callback, IntPtr p);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr h, StringBuilder name, int length);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);
    public static IntPtr Find(uint pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h,p)=> {
            uint owner; GetWindowThreadProcessId(h, out owner);
            var name = new StringBuilder(256); GetWindowText(h, name, 256);
            if(owner == pid && IsWindowVisible(h) && name.ToString().Contains("Startup failed")) found = h;
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@
[RustSignStartupFailure]::SetProcessDPIAware() | Out-Null
$taskNames = @('RUSTSIGN_DATA_DIR', 'WEBVIEW2_USER_DATA_FOLDER', 'RUSTSIGN_SMOKE_STALL_STARTUP')
$taskPrevious = @{}
foreach ($taskName in $taskNames) { $taskPrevious[$taskName] = [Environment]::GetEnvironmentVariable($taskName, 'Process') }
try {
    New-Item -ItemType Directory -Path $taskTemp -Force | Out-Null
    $env:RUSTSIGN_DATA_DIR = Join-Path $taskTemp 'data'
    $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $taskTemp 'webview'
    $env:RUSTSIGN_SMOKE_STALL_STARTUP = '1'
    $taskWatch = [Diagnostics.Stopwatch]::StartNew()
    $taskProcess = Start-Process -FilePath (Join-Path $taskWorkspace 'target/debug/rustsign.exe') -WorkingDirectory $taskWorkspace -WindowStyle Hidden -PassThru
    do {
        Start-Sleep -Milliseconds 100
        if ($taskProcess.HasExited -or $taskWatch.Elapsed.TotalSeconds -gt 25) { throw 'Native startup watchdog did not show its error dialog.' }
        $taskDialog = [RustSignStartupFailure]::Find($taskProcess.Id)
    } while ($taskDialog -eq [IntPtr]::Zero)
    $taskRect = New-Object RustSignStartupFailure+RECT
    [RustSignStartupFailure]::GetWindowRect($taskDialog, [ref]$taskRect) | Out-Null
    $taskWidth = ($taskRect.Right - $taskRect.Left) -band -2
    $taskHeight = ($taskRect.Bottom - $taskRect.Top) -band -2
    & ffmpeg -hide_banner -loglevel error -f gdigrab -offset_x $taskRect.Left -offset_y $taskRect.Top -video_size "${taskWidth}x${taskHeight}" -i desktop -frames:v 1 -y (Join-Path $taskWorkspace 'artifacts/startup-failure.png')
    $taskReport = @{ success = $true; elapsedSeconds = [Math]::Round($taskWatch.Elapsed.TotalSeconds, 2); check = 'Missing frontend handshake exposes the native Reload / Exit dialog instead of leaving an invisible process.' }
    $taskReport | ConvertTo-Json | Set-Content (Join-Path $taskWorkspace 'artifacts/startup-failure.json')
    $taskReport | ConvertTo-Json
} finally {
    if ($taskProcess -and -not $taskProcess.HasExited) { $taskProcess.Kill(); $taskProcess.WaitForExit() }
    foreach ($taskName in $taskNames) { [Environment]::SetEnvironmentVariable($taskName, $taskPrevious[$taskName], 'Process') }
    $taskResolved = [IO.Path]::GetFullPath($taskTemp)
    if (-not $taskResolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) { throw 'Test data escaped the temporary directory.' }
    Remove-Item -LiteralPath $taskResolved -Recurse -Force -ErrorAction SilentlyContinue
}
