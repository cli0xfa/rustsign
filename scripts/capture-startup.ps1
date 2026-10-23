param(
    [string]$Executable = 'target/debug/rustsign.exe',
    [string]$Output = 'artifacts/startup-after.mp4',
    [ValidateSet('dark', 'light')][string]$Theme = 'dark',
    [switch]$Cold
)
$ErrorActionPreference = 'Stop'
$taskWorkspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskExecutable = [IO.Path]::GetFullPath((Join-Path $taskWorkspace $Executable))
$taskOutput = [IO.Path]::GetFullPath((Join-Path $taskWorkspace $Output))
$taskTemp = Join-Path ([IO.Path]::GetTempPath()) ('rustsign-capture-' + [guid]::NewGuid().ToString('N'))
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class RustSignCapture {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr handle, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr h, uint attr, out int value, int size);
    public static bool IsCloaked(IntPtr h) { int value; return DwmGetWindowAttribute(h, 14, out value, 4) == 0 && value != 0; }
}
'@
[RustSignCapture]::SetProcessDPIAware() | Out-Null
$taskPreviousData = $env:RUSTSIGN_DATA_DIR
$taskPreviousWebview = $env:WEBVIEW2_USER_DATA_FOLDER
$taskPreviousTheme = $env:RUSTSIGN_SMOKE_THEME
try {
    New-Item -ItemType Directory -Path $taskTemp -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path $taskOutput) -Force | Out-Null
    $env:RUSTSIGN_DATA_DIR = Join-Path $taskTemp 'data'
    $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $taskTemp 'webview'
    $env:RUSTSIGN_SMOKE_THEME = $Theme
    $taskProcess = Start-Process -FilePath $taskExecutable -WorkingDirectory $taskWorkspace -WindowStyle Hidden -PassThru
    $taskDeadline = [DateTime]::UtcNow.AddSeconds(20)
    $taskRect = New-Object RustSignCapture+RECT
    do {
        Start-Sleep -Milliseconds 50
        $taskProcess.Refresh()
        if ($taskProcess.HasExited -or [DateTime]::UtcNow -gt $taskDeadline) { throw 'Window did not appear.' }
        if ($taskProcess.MainWindowHandle -ne 0) { [RustSignCapture]::GetWindowRect($taskProcess.MainWindowHandle, [ref]$taskRect) | Out-Null }
    } while ($taskProcess.MainWindowHandle -eq 0 -or $taskProcess.MainWindowTitle -notmatch 'RustSign$' -or ($taskRect.Right - $taskRect.Left) -lt 500 -or [RustSignCapture]::IsCloaked($taskProcess.MainWindowHandle))
    [RustSignCapture]::GetWindowRect($taskProcess.MainWindowHandle, [ref]$taskRect) | Out-Null
    $taskProcess.CloseMainWindow() | Out-Null
    if (-not $taskProcess.WaitForExit(5000)) { $taskProcess.Kill(); $taskProcess.WaitForExit() }
    if ($Cold) { $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $taskTemp 'webview-cold' }
    $taskWidth = ($taskRect.Right - $taskRect.Left) -band -2
    $taskHeight = ($taskRect.Bottom - $taskRect.Top) -band -2
    $taskArguments = @('-hide_banner', '-loglevel', 'error', '-f', 'gdigrab', '-framerate', '60', '-offset_x', $taskRect.Left, '-offset_y', $taskRect.Top, '-video_size', "${taskWidth}x${taskHeight}", '-i', 'desktop', '-t', '5', '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p', '-y', "`"$taskOutput`"")
    $taskRecorder = Start-Process ffmpeg -ArgumentList $taskArguments -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 300
    $taskProcess = Start-Process -FilePath $taskExecutable -WorkingDirectory $taskWorkspace -WindowStyle Hidden -PassThru
    if (-not $taskRecorder.WaitForExit(15000)) { throw 'Recording timed out.' }
    if ($taskRecorder.ExitCode -ne 0) { throw 'Recording failed.' }
    Write-Output $taskOutput
    @{ theme = $Theme; coldProfile = [bool]$Cold; fps = 60; executable = $taskExecutable; width = $taskWidth; height = $taskHeight } | ConvertTo-Json | Set-Content ([IO.Path]::ChangeExtension($taskOutput, '.json'))
} finally {
    if ($taskProcess -and -not $taskProcess.HasExited) { $taskProcess.CloseMainWindow() | Out-Null; if (-not $taskProcess.WaitForExit(5000)) { $taskProcess.Kill(); $taskProcess.WaitForExit() } }
    if ($taskRecorder -and -not $taskRecorder.HasExited) { $taskRecorder.Kill() }
    $env:RUSTSIGN_DATA_DIR = $taskPreviousData
    $env:WEBVIEW2_USER_DATA_FOLDER = $taskPreviousWebview
    $env:RUSTSIGN_SMOKE_THEME = $taskPreviousTheme
    $taskResolved = [IO.Path]::GetFullPath($taskTemp)
    if (-not $taskResolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) { throw 'Capture data escaped the temporary directory.' }
    Remove-Item -LiteralPath $taskResolved -Recurse -Force -ErrorAction SilentlyContinue
}
