param([string]$Executable = 'target/debug/rustsign.exe')
$ErrorActionPreference = 'Stop'
$taskWorkspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskTemp = Join-Path ([IO.Path]::GetTempPath()) ('rustsign-chrome-' + [guid]::NewGuid().ToString('N'))
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class RustSignChromeTest {
    public delegate bool EnumProc(IntPtr h, IntPtr p);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc callback, IntPtr p);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder name, int size);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT point);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT p);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint message, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint message, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint x, uint y, uint data, UIntPtr extra);
    [DllImport("user32.dll")] public static extern void keybd_event(byte key, byte scan, uint flags, UIntPtr extra);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
}
'@
[RustSignChromeTest]::SetProcessDPIAware() | Out-Null
$taskPreviousData = $env:RUSTSIGN_DATA_DIR
$taskPreviousWebview = $env:WEBVIEW2_USER_DATA_FOLDER
$taskCursor = New-Object RustSignChromeTest+POINT
[RustSignChromeTest]::GetCursorPos([ref]$taskCursor) | Out-Null
function Get-SnapRegion($taskHandle) {
    $script:taskSnap = [IntPtr]::Zero
    $taskCallback = [RustSignChromeTest+EnumProc] {
        param($taskChild, $taskUnused)
        $taskName = New-Object Text.StringBuilder 128
        [RustSignChromeTest]::GetClassName($taskChild, $taskName, 128) | Out-Null
        if ($taskName.ToString() -eq 'RustSignSnapRegion') { $script:taskSnap = $taskChild }
        return $true
    }
    [RustSignChromeTest]::EnumChildWindows($taskHandle, $taskCallback, [IntPtr]::Zero) | Out-Null
    if ($script:taskSnap -eq [IntPtr]::Zero) { throw 'Native Snap region not found.' }
    $taskRegion = New-Object RustSignChromeTest+RECT
    [RustSignChromeTest]::GetWindowRect($script:taskSnap, [ref]$taskRegion) | Out-Null
    return $taskRegion
}
function Move-ToRegion($taskRegion) {
    $taskPoint = New-Object RustSignChromeTest+POINT
    $taskPoint.X = [int](($taskRegion.Left + $taskRegion.Right) / 2)
    $taskPoint.Y = [int](($taskRegion.Top + $taskRegion.Bottom) / 2)
    if (-not [RustSignChromeTest]::SetCursorPos($taskPoint.X, $taskPoint.Y)) { return $false }
    $taskActual = New-Object RustSignChromeTest+POINT
    [RustSignChromeTest]::GetCursorPos([ref]$taskActual) | Out-Null
    if ($taskActual.X -ne $taskPoint.X -or $taskActual.Y -ne $taskPoint.Y) { return $false }
    if ([RustSignChromeTest]::WindowFromPoint($taskPoint) -ne $script:taskSnap) { throw 'Snap region is not receiving native mouse input.' }
    return $true
}
function Click-Region($taskRegion, $taskPhysical) {
    if ($taskPhysical) {
        [RustSignChromeTest]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 100
        [RustSignChromeTest]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
    } else {
        $taskX = [int](($taskRegion.Left + $taskRegion.Right) / 2)
        $taskY = [int](($taskRegion.Top + $taskRegion.Bottom) / 2)
        $taskPoint = [IntPtr](([int64]($taskY -band 65535) -shl 16) -bor ($taskX -band 65535))
        [RustSignChromeTest]::SendMessage($script:taskSnap, 0xA1, [IntPtr]9, $taskPoint) | Out-Null
        [RustSignChromeTest]::SendMessage($script:taskSnap, 0xA2, [IntPtr]9, $taskPoint) | Out-Null
    }
}
try {
    New-Item -ItemType Directory -Path $taskTemp -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $taskWorkspace 'artifacts') -Force | Out-Null
    $env:RUSTSIGN_DATA_DIR = Join-Path $taskTemp 'data'
    $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $taskTemp 'webview'
    $taskProcess = Start-Process -FilePath (Join-Path $taskWorkspace $Executable) -WorkingDirectory $taskWorkspace -WindowStyle Hidden -PassThru
    $taskDeadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 50
        $taskProcess.Refresh()
        if ($taskProcess.HasExited -or [DateTime]::UtcNow -gt $taskDeadline) { throw 'Window did not appear.' }
    } while ($taskProcess.MainWindowHandle -eq 0 -or $taskProcess.MainWindowTitle -notmatch 'RustSign$')
    $taskHandle = $taskProcess.MainWindowHandle
    [RustSignChromeTest]::SetForegroundWindow($taskHandle) | Out-Null
    $taskRegion = Get-SnapRegion $taskHandle
    $taskPhysical = Move-ToRegion $taskRegion
    Start-Sleep -Milliseconds 1200
    $taskBounds = New-Object RustSignChromeTest+RECT
    [RustSignChromeTest]::GetWindowRect($taskHandle, [ref]$taskBounds) | Out-Null
    $taskWidth = ($taskBounds.Right - $taskBounds.Left) -band -2
    $taskHeight = [Math]::Min(($taskBounds.Bottom - $taskBounds.Top), 650) -band -2
    $taskImage = if ($taskPhysical) { 'artifacts/native-snap-layout.png' } else { 'artifacts/native-window.png' }
    & ffmpeg -hide_banner -loglevel error -f gdigrab -offset_x $taskBounds.Left -offset_y $taskBounds.Top -video_size "${taskWidth}x${taskHeight}" -i desktop -frames:v 1 -y (Join-Path $taskWorkspace $taskImage)
    if (-not $taskPhysical) {
        $taskReport = @{ success = $null; skipped = $true; physicalInput = $false; dpi = [RustSignChromeTest]::GetDpiForWindow($taskHandle); monitors = [RustSignChromeTest]::GetSystemMetrics(80); reason = 'The active Windows input desktop rejected SetCursorPos. Run on an unlocked interactive desktop to verify the physical Snap flyout. In-process caption messages are covered by test:native.' }
        $taskReport | ConvertTo-Json | Set-Content (Join-Path $taskWorkspace 'artifacts/window-chrome.json')
        $taskReport | ConvertTo-Json
        return
    }
    Click-Region $taskRegion $taskPhysical
    Start-Sleep -Milliseconds 350
    if (-not [RustSignChromeTest]::IsZoomed($taskHandle)) { throw 'Native maximize click did not maximize exactly once.' }
    $taskRegion = Get-SnapRegion $taskHandle
    $taskPhysical = (Move-ToRegion $taskRegion) -and $taskPhysical
    Click-Region $taskRegion $taskPhysical
    Start-Sleep -Milliseconds 350
    if ([RustSignChromeTest]::IsZoomed($taskHandle)) { throw 'Native restore click did not restore exactly once.' }
    # Send the same system command as Alt+Space without invoking a host's
    # global launcher shortcut (for example PowerToys Run).
    [RustSignChromeTest]::PostMessage($taskHandle, 0x112, [IntPtr]0xF100, [IntPtr]32) | Out-Null
    Start-Sleep -Milliseconds 250
    & ffmpeg -hide_banner -loglevel error -f gdigrab -offset_x $taskBounds.Left -offset_y $taskBounds.Top -video_size "${taskWidth}x${taskHeight}" -i desktop -frames:v 1 -y (Join-Path $taskWorkspace 'artifacts/native-window-menu.png')
    [RustSignChromeTest]::keybd_event(0x1B, 0, 0, [UIntPtr]::Zero)
    [RustSignChromeTest]::keybd_event(0x1B, 0, 2, [UIntPtr]::Zero)
    $taskReport = @{ success = $true; physicalInput = $taskPhysical; dpi = [RustSignChromeTest]::GetDpiForWindow($taskHandle); monitors = [RustSignChromeTest]::GetSystemMetrics(80); checks = @('Native caption messages maximize and restore exactly once', 'Native system-menu request screenshot saved'); limitation = $(if ($taskPhysical) { $null } else { 'Active input desktop rejected SetCursorPos; physical hover/Snap flyout not verified.' }) }
    $taskReport | ConvertTo-Json | Set-Content (Join-Path $taskWorkspace 'artifacts/window-chrome.json')
    $taskReport | ConvertTo-Json
} finally {
    if ($taskProcess -and -not $taskProcess.HasExited) { $taskProcess.CloseMainWindow() | Out-Null; if (-not $taskProcess.WaitForExit(5000)) { $taskProcess.Kill(); $taskProcess.WaitForExit() } }
    [RustSignChromeTest]::SetCursorPos($taskCursor.X, $taskCursor.Y) | Out-Null
    $env:RUSTSIGN_DATA_DIR = $taskPreviousData
    $env:WEBVIEW2_USER_DATA_FOLDER = $taskPreviousWebview
    $taskResolved = [IO.Path]::GetFullPath($taskTemp)
    if (-not $taskResolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) { throw 'Test data escaped the temporary directory.' }
    Remove-Item -LiteralPath $taskResolved -Recurse -Force -ErrorAction SilentlyContinue
}
