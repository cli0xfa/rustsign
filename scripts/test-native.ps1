$ErrorActionPreference = 'Stop'
$taskWorkspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rustsign-native-' + [guid]::NewGuid().ToString('N'))
$taskReport = Join-Path $taskWorkspace 'artifacts/native-smoke.json'
$taskPrevious = @{}
$taskNames = @('RUSTSIGN_DATA_DIR', 'RUSTSIGN_SMOKE_RESULT', 'RUSTSIGN_SMOKE_FILE', 'RUSTSIGN_SMOKE_CERT', 'WEBVIEW2_USER_DATA_FOLDER')
foreach ($taskName in $taskNames) { $taskPrevious[$taskName] = [Environment]::GetEnvironmentVariable($taskName, 'Process') }
try {
    New-Item -ItemType Directory -Path $taskRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $taskWorkspace 'artifacts') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $taskWorkspace 'test_data/test_hello.exe') -Destination (Join-Path $taskRoot 'client.exe')
    $env:RUSTSIGN_DATA_DIR = Join-Path $taskRoot 'data'
    $env:RUSTSIGN_SMOKE_RESULT = $taskReport
    $env:RUSTSIGN_SMOKE_FILE = Join-Path $taskRoot 'client.exe'
    $env:RUSTSIGN_SMOKE_CERT = Join-Path $taskWorkspace 'test_data/test_combined.pem'
    $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $taskRoot 'webview'
    cargo build --package rustsign --bin rustsign --features desktop-smoke
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (Test-Path -LiteralPath $taskReport) { Remove-Item -LiteralPath $taskReport -Force }
    $taskProcess = Start-Process -FilePath (Join-Path $taskWorkspace 'target/debug/rustsign.exe') -WorkingDirectory $taskWorkspace -WindowStyle Hidden -PassThru
    if (-not $taskProcess.WaitForExit(90000)) { $taskProcess.Kill(); throw 'Native smoke test timed out.' }
    $taskProcess.Refresh()
    $taskReportText = Get-Content -LiteralPath $taskReport -Raw
    Write-Output $taskReportText
    $taskReportData = $taskReportText | ConvertFrom-Json
    $taskExitCode = if ($taskReportData.success) { 0 } else { 1 }
} finally {
    foreach ($taskName in $taskNames) { [Environment]::SetEnvironmentVariable($taskName, $taskPrevious[$taskName], 'Process') }
    $taskResolvedRoot = [System.IO.Path]::GetFullPath($taskRoot)
    $taskTempParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $taskResolvedRoot.StartsWith($taskTempParent, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Native test data is outside the temporary directory.' }
    if (Test-Path -LiteralPath $taskResolvedRoot) { Remove-Item -LiteralPath $taskResolvedRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
exit $taskExitCode
