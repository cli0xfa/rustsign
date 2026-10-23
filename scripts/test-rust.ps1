$ErrorActionPreference = 'Stop'
$taskDataRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rustsign-tests-' + [guid]::NewGuid().ToString('N'))
$taskPreviousDataRoot = $env:RUSTSIGN_DATA_DIR
try {
    $env:RUSTSIGN_DATA_DIR = $taskDataRoot
    cargo test --package rustsign --lib --tests -- --test-threads=1
    $taskExitCode = $LASTEXITCODE
} finally {
    $env:RUSTSIGN_DATA_DIR = $taskPreviousDataRoot
    $taskResolvedRoot = [System.IO.Path]::GetFullPath($taskDataRoot)
    $taskTempParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $taskResolvedRoot.StartsWith($taskTempParent, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Test data root is outside the temporary directory.' }
    if (Test-Path -LiteralPath $taskResolvedRoot) { Remove-Item -LiteralPath $taskResolvedRoot -Recurse -Force }
}
exit $taskExitCode
