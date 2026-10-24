$ErrorActionPreference = 'Stop'
node (Join-Path $PSScriptRoot 'test-rust.mjs') @args
exit $LASTEXITCODE
