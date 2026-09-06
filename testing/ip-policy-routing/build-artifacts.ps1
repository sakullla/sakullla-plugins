$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$output = Join-Path $root 'dist/bin'
$null = New-Item -ItemType Directory -Force -Path $output

Push-Location $root
try {
  & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o (Join-Path $output 'nre-ci') ./cmd/nre-ci
  if ($LASTEXITCODE -ne 0) { throw "build nre-ci failed with exit code $LASTEXITCODE" }
  & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o (Join-Path $output 'nre-package') ./cmd/nre-package
  if ($LASTEXITCODE -ne 0) { throw "build nre-package failed with exit code $LASTEXITCODE" }
  & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o (Join-Path $output 'nre-market') ./cmd/nre-market
  if ($LASTEXITCODE -ne 0) { throw "build nre-market failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}
