param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('plugins-ci', 'host-ci', 'e2e', 'performance')]
  [string]$Suite,
  [Parameter(Mandatory = $true)]
  [string]$HostRoot,
  [string]$PluginCommit = '',
  [string]$HostCommit = '',
  [string]$DatasetCache = ''
)

$ErrorActionPreference = 'Stop'
$pluginRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$hostPath = (Resolve-Path $HostRoot).Path
$datasetSources = @(
  [pscustomobject]@{ Name = 'geoip.dat'; URL = 'https://github.com/v2fly/geoip/releases/download/202609040609/geoip.dat'; SHA256 = '1cba1f0982cf62502fa079c66047c3d0c608196da5b3305671e68f60e917a482' },
  [pscustomobject]@{ Name = 'dlc.dat'; URL = 'https://github.com/v2fly/domain-list-community/releases/download/20260904020013/dlc.dat'; SHA256 = 'f82f26c015f9726c763d96a5f658e5b31b285dc094a985e718051e421f350ed6' },
  [pscustomobject]@{ Name = 'dlc.tar.gz'; URL = 'https://codeload.github.com/v2fly/domain-list-community/tar.gz/cb663f66025ef3be1c1c7eb367dfac5f46645ffc'; SHA256 = 'ce78b02633037eb64b034564bb7c8244e90d9b1335298b7b91057ff9f8d5ab25' },
  [pscustomobject]@{ Name = 'dlc.zip'; URL = 'https://codeload.github.com/v2fly/domain-list-community/zip/cb663f66025ef3be1c1c7eb367dfac5f46645ffc'; SHA256 = '842ab69a418901bfa34c32c465bdf5cb8af935a474fcbc6854dc0325ab381a30' },
  [pscustomobject]@{ Name = 'loyalsoldier-geoip.dat'; URL = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202609042338/geoip.dat'; SHA256 = '4149e607530f91da697bad4696f8c59f0a475af38e69405e4124438c9886c721' },
  [pscustomobject]@{ Name = 'loyalsoldier-geosite.dat'; URL = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202609042338/geosite.dat'; SHA256 = 'bca29c80611ee4b909ecc0bd531cf05901b1502998d88bf01580152ffc9e260b' },
  [pscustomobject]@{ Name = 'dbip-city-lite-2026-09.mmdb.gz'; URL = 'https://download.db-ip.com/free/dbip-city-lite-2026-09.mmdb.gz'; SHA256 = 'c5d05b35a45c3eea0cadc728c8f5ad751693d4e270529b731442172a73f05954' }
)

function Require-Tool([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "required tool is missing: $Name" }
}

function Invoke-Checked([string]$WorkingDirectory, [string]$File, [string[]]$Arguments) {
  Push-Location $WorkingDirectory
  try {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
  } finally { Pop-Location }
}

function Resolve-Candidate([string]$Root, [string]$Requested) {
  if ((& git -C $Root status --porcelain).Count -ne 0) { throw "candidate worktree is dirty: $Root" }
  $head = (& git -C $Root rev-parse HEAD).Trim()
  $candidate = if ($Requested) { $Requested } else { $head }
  $commit = (& git -C $Root rev-parse --verify "$candidate`^{commit}").Trim()
  if ($LASTEXITCODE -ne 0 -or -not $commit) { throw "candidate commit is invalid: $Requested" }
  if ($commit -ne $head) { throw "requested candidate must equal clean HEAD: requested=$commit HEAD=$head" }
  return $commit
}

function Invoke-GoSelection([string]$WorkingDirectory, [string[]]$Prefix, [string]$Pattern, [string[]]$Packages) {
  Push-Location $WorkingDirectory
  try {
    $listed = & go test @Prefix -list $Pattern @Packages 2>&1
    if ($LASTEXITCODE -ne 0) { throw "go test -list failed: $listed" }
    if (-not ($listed -match '(?m)^Test')) { throw "focused selector matched zero tests: $Pattern" }
    & go test @Prefix -run $Pattern @Packages
    if ($LASTEXITCODE -ne 0) { throw "focused go test failed: $Pattern" }
  } finally { Pop-Location }
}

function Invoke-DockerGoSelection([string]$Image, [string[]]$Mounts, [string]$WorkDir, [string[]]$Environment, [string[]]$Prefix, [string]$Pattern, [string[]]$Packages) {
  $common = @('run', '--rm', '--privileged')
  foreach ($mount in $Mounts) { $common += @('-v', $mount) }
  foreach ($item in $Environment) { $common += @('-e', $item) }
  $common += @('-w', $WorkDir, $Image, 'go', 'test')
  $listed = & docker @common @Prefix -list $Pattern @Packages 2>&1
  if ($LASTEXITCODE -ne 0) { throw "docker go test -list failed: $listed" }
  if (-not ($listed -match '(?m)^Test')) { throw "docker focused selector matched zero tests: $Pattern" }
  & docker @common @Prefix -run $Pattern @Packages
  if ($LASTEXITCODE -ne 0) { throw "docker focused go test failed: $Pattern" }
}

function Invoke-DockerPerformanceSelection([string]$Image, [string[]]$Mounts, [string]$WorkDir, [string[]]$Environment, [string[]]$Prefix, [string]$Pattern, [string[]]$Packages) {
  $common = @('run', '--rm', '--privileged')
  foreach ($mount in $Mounts) { $common += @('-v', $mount) }
  foreach ($item in $Environment) { $common += @('-e', $item) }
  $common += @('-w', $WorkDir, $Image, 'go', 'test')
  $listed = & docker @common @Prefix -list $Pattern @Packages 2>&1
  if ($LASTEXITCODE -ne 0) { throw "docker performance test -list failed: $listed" }
  if (-not ($listed -match '(?m)^Test')) { throw "docker performance selector matched zero tests: $Pattern" }

  $output = & docker @common @Prefix -v -run $Pattern @Packages 2>&1
  $exitCode = $LASTEXITCODE
  $text = $output -join [Environment]::NewLine
  Write-Host $text
  if ($exitCode -ne 0) { throw "docker performance test failed: $Pattern" }

  $metricPattern = '(?m)^NRE_SS_PERF_JSON=(?<json>\{.*\})\r?$'
  $metricMatches = [regex]::Matches($text, $metricPattern)
  if ($metricMatches.Count -ne 1) { throw "performance workload emitted $($metricMatches.Count) metric records, want exactly one" }
  $metrics = $metricMatches[0].Groups['json'].Value | ConvertFrom-Json
  $samples = @($metrics.raw_latency_ns)
  if ($samples.Count -ne 20) { throw "performance workload emitted $($samples.Count) raw latency samples, want 20" }
  if (($samples | Where-Object { $_ -le 0 }).Count -ne 0 -or $metrics.throughput_per_sec -le 0 -or $metrics.rss_bytes -le 0) {
    throw 'performance workload emitted non-positive latency, throughput or RSS'
  }
  $sortedSamples = @($samples | Sort-Object)
  if ($metrics.p95_ns -ne $sortedSamples[18] -or $metrics.p99_ns -ne $sortedSamples[19]) { throw 'performance percentile evidence does not match raw latency samples' }
  if ($metrics.rss_bytes -gt 256MB -or $metrics.p99_ns -gt 500000000) { throw 'performance workload exceeded RSS or p99 bound' }
  if ($metrics.dataset_count -ne 2 -or @($metrics.candidate_refs).Count -ne 2) { throw 'performance workload omitted dataset or candidate identity evidence' }
  if (-not $metrics.dataset_digests.'dlc.dat' -or -not $metrics.dataset_digests.'loyalsoldier-geoip.dat') { throw 'performance workload omitted pinned dataset digests' }
  Write-Host ("ss-route-performance=" + ($metrics | ConvertTo-Json -Compress))
}

function Resolve-DatasetCache([string[]]$RequiredFiles) {
  $configured = $DatasetCache
  if (-not $configured) {
    $temporaryRoot = if ($env:TEMP) { $env:TEMP } else { [IO.Path]::GetTempPath() }
    $configured = Join-Path $temporaryRoot 'nre-dataset-source-cache'
  }
  $null = New-Item -ItemType Directory -Force -Path $configured
  $resolved = (Resolve-Path -LiteralPath $configured).Path
  foreach ($name in $RequiredFiles) {
    $source = @($datasetSources | Where-Object { $_.Name -eq $name })
    if ($source.Count -ne 1) { throw "unknown pinned dataset: $name" }
    $path = Join-Path $resolved $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      $partial = "$path.partial-$([guid]::NewGuid().ToString('N'))"
      try {
        Write-Host "download pinned dataset $name"
        Invoke-WebRequest -Uri $source[0].URL -OutFile $partial -MaximumRedirection 5 -TimeoutSec 300
        $length = (Get-Item -LiteralPath $partial).Length
        $digest = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($length -le 0 -or $length -gt 128MB) { throw "pinned dataset size is invalid for ${name}: $length" }
        if ($digest -ne $source[0].SHA256) { throw "pinned dataset digest mismatch for ${name}: $digest" }
        Move-Item -LiteralPath $partial -Destination $path
      } finally {
        if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
      }
    }
    $length = (Get-Item -LiteralPath $path).Length
    $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($length -le 0 -or $length -gt 128MB) { throw "cached dataset size is invalid for ${name}: $length" }
    if ($digest -ne $source[0].SHA256) { throw "cached dataset digest mismatch for ${name}: $digest" }
  }
  return $resolved
}

function Build-IPPolicyArtifact {
  Require-Tool cargo
  Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'plugin', '--id', 'ip-policy')
  $artifact = Join-Path $pluginRoot 'target/nre-ci/ip-policy/plugin.wasm'
  if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { throw "IP policy build did not produce $artifact" }
  return $artifact
}

Require-Tool git
Require-Tool go
if (-not ($IsLinux -or $IsWindows)) { throw 'candidate verification requires Linux or Windows x64' }
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') { throw 'candidate verification requires x64' }
Require-Tool docker
Invoke-Checked $pluginRoot docker @('info')
$drive = [System.IO.DriveInfo]::new((Get-Item -LiteralPath $pluginRoot).PSDrive.Root)
if ($drive.AvailableFreeSpace -lt 5GB) { throw 'candidate verification requires at least 5 GiB free disk space' }
$pluginOID = Resolve-Candidate $pluginRoot $PluginCommit
$hostOID = Resolve-Candidate $hostPath $HostCommit
Write-Host "plugins=$pluginOID host=$hostOID suite=$Suite"

switch ($Suite) {
  'plugins-ci' {
    if ($IsLinux) {
      Require-Tool make
      Invoke-Checked $pluginRoot make @('ci')
    } else {
      Require-Tool cargo
      Require-Tool pwsh
      Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'sdk', '--require-host-capabilities')
      Invoke-Checked $pluginRoot go @('test', './...')
      Invoke-Checked $pluginRoot cargo @('test', '--workspace', '--locked')
      Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'reproducible', '--root', '.', '--output', 'dist', '--', 'pwsh', '-NoProfile', '-File', 'testing/ip-policy-routing/build-artifacts.ps1')
      Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'repository', '--root', '.')
    }
    Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'plugin', '--id', 'ip-policy')
    Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'plugin', '--id', 'shadowsocks-server')
  }
  'host-ci' {
    Invoke-Checked (Join-Path $hostPath 'go-agent') go @('test', '-p=16', '-count=1', '-timeout=30s', './internal/app', './internal/control', './internal/core', './internal/generation', './internal/model', './internal/module', './internal/modules/http', './internal/modules/l4', './internal/modules/relay', './internal/observability', './internal/plugins/hostapi', './internal/plugins/policy', './internal/plugins/process', './internal/plugins/rpc', './internal/plugins/wasm')
    if ($IsWindows) {
      Invoke-DockerGoSelection -Image 'golang:1.27.0-trixie' -Mounts @("${hostPath}:/host:ro") -WorkDir '/host/go-agent' -Environment @() -Prefix @('-p=16', '-tags=integration', '-count=1', '-timeout=180s') -Pattern '^TestIntegration' -Packages @('./embedded', './internal/app', './internal/core', './internal/plugins/process', './internal/plugins/rpc')
    } else {
      Invoke-Checked (Join-Path $hostPath 'go-agent') go @('test', '-p=16', '-tags=integration', '-count=1', '-timeout=180s', '-run', '^TestIntegration', './embedded', './internal/app', './internal/core', './internal/plugins/process', './internal/plugins/rpc')
    }
    Invoke-Checked (Join-Path $hostPath 'panel/backend-go') go @('test', '-p=16', '-count=1', '-timeout=30s', './cmd/nre-control-plane', './internal/controlplane/config', './internal/controlplane/http', './internal/controlplane/localagent', './internal/controlplane/pluginhost', './internal/controlplane/service', './internal/controlplane/storage')
    Require-Tool npm
    Invoke-Checked (Join-Path $hostPath 'panel/frontend') npm @('test')
    Invoke-Checked (Join-Path $hostPath 'panel/frontend') npm @('run', 'build')
    $image = "nre-candidate:$($hostOID.Substring(0,12))"
    try { Invoke-Checked $hostPath docker @('build', '--pull=false', '--tag', $image, '.') }
    finally { & docker image rm --force $image | Out-Null }
  }
  'e2e' {
    $null = Build-IPPolicyArtifact
    $sourceCache = Resolve-DatasetCache @('dlc.dat', 'loyalsoldier-geoip.dat')
    Invoke-GoSelection -WorkingDirectory $pluginRoot -Prefix @('-count=1', '-timeout=180s') -Pattern 'IPPolicy|Managed|Routing|Sniff|TCPHandler|UDPUpstream' -Packages @('./plugins/ip-policy', './plugins/shadowsocks-server', './testing/integration/ip-policy', './testing/integration/shadowsocks-server')
    Invoke-DockerGoSelection -Image 'golang:1.27.0-trixie' -Mounts @("${pluginRoot}:/plugins:ro", "${hostPath}:/host:ro", "${sourceCache}:/dataset-cache:ro") -WorkDir '/host/go-agent' -Environment @('NRE_SS_PLUGIN_ROOT=/plugins', 'NRE_IP_POLICY_WASM=/plugins/target/nre-ci/ip-policy/plugin.wasm', 'NRE_DATASET_SOURCE_CACHE=/dataset-cache') -Prefix @('-tags=integration,ssplugin', '-count=1', '-timeout=180s') -Pattern '^TestIntegrationRealShadowsocksDatasetSniffAndIPPolicy$' -Packages @('./internal/plugins/rpc')
  }
  'performance' {
    $sourceCache = Resolve-DatasetCache @('geoip.dat', 'dlc.dat', 'dlc.tar.gz', 'dlc.zip', 'loyalsoldier-geoip.dat', 'loyalsoldier-geosite.dat', 'dbip-city-lite-2026-09.mmdb.gz')
    $null = Build-IPPolicyArtifact
    $mounts = @("${pluginRoot}:/plugins:ro", "${hostPath}:/host:ro", "${sourceCache}:/dataset-cache:ro")
    Invoke-DockerGoSelection -Image 'golang:1.27.0-trixie' -Mounts $mounts -WorkDir '/host/go-agent' -Environment @('NRE_DATASET_SOURCE_CACHE=/dataset-cache') -Prefix @('-tags=integration', '-count=1', '-timeout=300s') -Pattern '^TestIntegrationDatasetSources$' -Packages @('./pkg/datasets')
    Invoke-DockerPerformanceSelection -Image 'golang:1.27.0-trixie' -Mounts $mounts -WorkDir '/host/go-agent' -Environment @('NRE_SS_PLUGIN_ROOT=/plugins', 'NRE_IP_POLICY_WASM=/plugins/target/nre-ci/ip-policy/plugin.wasm', 'NRE_DATASET_SOURCE_CACHE=/dataset-cache', 'NRE_SS_PERF=1') -Prefix @('-tags=integration,ssplugin', '-count=1', '-timeout=300s') -Pattern '^TestIntegrationRealShadowsocksDatasetSniffAndIPPolicy$' -Packages @('./internal/plugins/rpc')
  }
}
