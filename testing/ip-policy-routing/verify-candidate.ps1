param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('plugins-ci', 'host-ci', 'e2e', 'performance')]
  [string]$Suite,
  [Parameter(Mandatory = $true)]
  [string]$HostRoot,
  [string]$PluginCommit = '',
  [string]$HostCommit = ''
)

$ErrorActionPreference = 'Stop'
$pluginRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$hostPath = (Resolve-Path $HostRoot).Path

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
  $configured = [Environment]::GetEnvironmentVariable('NRE_DATASET_SOURCE_CACHE')
  if (-not $configured) { throw 'NRE_DATASET_SOURCE_CACHE is required for this suite' }
  if (-not (Test-Path -LiteralPath $configured -PathType Container)) { throw 'NRE_DATASET_SOURCE_CACHE is not a directory' }
  $resolved = (Resolve-Path -LiteralPath $configured).Path
  foreach ($name in $RequiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $resolved $name) -PathType Leaf)) {
      throw "required pinned dataset is missing from NRE_DATASET_SOURCE_CACHE: $name"
    }
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
if (-not $IsLinux) { throw 'candidate verification requires Linux amd64' }
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') { throw 'candidate verification requires Linux amd64' }
Require-Tool docker
Invoke-Checked $pluginRoot docker @('info')
$drive = [System.IO.DriveInfo]::new((Get-Item -LiteralPath $pluginRoot).PSDrive.Root)
if ($drive.AvailableFreeSpace -lt 5GB) { throw 'candidate verification requires at least 5 GiB free disk space' }
$pluginOID = Resolve-Candidate $pluginRoot $PluginCommit
$hostOID = Resolve-Candidate $hostPath $HostCommit
Write-Host "plugins=$pluginOID host=$hostOID suite=$Suite"

switch ($Suite) {
  'plugins-ci' {
    Require-Tool make
    Invoke-Checked $pluginRoot make @('ci')
    Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'plugin', '--id', 'ip-policy')
    Invoke-Checked $pluginRoot go @('run', './cmd/nre-ci', 'plugin', '--id', 'shadowsocks-server')
  }
  'host-ci' {
    Invoke-Checked (Join-Path $hostPath 'go-agent') go @('test', '-p=16', '-count=1', '-timeout=30s', './internal/app', './internal/control', './internal/core', './internal/generation', './internal/model', './internal/module', './internal/modules/http', './internal/modules/l4', './internal/modules/relay', './internal/observability', './internal/plugins/hostapi', './internal/plugins/policy', './internal/plugins/process', './internal/plugins/rpc', './internal/plugins/wasm')
    Invoke-Checked (Join-Path $hostPath 'go-agent') go @('test', '-p=16', '-tags=integration', '-count=1', '-timeout=180s', '-run', '^TestIntegration', './embedded', './internal/app', './internal/core', './internal/plugins/process', './internal/plugins/rpc')
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
