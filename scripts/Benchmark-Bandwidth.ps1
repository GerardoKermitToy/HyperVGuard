[CmdletBinding()]
param(
    [ValidateRange(128, 10000000)][int]$Records = 1000000,
    [ValidateRange(1, 10000000)][int]$Flows = 250000,
    [ValidateRange(1, 31)][int]$Rounds = 3,
    [ValidateRange(1, 64)][int]$Interfaces = 1,
    [UInt64]$Seed = 5213270986485678420,
    [ValidateSet('realistic', 'unique')][string]$Scenario = 'realistic',
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$PfxPath,
    [Parameter(Mandatory = $true)][string]$RootCertificate,
    [string]$PfxPassword = $(if ($env:HYPERVXNDISFILTER_PFX_PASSWORD) { $env:HYPERVXNDISFILTER_PFX_PASSWORD } else { '1' }),
    [string]$SdkVersion = '10.0.28000.0'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if ($Flows -gt $Records) { throw 'Flows must not exceed Records.' }
$signTool = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\$SdkVersion\x64\signtool.exe"
if (!(Test-Path -LiteralPath $signTool)) { throw 'Windows SDK signtool is required.' }
$PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
$RootCertificate = (Resolve-Path -LiteralPath $RootCertificate).Path
if (!$OutputDirectory) {
    $OutputDirectory = Join-Path $root ('build\bandwidth-bench\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
}
if ((Test-Path -LiteralPath $OutputDirectory) -and (Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1)) {
    throw 'Use a new/empty output directory; prior results are never overwritten.'
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$oldFlags = $env:RUSTFLAGS
$oldEncodedFlags = $env:CARGO_ENCODED_RUSTFLAGS
$oldDir = Get-Location
try {
    Set-Location $root
    # User-mode example only. No kernel/package build or installation occurs.
    $env:RUSTFLAGS = '-C no-redzone=yes -C debuginfo=2'
    $env:CARGO_ENCODED_RUSTFLAGS = $null
    & cargo build --release -p hyperv-policy --example bandwidth_stats_bench --locked
    if ($LASTEXITCODE) { throw 'Bandwidth benchmark build failed.' }
    $exe = Join-Path $root 'target\release\examples\bandwidth_stats_bench.exe'
    # Use existing signing material in place; no key copy, certificate import,
    # network timestamp request, trust-store change, or production device access.
    & $signTool sign /fd SHA256 /f $PfxPath /p $PfxPassword /ac $RootCertificate $exe
    if ($LASTEXITCODE) { throw 'Bandwidth benchmark signing failed.' }
    & $signTool verify /pa $exe
    if ($LASTEXITCODE) { throw 'Bandwidth benchmark signature verification failed.' }
    $sources = @(
        'Cargo.toml',
        'policy\examples\bandwidth_stats_bench.rs',
        'policy\examples\bandwidth_stats_bench\indexed.rs',
        'policy\src\engine.rs',
        'policy\src\bandwidth.rs',
        'policy\src\cache\group.rs',
        'policy\src\storage.rs',
        'policy\src\cache.rs',
        'protocol\src\lib.rs'
    )
    $environment = @(
        'Offline DRIVER bandwidth aggregation benchmark; no driver installed, loaded, bound or opened.',
        ('Date: ' + (Get-Date -Format o)),
        ('Records: ' + $Records),
        ('Flows argument: ' + $Flows),
        ('Scenario: ' + $Scenario),
        ('Rounds: ' + $Rounds),
        ('Interface scopes: ' + $Interfaces),
        ('Seed: ' + $Seed),
        ('RUSTFLAGS: ' + $env:RUSTFLAGS),
        'Release profile: opt-level=2, lto=true, codegen-units=1, panic=abort',
        'Host System allocator with requested-byte/call instrumentation; allocator overhead not counted as storage.',
        'Main benchmark thread pinned to logical CPU 2 when allowed; inherited priority unchanged.',
        (& rustc -Vv),
        (& cargo -V),
        ('Git HEAD: ' + (& git rev-parse HEAD)),
        (& git status --short),
        (Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List | Out-String),
        (Get-CimInstance Win32_OperatingSystem | Select-Object Version, TotalVisibleMemorySize | Format-List | Out-String)
    )
    foreach ($source in $sources) {
        $environment += (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root $source) | Format-List | Out-String)
    }
    $environment += (Get-FileHash -Algorithm SHA256 -LiteralPath $exe | Format-List | Out-String)
    $environment += (Get-AuthenticodeSignature -LiteralPath $exe | Select-Object Status, StatusMessage | Format-List | Out-String)
    $environment | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutputDirectory 'environment.txt')
    & $exe --records $Records --flows $Flows --interfaces $Interfaces --rounds $Rounds --seed $Seed --scenario $Scenario --out $OutputDirectory 2>&1 |
        Tee-Object -FilePath (Join-Path $OutputDirectory 'run.log')
    if ($LASTEXITCODE) { throw 'Bandwidth benchmark or correctness assertion failed.' }
    Write-Host "Results: $OutputDirectory (report.md, samples.tsv, environment.txt, run.log)"
} finally {
    $env:RUSTFLAGS = $oldFlags
    $env:CARGO_ENCODED_RUSTFLAGS = $oldEncodedFlags
    Set-Location $oldDir
}
