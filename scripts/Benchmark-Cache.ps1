[CmdletBinding()]
param(
    [ValidateRange(2, 100000000)][int]$Entries = 1000000,
    [ValidateRange(1, 100000000)][int]$Queries = 1000000,
    [ValidateRange(3, 101)][int]$Rounds = 7,
    [UInt64]$Seed = 5213293108232939589,
    [ValidateSet('both', 'random', 'shared')][string]$Pattern = 'both',
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$PfxPath,
    [Parameter(Mandatory = $true)][string]$RootCertificate,
    [string]$PfxPassword = $(if ($env:HYPERVXNDISFILTER_PFX_PASSWORD) { $env:HYPERVXNDISFILTER_PFX_PASSWORD } else { '1' }),
    [string]$SdkVersion = '10.0.28000.0'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$signTool = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\$SdkVersion\x64\signtool.exe"
if (!(Test-Path -LiteralPath $signTool)) { throw 'Windows SDK signtool is required.' }
$PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
$RootCertificate = (Resolve-Path -LiteralPath $RootCertificate).Path
if (!$OutputDirectory) {
    $OutputDirectory = Join-Path $root ('build\cache-bench\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
}
if ((Test-Path -LiteralPath $OutputDirectory) -and (Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1)) {
    throw 'Use a new/empty output directory; prior benchmark results are never overwritten.'
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$oldFlags = $env:RUSTFLAGS
$oldEncodedFlags = $env:CARGO_ENCODED_RUSTFLAGS
$oldDir = Get-Location
try {
    Set-Location $root
    # Match release opt-level/LTO/codegen units, with the driver's no-redzone flag.
    # This builds only a user-mode benchmark, not a new kernel/package artifact.
    $env:RUSTFLAGS = '-C no-redzone=yes -C debuginfo=2 -C link-arg=/DEBUG:FULL -C link-arg=/PDBALTPATH:%_PDB%'
    $env:CARGO_ENCODED_RUSTFLAGS = $null
    & cargo build --release -p hyperv-policy --example cache_lookup_bench --locked
    if ($LASTEXITCODE) { throw 'Benchmark build failed.' }
    $exe = Join-Path $root 'target\release\examples\cache_lookup_bench.exe'
    # Use the supplied certificates in place. No timestamp request, certificate
    # import, key copy, trust-store change, or installed driver/device access.
    & $signTool sign /fd SHA256 /f $PfxPath /p $PfxPassword /ac $RootCertificate $exe
    if ($LASTEXITCODE) { throw 'Benchmark signing failed.' }
    & $signTool verify /pa $exe
    if ($LASTEXITCODE) { throw 'Benchmark signature verification failed.' }
    $environment = @(
        'Offline cache benchmark; no driver was installed, loaded, bound or opened.',
        ('Date: ' + (Get-Date -Format o)),
        ('Entries per family/distribution: ' + $Entries),
        ('Queries per sample: ' + $Queries),
        ('Rounds: ' + $Rounds),
        ('Seed: ' + $Seed),
        ('Pattern: ' + $Pattern),
        ('RUSTFLAGS: ' + $env:RUSTFLAGS),
        'Release profile: opt-level=2, lto=true, codegen-units=1, panic=abort',
        (& rustc -Vv),
        (& cargo -V),
        (Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List | Out-String),
        (Get-CimInstance Win32_OperatingSystem | Select-Object Version, TotalVisibleMemorySize, FreePhysicalMemory | Format-List | Out-String),
        (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root 'policy\src\cache.rs') | Format-List | Out-String),
        (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root 'policy\src\cache\group.rs') | Format-List | Out-String),
        (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root 'policy\examples\cache_lookup_bench.rs') | Format-List | Out-String),
        (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root 'policy\examples\cache_lookup_bench\linear_cache.rs') | Format-List | Out-String),
        (Get-FileHash -Algorithm SHA256 -LiteralPath $exe | Format-List | Out-String),
        (Get-AuthenticodeSignature -LiteralPath $exe | Select-Object Status, StatusMessage | Format-List | Out-String)
    )
    $environment | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutputDirectory 'environment.txt')
    & $exe --entries $Entries --queries $Queries --rounds $Rounds --seed $Seed --pattern $Pattern --out $OutputDirectory 2>&1 |
        Tee-Object -FilePath (Join-Path $OutputDirectory 'run.log')
    if ($LASTEXITCODE) { throw 'Benchmark or correctness assertion failed.' }
    Write-Host "Results: $OutputDirectory (report.md, samples.tsv, environment.txt, run.log)"
} finally {
    $env:RUSTFLAGS = $oldFlags
    $env:CARGO_ENCODED_RUSTFLAGS = $oldEncodedFlags
    Set-Location $oldDir
}
