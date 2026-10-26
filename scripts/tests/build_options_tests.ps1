# Offline tests: evaluate only the build parameter block, never the build body.
$ErrorActionPreference = 'Stop'
$buildScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Build.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0 -or $null -eq $ast.ParamBlock) { throw 'Build.ps1 parameter parsing failed.' }
$probe = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n" + '$PfxPassword')
$oldPassword = $env:HYPERVXNDISFILTER_PFX_PASSWORD
$script:passed = 0

function Test-Password {
    param([string]$Name, [string]$EnvironmentPassword, [hashtable]$Arguments, [string]$Expected)
    $env:HYPERVXNDISFILTER_PFX_PASSWORD = $EnvironmentPassword
    $actual = & $probe @Arguments
    if ($actual -cne $Expected) { throw "Unexpected password selection: $Name" }
    ++$script:passed
    Write-Host "PASS $Name"
}

try {
    Test-Password 'default without an environment password' $null @{} '1'
    Test-Password 'environment overrides the default' 'environment-fixture' @{} 'environment-fixture'
    Test-Password 'explicit argument overrides environment' 'environment-fixture' @{ PfxPassword = 'argument-fixture' } 'argument-fixture'
    Test-Password 'explicit empty argument overrides environment' 'environment-fixture' @{ PfxPassword = '' } ''
    Test-Password 'explicit empty argument overrides default' $null @{ PfxPassword = '' } ''
    Test-Password 'zero is a nonempty environment password' '0' @{} '0'
    Test-Password 'whitespace is preserved when explicitly configured' ' ' @{} ' '
    Test-Password 'a PFX path does not change the default or open a file' $null @{ PfxPath = 'never-opened-by-parser.pfx' } '1'
    Write-Host "PASS $script:passed build option cases (no compiler, signing tool, key or driver access)."
} finally {
    $env:HYPERVXNDISFILTER_PFX_PASSWORD = $oldPassword
}
