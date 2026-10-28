# Offline tests: evaluate only parameters and signing arguments, never build actions.
$ErrorActionPreference = 'Stop'
$buildScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Build.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0 -or $null -eq $ast.ParamBlock) { throw 'Build.ps1 parameter parsing failed.' }
$probe = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n" + '$PfxPassword')
$timestampProbe = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n" + '$TimestampUrl')
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
    foreach ($case in @(
        @{ Name = 'timestamp service defaults to DigiCert'; Arguments = @{}; Expected = 'http://timestamp.digicert.com' },
        @{ Name = 'timestamp service can be overridden'; Arguments = @{ TimestampUrl = 'https://tsa.example.test' }; Expected = 'https://tsa.example.test' }
    )) {
        $arguments = $case.Arguments
        $actual = & $timestampProbe @arguments
        if ($actual -cne $case.Expected) { throw "Unexpected timestamp selection: $($case.Name)" }
        ++$script:passed
        Write-Host "PASS $($case.Name)"
    }
    foreach ($invalidUrl in @('', $null)) {
        $rejected = $false
        try { & $timestampProbe -TimestampUrl $invalidUrl | Out-Null }
        catch [System.Management.Automation.ParameterBindingException] { $rejected = $true }
        if (!$rejected) { throw 'Empty/null timestamp URL was accepted.' }
        ++$script:passed
        Write-Host 'PASS empty/null timestamp URL is rejected without a request'
    }
    $assignment = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$signArgs'
    }, $true)
    if ($null -eq $assignment) { throw 'Signing argument assignment not found.' }
    $TimestampUrl = 'https://tsa.example.test'
    $signArgs = & ([scriptblock]::Create($assignment.Right.Extent.Text))
    $expectedArgs = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
    if (($signArgs -join "`0") -cne ($expectedArgs -join "`0")) { throw 'RFC 3161/SHA-256 signing arguments differ.' }
    ++$script:passed
    Write-Host 'PASS all signing uses RFC 3161 with SHA-256 and the selected URL'
    Write-Host "PASS $script:passed build option cases (no compiler, signing tool, key, TSA or driver access)."
} finally {
    $env:HYPERVXNDISFILTER_PFX_PASSWORD = $oldPassword
}
