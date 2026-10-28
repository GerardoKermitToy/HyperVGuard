# Offline source/version-resource checks; an optional SYS is read as a file only.
[CmdletBinding()]
param([string]$DriverPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$resource = Get-Content -Raw -LiteralPath (Join-Path $root 'driver\version.rc')
$inf = Get-Content -Raw -LiteralPath (Join-Path $root 'install\HyperVXNdisFilter.inf')
$script:passed = 0

function Assert-Version {
    param([bool]$Condition, [string]$Name)
    if (!$Condition) { throw "Driver version resource check failed: $Name" }
    ++$script:passed
    Write-Host "PASS $Name"
}

$package = [regex]::Match($inf, '(?m)^DriverVer=[^,\r\n]+,(\d+\.\d+\.\d+\.\d+)\s*$')
Assert-Version $package.Success 'INF contains a four-part package version'
$version = $package.Groups[1].Value
foreach ($field in @('FILEVERSION', 'PRODUCTVERSION')) {
    $match = [regex]::Match($resource, "(?m)^\s*$field\s+(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\s*$")
    $actual = (1..4 | ForEach-Object { $match.Groups[$_].Value }) -join '.'
    Assert-Version ($match.Success -and $actual -ceq $version) "$field matches $version"
}
$strings = @{
    CompanyName = [regex]::Match($inf, '(?m)^Provider="([^"]+)"').Groups[1].Value
    FileDescription = [regex]::Match($inf, '(?m)^Description="([^"]+)"').Groups[1].Value
    FileVersion = $version
    InternalName = 'HyperVXNdisFilter'
    OriginalFilename = 'HyperVXNdisFilter.sys'
    ProductName = 'HyperVXNdisFilter'
    ProductVersion = $version
}
foreach ($name in $strings.Keys) {
    $match = [regex]::Match($resource, 'VALUE\s+"' + $name + '",\s*"([^"]+)"')
    Assert-Version ($match.Success -and $match.Groups[1].Value -ceq $strings[$name]) "resource $name"
}
Assert-Version ([regex]::IsMatch($resource, '(?m)^\s*FILETYPE\s+VFT_DRV\s*$')) 'resource type is VFT_DRV'
Assert-Version ([regex]::IsMatch($resource, '(?m)^\s*FILESUBTYPE\s+VFT2_DRV_NETWORK\s*$')) 'resource subtype is VFT2_DRV_NETWORK'
Assert-Version ([regex]::IsMatch($resource, '(?m)^\s*FILEFLAGS\s+0\s*$')) 'resource has Release flags'
Assert-Version ([regex]::IsMatch($resource, 'VALUE\s+"Translation",\s*0x0409,\s*1200')) 'resource translation is US English/Unicode'

if ($DriverPath) {
    $path = (Resolve-Path -LiteralPath $DriverPath).Path
    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
    $fileVersion = @($info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart) -join '.'
    $productVersion = @($info.ProductMajorPart, $info.ProductMinorPart, $info.ProductBuildPart, $info.ProductPrivatePart) -join '.'
    Assert-Version ($fileVersion -ceq $version) 'SYS numeric file version'
    Assert-Version ($productVersion -ceq $version) 'SYS numeric product version'
    foreach ($name in $strings.Keys) {
        Assert-Version ($info.$name -ceq $strings[$name]) "SYS $name"
    }
    Assert-Version (!($info.IsDebug -or $info.IsPreRelease -or $info.IsPatched -or $info.IsPrivateBuild -or $info.IsSpecialBuild)) 'SYS has Release flags'
}
Write-Host "PASS $script:passed driver version checks (no installation, device open or driver loading)."
