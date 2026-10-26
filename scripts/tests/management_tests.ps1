# Offline tests: every network/registry function used by helpers is mocked.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'HyperVXNdisFilter.Common.ps1')
$script:passed = 0
$targetGuid = [guid]'9eb6ca05-3905-4420-a34f-4fa09dcc6a2d'
function Assert-True {
    param([bool]$Condition, [string]$Message = 'Assertion failed')
    if (!$Condition) { throw $Message }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Text)
    $caught = $null
    try { & $Action } catch { $caught = $_.Exception.Message }
    Assert-True ($null -ne $caught -and $caught.Contains($Text)) "Expected '$Text', got '$caught'."
}
function Get-VMSwitch { [CmdletBinding()] param() $script:switches }
function Get-VMNetworkAdapter {
    [CmdletBinding()] param([switch]$ManagementOS)
    Assert-True ([bool]$ManagementOS) 'Guest adapters must not be queried.'
    $script:vnics
}
function Get-NetAdapter {
    [CmdletBinding()] param([switch]$IncludeHidden)
    Assert-True ([bool]$IncludeHidden)
    $script:adapters
}
function Get-NetAdapterBinding {
    [CmdletBinding()] param([string]$Name, [switch]$IncludeHidden, [switch]$AllBindings)
    Assert-True ($Name -eq '*' -and $IncludeHidden -and $AllBindings)
    $script:bindings
}
function Get-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath)
    Assert-True ($LiteralPath -eq $script:HyperVXNdisFilterConfigPath)
    [pscustomobject]$script:config
}
function New-Item {
    [CmdletBinding()] param([string]$Path, [switch]$Force)
    Assert-True ($Path -eq $script:HyperVXNdisFilterConfigPath -and $Force)
}
function New-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Name, [string]$PropertyType, [object]$Value, [switch]$Force)
    Assert-True ($LiteralPath -eq $script:HyperVXNdisFilterConfigPath -and $Force)
    $script:writes += "$Name/$PropertyType"
    $script:config[$Name] = $Value
}
function Reset-Fixtures {
    $script:switches = @([pscustomobject]@{ Id = $script:HyperVXNdisFilterDefaultSwitchId; Name = 'Default Switch' })
    $script:vnics = @([pscustomobject]@{ IsManagementOs = $true; SwitchId = $script:HyperVXNdisFilterDefaultSwitchId; DeviceId = $targetGuid.ToString('B') })
    $script:adapters = @(
        [pscustomobject]@{ Name = 'vEthernet (Default Switch)'; InterfaceGuid = $targetGuid; NetLuid = [uint64]1689399750295552; Virtual = $true; HardwareInterface = $false; InterfaceType = 6 },
        [pscustomobject]@{ Name = 'Ethernet'; InterfaceGuid = [guid]::NewGuid(); NetLuid = [uint64]10; Virtual = $false; HardwareInterface = $true; InterfaceType = 6 }
    )
    $script:bindings = @(
        [pscustomobject]@{ Name = 'vEthernet (Default Switch)'; ComponentID = 'hyperv_xndis_filter'; Enabled = $false },
        [pscustomobject]@{ Name = 'Ethernet'; ComponentID = 'hyperv_xndis_filter'; Enabled = $false },
        [pscustomobject]@{ Name = 'Ethernet'; ComponentID = 'ms_tcpip'; Enabled = $true }
    )
    $script:config = @{ ConfigVersion = 2; TargetInterfaceGuid = $targetGuid.ToString('B'); TargetNetLuid = $script:adapters[0].NetLuid; AllowBindings = 0 }
    $script:writes = @()
}
function Test-Case {
    param([string]$Name, [scriptblock]$Action)
    Reset-Fixtures
    & $Action
    ++$script:passed
    Write-Host "PASS $Name"
}

Test-Case 'resolve actual management vNIC by Default Switch ID and interface GUID' {
    Assert-True ((Resolve-HyperVXNdisFilterAdapter).InterfaceGuid -eq $targetGuid)
}
Test-Case 'adapter alias is not an authorization identity' {
    $script:adapters[0].Name = 'Renamed host vNIC'
    Assert-True ((Resolve-HyperVXNdisFilterAdapter).Name -eq 'Renamed host vNIC')
}
Test-Case 'a matching display name on the wrong switch is rejected' {
    $script:switches[0].Id = [guid]::NewGuid()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'Default Switch is missing'
}
Test-Case 'absent Default Switch is rejected' {
    $script:switches = @()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'Default Switch is missing'
}
Test-Case 'ambiguous management vNIC is rejected' {
    $script:vnics += $script:vnics[0]
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'Expected one management-OS vNIC'
}
Test-Case 'guest vNIC cannot be selected' {
    $script:vnics[0].IsManagementOs = $false
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'Expected one management-OS vNIC'
}
Test-Case 'unrelated switch management vNIC cannot be selected' {
    $script:vnics[0].SwitchId = [guid]::NewGuid()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'Expected one management-OS vNIC'
}
Test-Case 'invalid management device GUID is rejected' {
    $script:vnics[0].DeviceId = 'not-a-guid'
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'no valid interface GUID'
}
Test-Case 'same alias cannot substitute a different interface GUID' {
    $script:adapters[0].InterfaceGuid = [guid]::NewGuid()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'exact Default Switch host adapter was not found'
}
Test-Case 'physical adapter cannot be selected' {
    $script:adapters[0].HardwareInterface = $true
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'not an Ethernet host vNIC'
}
Test-Case 'nonvirtual adapter cannot be selected' {
    $script:adapters[0].Virtual = $false
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'not an Ethernet host vNIC'
}
Test-Case 'non-Ethernet adapter cannot be selected' {
    $script:adapters[0].InterfaceType = 71
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'not an Ethernet host vNIC'
}
Test-Case 'missing NET_LUID cannot be selected' {
    $script:adapters[0].NetLuid = 0
    Assert-Throws { Resolve-HyperVXNdisFilterAdapter } 'not an Ethernet host vNIC'
}
Test-Case 'only own-component bindings are enumerated' {
    Assert-True (@(Get-HyperVXNdisFilterBindings).Count -eq 2)
}
Test-Case 'disabled foreign bindings do not get enabled or edited' {
    $binding = Assert-HyperVXNdisFilterBindingScope -Adapter $script:adapters[0] -AllDisabled
    Assert-True ($binding.Name -eq $script:adapters[0].Name -and $script:writes.Count -eq 0)
    Assert-True (!$script:bindings[1].Enabled -and $script:bindings[2].Enabled)
}
Test-Case 'foreign enabled binding causes abort instead of editing that adapter' {
    $script:bindings[1].Enabled = $true
    Assert-Throws { Assert-HyperVXNdisFilterBindingScope -Adapter $script:adapters[0] } 'unexpectedly enabled binding'
    Assert-True ($script:bindings[1].Enabled -and $script:writes.Count -eq 0)
}
Test-Case 'installation requires all new bindings to remain disabled' {
    $script:bindings[0].Enabled = $true
    Assert-Throws { Assert-HyperVXNdisFilterBindingScope -Adapter $script:adapters[0] -AllDisabled } 'unexpectedly enabled binding'
}
Test-Case 'target enabled is accepted after explicit enable' {
    $script:bindings[0].Enabled = $true
    Assert-True ([bool](Assert-HyperVXNdisFilterBindingScope -Adapter $script:adapters[0]).Enabled)
}
Test-Case 'matching GUID and NET_LUID configuration is accepted' {
    Assert-HyperVXNdisFilterTargetConfiguration -Adapter $script:adapters[0]
}
Test-Case 'stale GUID configuration is rejected' {
    $script:config.TargetInterfaceGuid = [guid]::NewGuid().ToString('B')
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapter $script:adapters[0] } 'does not match'
}
Test-Case 'stale NET_LUID configuration is rejected' {
    $script:config.TargetNetLuid = [uint64]10
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapter $script:adapters[0] } 'does not match'
}
Test-Case 'old configuration schema is rejected' {
    $script:config.ConfigVersion = 1
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapter $script:adapters[0] } 'does not match'
}
Test-Case 'fresh configuration is disarmed first and versioned last' {
    Set-HyperVXNdisFilterTargetConfiguration -Adapter $script:adapters[0]
    Assert-True (($script:writes -join ',') -eq 'AllowBindings/DWord,TargetInterfaceGuid/String,TargetNetLuid/QWord,ConfigVersion/DWord')
    Assert-True ($script:config.AllowBindings -eq 0 -and $script:config.ConfigVersion -eq 2)
    Assert-True ($script:config.TargetInterfaceGuid.Length -eq 38)
}
Test-Case 'arming changes only the own-component configuration' {
    Set-HyperVXNdisFilterBindingsAllowed -Allowed $true
    Assert-True ($script:config.AllowBindings -eq 1 -and $script:writes.Count -eq 1)
    Assert-True (!$script:bindings[1].Enabled -and $script:bindings[2].Enabled)
}
Test-Case 'obsolete switch script cannot mutate any switch' {
    Assert-Throws { & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Set-Extension.ps1') -SwitchName 'Default Switch' -Enable } 'not a vSwitch extension'
}
Test-Case 'all management scripts parse on Windows PowerShell' {
    Get-ChildItem (Split-Path $PSScriptRoot -Parent) -Filter *.ps1 -Recurse | ForEach-Object {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        Assert-True ($errors.Count -eq 0) "Parse errors in $($_.Name): $errors"
    }
}
Write-Host "$script:passed management tests passed (no driver, registry or network changes)."
