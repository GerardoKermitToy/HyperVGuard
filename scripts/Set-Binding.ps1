#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Enable')][switch]$Enable,
    [Parameter(Mandatory = $true, ParameterSetName = 'Disable')][switch]$Disable
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\HyperVGuard.Common.ps1"
Import-Module Hyper-V -ErrorAction Stop
$adapter = Resolve-HyperVGuardAdapter
Assert-HyperVGuardTargetConfiguration -Adapter $adapter
$binding = Assert-HyperVGuardBindingScope -Adapter $adapter
$desiredEnabled = [bool]$Enable
if ([bool]$binding.Enabled -eq $desiredEnabled) {
    Write-Host "HyperVGuard already has Enabled=$desiredEnabled on '$($adapter.Name)'."
} elseif ($PSCmdlet.ShouldProcess($adapter.Name, "Set ONLY the HyperVGuard binding to Enabled=$desiredEnabled")) {
    $current = Resolve-HyperVGuardAdapter
    Assert-HyperVGuardTargetConfiguration -Adapter $current
    if ([guid]$current.InterfaceGuid -ne [guid]$adapter.InterfaceGuid -or $current.Name -ne $adapter.Name) {
        throw 'The target changed while waiting for confirmation. No binding was changed.'
    }
    $binding = Assert-HyperVGuardBindingScope -Adapter $current
    Set-HyperVGuardBindingsAllowed -Allowed $desiredEnabled
    try {
        if ($Enable) { Enable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop }
        else { Disable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop }
        $binding = Assert-HyperVGuardBindingScope -Adapter $adapter
        if ([bool]$binding.Enabled -ne $desiredEnabled) { throw 'The target binding did not reach the requested state.' }
    } catch {
        Set-HyperVGuardBindingsAllowed -Allowed $false
        throw
    }
}
$binding | Format-List Name, DisplayName, ComponentID, Enabled
