[CmdletBinding()]
param(
    [string]$SwitchName,
    [switch]$Enable,
    [switch]$Disable
)
throw 'HyperVXNdisFilter 0.2 is a host-adapter NDIS LWF, not a vSwitch extension. Use dist/Install.exe and Set-Binding.ps1 -Enable/-Disable. Enable-VMSwitchExtension is not used; no switch configuration was changed.'
