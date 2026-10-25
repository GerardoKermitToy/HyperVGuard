$script:HyperVGuardComponentId = 'hyperv_guard'
$script:HyperVGuardConfigPath = 'HKLM:\SOFTWARE\HyperVGuard\Lwf'
$script:HyperVGuardDefaultSwitchId = [guid]'c08cb7b8-9b3c-408e-8e30-5e16a3aeb444'

function Resolve-HyperVGuardAdapter {
    [CmdletBinding()]
    param()

    $switches = @(Get-VMSwitch -ErrorAction Stop | Where-Object { $_.Id -eq $script:HyperVGuardDefaultSwitchId })
    if ($switches.Count -ne 1) { throw 'The automatic Default Switch is missing or ambiguous. No alternate adapter will be selected.' }
    $vnics = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop | Where-Object {
        $_.IsManagementOs -and $_.SwitchId -eq $script:HyperVGuardDefaultSwitchId
    })
    if ($vnics.Count -ne 1) { throw 'Expected one management-OS vNIC on Default Switch. No binding was changed.' }
    $guid = [guid]::Empty
    if (![guid]::TryParse([string]$vnics[0].DeviceId, [ref]$guid) -or $guid -eq [guid]::Empty) {
        throw 'The Default Switch management vNIC has no valid interface GUID.'
    }
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { [guid]$_.InterfaceGuid -eq $guid })
    if ($adapters.Count -ne 1) { throw 'The exact Default Switch host adapter was not found. No name-based fallback is allowed.' }
    $adapter = $adapters[0]
    if (!$adapter.Virtual -or $adapter.HardwareInterface -or $adapter.InterfaceType -ne 6 -or [uint64]$adapter.NetLuid -eq 0) {
        throw 'The selected device is not an Ethernet host vNIC with a valid NET_LUID.'
    }
    return $adapter
}

function Get-HyperVGuardBindings {
    [CmdletBinding()]
    param()
    Get-NetAdapterBinding -Name '*' -IncludeHidden -AllBindings -ErrorAction Stop |
        Where-Object { $_.ComponentID -eq $script:HyperVGuardComponentId }
}

function Assert-HyperVGuardBindingScope {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Adapter, [switch]$AllDisabled)

    $bindings = @(Get-HyperVGuardBindings)
    $foreign = @($bindings | Where-Object { $_.Enabled -and ($AllDisabled -or $_.Name -ne $Adapter.Name) })
    if ($foreign.Count) {
        throw 'HyperVGuard has an unexpectedly enabled binding. No other adapter will be edited; abort and remove the component with Uninstall.exe.'
    }
    $target = @($bindings | Where-Object { $_.Name -eq $Adapter.Name })
    if ($target.Count -ne 1) { throw 'Expected one HyperVGuard binding on the exact Default Switch host adapter.' }
    return $target[0]
}

function Assert-HyperVGuardTargetConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Adapter)

    $config = Get-ItemProperty -LiteralPath $script:HyperVGuardConfigPath -ErrorAction Stop
    if ($config.ConfigVersion -ne 2 -or [guid]$config.TargetInterfaceGuid -ne [guid]$Adapter.InterfaceGuid -or
        [uint64]$config.TargetNetLuid -ne [uint64]$Adapter.NetLuid) {
        throw 'The configured GUID/NET_LUID does not match the current Default Switch host vNIC. Uninstall and reinstall explicitly; no fallback or automatic retargeting is allowed.'
    }
}

function Set-HyperVGuardTargetConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Adapter)

    # Called only for a fresh installation, before NetCfg can load either binary.
    New-Item -Path $script:HyperVGuardConfigPath -Force | Out-Null
    New-ItemProperty -LiteralPath $script:HyperVGuardConfigPath -Name AllowBindings -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -LiteralPath $script:HyperVGuardConfigPath -Name TargetInterfaceGuid -PropertyType String -Value ([guid]$Adapter.InterfaceGuid).ToString('B').ToUpperInvariant() -Force | Out-Null
    New-ItemProperty -LiteralPath $script:HyperVGuardConfigPath -Name TargetNetLuid -PropertyType QWord -Value ([long]$Adapter.NetLuid) -Force | Out-Null
    New-ItemProperty -LiteralPath $script:HyperVGuardConfigPath -Name ConfigVersion -PropertyType DWord -Value 2 -Force | Out-Null
}

function Set-HyperVGuardBindingsAllowed {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$Allowed)
    New-ItemProperty -LiteralPath $script:HyperVGuardConfigPath -Name AllowBindings -PropertyType DWord -Value ([int]$Allowed) -Force | Out-Null
}
