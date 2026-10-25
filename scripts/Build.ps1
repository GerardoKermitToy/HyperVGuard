[CmdletBinding()]
param(
    [switch]$SkipMonitor,
    [switch]$Test,
    [string]$SdkVersion = '10.0.28000.0',
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [string]$RootCertificate,
    [string]$PfxPassword = $(if ($env:HYPERVGUARD_PFX_PASSWORD) { $env:HYPERVGUARD_PFX_PASSWORD } else { '1' })
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (!(Test-Path $vswhere)) { throw 'Visual Studio with C++ tools is required.' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual Studio C++ x64 tools were not found.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$env:Path += ';' + (Split-Path $vswhere -Parent)
$environment = & $env:ComSpec /d /c "call `"$vcvars`" >nul && set"
if ($LASTEXITCODE) { throw 'vcvars64 failed.' }
foreach ($line in $environment) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
$wdk = "${env:ProgramFiles(x86)}\Windows Kits\10"
$include = Join-Path $wdk "Include\$SdkVersion"
$lib = Join-Path $wdk "Lib\$SdkVersion\km\x64"
$bin = Join-Path $wdk "bin\$SdkVersion\x64"
foreach ($required in @("$include\km\ndis.h", "$lib\ndis.lib", "$lib\netio.lib")) {
    if (!(Test-Path $required)) { throw "Missing WDK input: $required" }
}
$build = Join-Path $root 'build'
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $build, $dist | Out-Null
$oldFlags = $env:RUSTFLAGS
$oldDir = Get-Location
try {
    Set-Location $root
    $env:RUSTFLAGS = '-C panic=abort -C no-redzone=yes -C debuginfo=2'
    & cargo build --release --target x86_64-pc-windows-msvc -p hyperv-driver --locked
    if ($LASTEXITCODE) { throw 'Rust driver build failed.' }
    $object = Join-Path $build 'ndis_shim.obj'
    & cl.exe /nologo /c /TC /O2 /W4 /WX /wd4324 /GS /kernel /Zl /Zi /D_AMD64_ /DAMD64 /DNDIS640 /DNDIS_SUPPORT_NDIS640=1 /D_WIN64 /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000C "/I$include\km" "/I$include\shared" "/I$include\ucrt" "/Fo$object" "/Fd$build\shim.pdb" "$root\driver\shim\ndis_shim.c"
    if ($LASTEXITCODE) { throw 'WDK ABI shim compilation failed.' }
    & link.exe /NOLOGO /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry /MACHINE:X64 /MANIFEST:NO /NODEFAULTLIB /INCREMENTAL:NO /INTEGRITYCHECK /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF /DEBUG:FULL /RELEASE "/OUT:$dist\HyperVGuard.sys" "/PDB:$dist\HyperVGuard.pdb" $object "$root\target\x86_64-pc-windows-msvc\release\hyperv_driver.lib" "$lib\ndis.lib" "$lib\netio.lib" "$lib\ntoskrnl.lib" "$lib\hal.lib" "$lib\BufferOverflowK.lib"
    if ($LASTEXITCODE) { throw 'Kernel image link failed.' }
    $cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
    $ninja = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
    & $cmake -S "$root\monitor" -B "$build\monitor" -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
    if ($LASTEXITCODE) { throw 'User-mode CMake configuration failed.' }
    if ($SkipMonitor) { & $cmake --build "$build\monitor" --target hyperv_guard_notify hyperv_Install hyperv_Uninstall }
    else { & $cmake --build "$build\monitor" }
    if ($LASTEXITCODE) { throw 'User-mode build failed.' }
    Copy-Item "$build\monitor\HyperVGuardNotify.dll" $dist -Force
    foreach ($tool in @('Install.exe', 'Uninstall.exe')) { Copy-Item (Join-Path "$build\monitor" $tool) $dist -Force }
    if (!$SkipMonitor) {
        Copy-Item "$build\monitor\hyperv_monitor.exe" $dist -Force
        if ($Test) {
            & (Join-Path (Split-Path $cmake -Parent) 'ctest.exe') --test-dir "$build\monitor" --output-on-failure
            if ($LASTEXITCODE) { throw 'Offline user-mode tests failed.' }
        }
    }
    Copy-Item "$root\install\HyperVGuard.inf" $dist -Force
    if ($CertificateThumbprint -and $PfxPath) { throw 'Choose a PFX or a certificate-store thumbprint, not both.' }
    $signArgs = @('sign', '/fd', 'SHA256')
    $sign = $CertificateThumbprint -or $PfxPath
    if ($PfxPath) {
        $PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
        $signArgs += @('/f', $PfxPath, '/p', $PfxPassword)
        if ($RootCertificate) { $signArgs += @('/ac', (Resolve-Path -LiteralPath $RootCertificate).Path) }
    } elseif ($CertificateThumbprint) { $signArgs += @('/sha1', $CertificateThumbprint) }
    if ($sign) {
        # Local signing only: no timestamp request, key copy, certificate import
        # or boot/security policy change. The PFX remains at the supplied path.
        foreach ($file in @('HyperVGuard.sys', 'HyperVGuardNotify.dll', 'Install.exe', 'Uninstall.exe')) {
            & "$bin\signtool.exe" @signArgs (Join-Path $dist $file)
            if ($LASTEXITCODE) { throw "Signing failed: $file" }
        }
    }
    # Stage the installed Inf2Cat with matching x64 native DLLs. Never patch the
    # WDK's mixed-bitness tool directory (0x8007000B without private staging).
    $catalogTools = Join-Path $build 'catalog-tools'
    New-Item -ItemType Directory -Force $catalogTools | Out-Null
    $catalogSource = "$wdk\bin\$SdkVersion\x86"
    Copy-Item "$catalogSource\Inf2Cat.exe" $catalogTools -Force
    Copy-Item "$catalogSource\WindowsProtectedFiles.xml" $catalogTools -Force
    foreach ($dll in Get-ChildItem "$catalogSource\Microsoft*.dll") {
        $matching = Join-Path $bin $dll.Name
        if (Test-Path $matching) { Copy-Item $matching $catalogTools -Force }
        else { Copy-Item $dll.FullName $catalogTools -Force }
    }
    Copy-Item "$bin\DRIVERS.dll" $catalogTools -Force
    if (Test-Path "$catalogSource\Inf2Cat.exe.config") { Copy-Item "$catalogSource\Inf2Cat.exe.config" $catalogTools -Force }
    & "$catalogTools\Inf2Cat.exe" "/driver:$dist" /os:10_X64 /uselocaltime
    if ($LASTEXITCODE) { throw 'Inf2Cat package validation failed.' }
    if ($sign) {
        & "$bin\signtool.exe" @signArgs "$dist\HyperVGuard.cat"
        if ($LASTEXITCODE) { throw 'Catalog signing failed.' }
        foreach ($file in @('HyperVGuard.sys', 'HyperVGuardNotify.dll', 'HyperVGuard.cat', 'Install.exe', 'Uninstall.exe')) {
            & "$bin\signtool.exe" verify /pa (Join-Path $dist $file)
            if ($LASTEXITCODE) { throw "Authenticode verification failed: $file (not a kernel admission test)." }
        }
        foreach ($file in @('HyperVGuard.sys', 'HyperVGuardNotify.dll', 'HyperVGuard.inf')) {
            & "$bin\signtool.exe" verify /pa /c "$dist\HyperVGuard.cat" (Join-Path $dist $file)
            if ($LASTEXITCODE) { throw "Catalog membership verification failed: $file" }
        }
    }
    if ($Test) {
        $env:RUSTFLAGS = ''
        & cargo test --release -p hyperv-protocol -p hyperv-policy --locked
        if ($LASTEXITCODE) { throw 'Offline Rust tests failed.' }
    }
    Write-Host "Built $dist (no driver was installed, loaded or bound; notify COM was not registered)."
    if (!$sign) { Write-Warning 'SYS, notify DLL, CAT and setup tools are unsigned. Driver package signatures must be trusted before installation.' }
} finally {
    $env:RUSTFLAGS = $oldFlags
    Set-Location $oldDir
}
