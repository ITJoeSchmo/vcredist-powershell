<#
.SYNOPSIS
MECM Detection script: returns success ONLY when all Microsoft Visual C++ Redistributables are compliant.

.DESCRIPTION
This script is intended for MECM Application Detection Methods. It writes EXACTLY ONE line of output
when the device is fully compliant; otherwise it writes nothing. MECM interprets any output as
“application is installed/detected”.

RULES:
- No output if any VC++ redist is missing, outdated, installed via WiX bundle, or otherwise non-compliant.
- One concise output line if everything is compliant.

.NOTES
Author: Joey Eckelbarger
Version: 0.1

Reboots: Exit code 3010 is logged as "reboot required." The script does not reboot automatically.

WiX Detection: Uses Bundle* uninstall properties, Package Cache evidence, and dependency mapping to infer bundles.

Edge Cases:
- VC++ 2005/2008 may not have MSI registrations; when DLLs are compliant and `doNotReinstallIfOrphanedDll=$true`,
  the product is considered compliant to avoid downgrading WinSxS.
- ARM64 is not explicitly handled in this script.
#>

$Is64BitOS                = [Environment]::Is64BitOperatingSystem

$x86SystemFolder          = if($Is64BitOS){ Join-Path $env:SYSTEMROOT 'SysWOW64' } else { Join-Path $env:SYSTEMROOT 'System32' }
$x64SystemFolder          = Join-Path $env:SYSTEMROOT 'System32'

$x86CommonProgramFolder = if($Is64BitOS){ ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles }
$x64CommonProgramFolder = $env:CommonProgramW6432

$x86Uninstall             = if($Is64BitOS){ 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' } else { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
$x64Uninstall             = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

$registeredDependencies = Get-ChildItem "HKLM:\SOFTWARE\Classes\Installer\Dependencies" -ErrorAction Ignore

$installDependencyData = foreach($install in $registeredDependencies){
    # ParentProduct        = installation that can likely be inferred as installed as part of WIX bundle. 
    # DependentProductCode = this GUID depends on the parent 
    $ParentProductCode            = Get-ItemProperty $install.PSPath | Select-Object -ExpandProperty '(default)' -ErrorAction Ignore 
    [array]$DependentProductCodes = Get-ChildItem "$($install.PSPath)\Dependents" -ErrorAction Ignore | Select -expand PSChildName | Where-Object {$_ -ne $ParentProductCode}

    # skip if null values
    if((-Not $DependentProductCodes) -or (-Not $ParentProductCode)){
        continue
    }

    $ParentProductArch = if(Test-Path -LiteralPath "$x86Uninstall\$ParentProductCode"){
        'x86'
    } elseif(Test-Path -LiteralPath "$x64Uninstall\$ParentProductCode"){
        'x64'
    } else {
        continue
    }
    
    foreach($productCode in $DependentProductCodes){
        [PSCustomObject]@{
            DependentProductCode = $productCode
            ProductCode          = $ParentProductCode
            ProductArch          = $ParentProductArch
        }
    }
}
# dedupe
$installDependencyData = $installDependencyData | Sort-Object * -Unique


$products = @(
    @{ # VC++ 2005 (major 8) x86
        productName             = "Microsoft Visual C++ 2005 Redistributable"
        productCodes            = "{710f4c1c-cc18-4c49-8cbf-51240c89a1a2}"
        arch                    = "x86"
        latestDllVersion        = "8.0.50727.6229" 

        dllPaths                = "$ENV:SYSTEMROOT\WinSxS\x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b*\msvcp80.dll",
                                  "$ENV:SYSTEMROOT\WinSxS\Fusion\x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b*\*\*\msvcp80.dll"

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2005\b.*?\b(?:Redistributable|Runtime)\b.*$'

        installers              = ".\2005\x86\vcredist.msi"


        # Why: These versions often deploy into WinSxS without MSI entries; if DLLs are up-to-date,
        # reinstallation is unnecessary and could downgrade a higher, side-by-side version.
        doNotReinstallIfOrphanedDll = $true
    }
    @{ # VC++ 2005 (major 8) x64
        productName             = "Microsoft Visual C++ 2005 Redistributable (x64)"
        productCodes            = "{ad8a2fa1-06e7-4b0d-927d-6e54b3d31028}"
        arch                    = "x64"
        latestDllVersion        = "8.0.50727.6229" 

        dllPaths                = "$ENV:SYSTEMROOT\WinSxS\amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b*\msvcp80.dll",
                                  "$ENV:SYSTEMROOT\WinSxS\Fusion\amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b*\*\*\msvcp80.dll"
        
        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2005\b.*?\b(?:Redistributable|Runtime)\b.*$'

        installers              = ".\2005\x64\vcredist.msi"

        # Why: These versions often deploy into WinSxS without MSI entries; if DLLs are up-to-date,
        # reinstallation is unnecessary and could downgrade a higher, side-by-side version.
        doNotReinstallIfOrphanedDll = $true
    }

    
    @{ # VC++ 2008 (major 9) x86
        productName             = "Microsoft Visual C++ 2008 Redistributable - x86"
        productCodes            = "{9BE518E6-ECC6-35A9-88E4-87755C07200F}"
        arch                    = "x86"
        latestDllVersion        = "9.0.30729.7523" 

        dllPaths                = "$ENV:SYSTEMROOT\WinSxS\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b*\msvcp90.dll",
                                  "$ENV:SYSTEMROOT\WinSxS\Fusion\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b*\*\*\msvcp90.dll"

        msiFeatureRegistry      = "HKLM:\SOFTWARE\Classes\Installer\Features\6E815EB96CCE9A53884E7857C57002F0" # VC_RED_enu_

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2008\b.*?\b(?:Redistributable|Runtime)\b.*$'

        installers              = ".\2008\x86\vc_red.msi"

        # Why: These versions often deploy into WinSxS without MSI entries; if DLLs are up-to-date,
        # reinstallation is unnecessary and could downgrade a higher, side-by-side version.
        doNotReinstallIfOrphanedDll = $true
    }
    @{ # VC++ 2008 (major 9) x64
        productName             = "Microsoft Visual C++ 2008 Redistributable - x64"
        productCodes            = "{5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4}"
        arch                    = "x64"
        latestDllVersion        = "9.0.30729.7523" 

        dllPaths                = "$ENV:SYSTEMROOT\WinSxS\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b*\msvcp90.dll",
                                  "$ENV:SYSTEMROOT\WinSxS\Fusion\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b*\*\*\msvcp90.dll"

        msiFeatureRegistry      = "HKLM:\SOFTWARE\Classes\Installer\Features\67D6ECF5CD5FBA732B8B22BAC8DE1B4D" # VC_RED_enu_

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2008\b.*?\b(?:Redistributable|Runtime)\b.*$'

        installers              = ".\2008\x64\vc_red.msi"

        # Why: These versions often deploy into WinSxS without MSI entries; if DLLs are up-to-date,
        # reinstallation is unnecessary and could downgrade a higher, side-by-side version.
        doNotReinstallIfOrphanedDll = $true
    }

    
    @{ # VS 2010 Tools for Office Runtime (major 10) x86
        productName          = "Microsoft Visual Studio 2010 Tools for Office Runtime"
        productCodes         = "{888E1022-9CD3-32AC-BE6B-668FF6ABA136}"
        arch                 = "x86"
        latestDllVersion     = '10.0.60917.0'
        
        dllPaths             = "$x86CommonProgramFolder\Microsoft Shared\VSTO\vstoee.dll"
        
        msiFeatureRegistry   = "HKLM:\SOFTWARE\Classes\Installer\Features\2201E8883DC9CA23EBB666F86FBA1A63" # TRIN_TRIR_SETUP

        regexFilter          = '^(?i)(?!.*\blanguage\s*pack\b)(?!.*\bsdk\b)\s*(?:Microsoft\s+)?Visual\s+Studio\s+2010\s+Tools\s+for\s+Office\s+Runtime\b.*$'
        
        installers           = ".\vstor\vstor40_x86.msi"

        onlyOn32BitOS        = $true
    }
    @{ # VS 2010 Tools for Office Runtime (major 10) x64
        productName          = "Microsoft Visual Studio 2010 Tools for Office Runtime (x64)"
        productCodes         = "{610487D9-3460-328A-9333-219D43A75CC5}"
        arch                 = "x64"
        latestDllVersion     = '10.0.60917.0'

        dllPaths             = "$x64CommonProgramFolder\Microsoft Shared\VSTO\vstoee.dll"
        msiFeatureRegistry   = "HKLM:\SOFTWARE\Classes\Installer\Features\9D7840160643A823393312D9347AC55C" # TRIN_TRIR_SETUP

        regexFilter          = '^(?i)(?!.*\blanguage\s*pack\b)(?!.*\bsdk\b)\s*(?:Microsoft\s+)?Visual\s+Studio\s+2010\s+Tools\s+for\s+Office\s+Runtime\b.*$'
        
        installers           = ".\vstor\vstor40_x64.msi"
    }
    
    @{ # VC++ 2010 (major 10) x86
        productName             = "Microsoft Visual C++ 2010  x86 Redistributable"
        productCodes            = "{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}"
        arch                    = "x86"
        latestDllVersion        = "10.0.40219.473" 

        dllPaths                = "$x86SystemFolder\msvcp100.dll"

        msiFeatureRegistry      = "HKLM:\SOFTWARE\Classes\Installer\Features\1D5E3C0FEDA1E123187686FED06E995A" # VC_RED_enu_

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2010\b.*?\b(?:Redistributable|Runtime)\b.*$'

        installers              = ".\2010\x86\vc_red.msi"
    }
    @{ # VC++ 2010 (major 10) x64
        productName             = "Microsoft Visual C++ 2010  x64 Redistributable"
        productCodes            = "{1D8E6291-B0D5-35EC-8441-6616F567A0F7}"
        arch                    = "x64"
        latestDllVersion        = "10.0.40219.473" 

        dllPaths                = "$x64SystemFolder\msvcp100.dll"

        msiFeatureRegistry      = "HKLM:\SOFTWARE\Classes\Installer\Features\1926E8D15D0BCE53481466615F760A7F" # VC_RED_enu_

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2010\b.*?\b(?:Redistributable|Runtime)\b.*$'

        installers              = ".\2010\x64\vc_red.msi"
    }
    

    @{ # VC++ 2012 (major 11) x86
        productName             = "Microsoft Visual C++ 2012 Redistributable (x86)"
        productCodes            = "{BD95A8CD-1D9F-35AD-981A-3E7925026EBB}", # Minimum
                                  "{B175520C-86A2-35A7-8619-86DC379688B9}"  # Additional

        arch                    = "x86"
        latestDllVersion        = "11.0.61135.400" 

        dllPaths                = "$x86SystemFolder\msvcp110.dll"

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2012\b.*?\b(?:Redistributable|(?:Additional|Minimum)\s+Runtime)\b.*$'


        installers              = ".\2012\x86\vc_runtimeMinimum_x86.msi",
                                  ".\2012\x86\vc_runtimeAdditional_x86.msi"    
    }
    @{ # VC++ 2012 (major 11) x64
        productName             = "Microsoft Visual C++ 2012 Redistributable (x64)"
        productCodes            = "{CF2BEA3C-26EA-32F8-AA9B-331F7E34BA97}", # Minimum
                                  "{37B8F9C7-03FB-3253-8781-2517C99D7C00}"  # Additional 

        arch                    = "x64"
        latestDllVersion        = "11.0.61135.400" 

        dllPaths                = "$x64SystemFolder\msvcp110.dll"

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2012\b.*?\b(?:Redistributable|(?:Additional|Minimum)\s+Runtime)\b.*$'

        installers              = ".\2012\x64\vc_runtimeMinimum_x64.msi",
                                  ".\2012\x64\vc_runtimeAdditional_x64.msi"
    }

    
    @{ # VC++ 2013 (major 12) x86
        productName             = "Microsoft Visual C++ 2013 Redistributable (x86)"
        productCodes            = "{8122DAB1-ED4D-3676-BB0A-CA368196543E}", # Minimum
                                  "{D401961D-3A20-3AC7-943B-6139D5BD490A}"  # Additional 

        arch                    = "x86"
        latestDllVersion        = "12.0.40664.0" 

        dllPaths                = "$x86SystemFolder\msvcp120.dll"

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2013\b.*?\b(?:Redistributable|(?:Additional|Minimum)\s+Runtime)\b.*$'

        installers              = ".\2013\x86\vc_runtimeMinimum_x86.msi",
                                  ".\2013\x86\vc_runtimeAdditional_x86.msi"
    }
    @{ # VC++ 2013 (major 12) x64
        productName             = "Microsoft Visual C++ 2013 Redistributable (x64)"
        productCodes            = "{53CF6934-A98D-3D84-9146-FC4EDF3D5641}", # Minimum
                                  "{010792BA-551A-3AC0-A7EF-0FAB4156C382}"  # Additional 

        arch                    = "x64"
        latestDllVersion        = "12.0.40664.0" 

        dllPaths                = "$x64SystemFolder\msvcp120.dll"

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2013\b.*?\b(?:Redistributable|(?:Additional|Minimum)\s+Runtime)\b.*$'

        installers              = ".\2013\x64\vc_runtimeMinimum_x64.msi",
                                  ".\2013\x64\vc_runtimeAdditional_x64.msi"
    }
    
    
    @{ # VC++ 2015–2022 (major 14) x86
        productName             = "Microsoft Visual C++ 2015-2022 Redistributable (x86)"
        productCodes            = "{922480B5-CAEB-4B1B-AAA4-9716EFDCE26B}", # Minimum
                                  "{C18FB403-1E88-43C8-AD8A-CED50F23DE8B}"  # Additional 

        arch                    = "x86"
        latestDllVersion        = "14.44.35211.0" 

        dllPaths                = "$x86SystemFolder\msvcp140.dll"

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+.*?(?:2015(?:\s*(?:-|–|—|to)\s*(?:2019|2022))?|2017|2019|2022)\b.*?\b(?:Redistributable|Runtime|(?:Additional|Minimum)\s+Runtime)\b.*$'
        
        installers              = ".\2022\x86\vc_runtimeMinimum_x86.msi",
                                  ".\2022\x86\vc_runtimeAdditional_x86.msi"
    }
    @{ # VC++ 2015–2022 (major 14) x64
        productName             = "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
        productCodes            = "{43B0D101-A022-48F4-9D04-BA404CEB1D53}", # Minimum
                                  "{86AB2CC9-08BD-4643-B0F9-F82D006D72FF}"  # Additional 

        arch                    = "x64"
        latestDllVersion        = "14.44.35211.0" 

        dllPaths                = "$x64SystemFolder\msvcp140.dll"

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+.*?(?:2015(?:\s*(?:-|–|—|to)\s*(?:2019|2022))?|2017|2019|2022)\b.*?\b(?:Redistributable|Runtime|(?:Additional|Minimum)\s+Runtime)\b.*$'
    
        installers              = ".\2022\x64\vc_runtimeMinimum_x64.msi",
                                  ".\2022\x64\vc_runtimeAdditional_x64.msi"
    }
)

<#
.SYNOPSIS
Checks DLL versions for a VC++ product against a baseline.

.DESCRIPTION
Expands wildcarded DLL paths, reads file versions, and compares the highest discovered version
to a required baseline. If no DLL is present, returns Present=$false and Compliant=$true
(because MSI presence is validated separately).

.PARAMETER DllPaths
One or more paths (wildcards allowed) to DLLs that represent the redistributable.

.PARAMETER Baseline
The minimum compliant [version].

.OUTPUTS
pscustomobject with HighestPath, HighestVersion, Baseline, Compliant, Present, All
#>
function Test-VcRedistDllCompliance {
    param(
        [string[]]$dllPaths,
        [version]$Baseline
    )
    ### check versions of DLL files
    [array]$dlls = Get-Item $dllPaths -ErrorAction Ignore | 
        Select-Object -ExpandProperty VersionInfo | 
        Foreach-Object {
            if($_.FileVersionRaw){
                [PSCustomObject]@{
                    FileName = $_.FileName
                    Version  = $_.FileVersionRaw
                }
            } else {
                [PSCustomObject]@{
                    FileName = $_.FileName
                    Version  = [version]$_.FileVersion
                }
            }
        }

    if($dlls){
        $highestVersionDll = $dlls | Sort-Object Version -Descending | Select-Object -First 1

        $isCompliant = [version]$highestVersionDll.Version -ge $baseline

        return [PSCustomObject]@{
            HighestPath    = $highestVersionDll.FileName
            HighestVersion = [version]$highestVersionDll.Version
            Baseline       = $Baseline
            Compliant      = $isCompliant
            Present        = $true
            All            = $dlls
        }
    } else {
        # Why: No DLLs found usually means “no runtime present”. We don't force reinstall here;
        # MSI presence (or absence) is validated in the registered installations check.

        return [PSCustomObject]@{
            HighestPath    = $null
            HighestVersion = $null
            Baseline       = $Baseline
            Compliant      = $true # mark compliant when no .dll exists -- assuming no install, but if product is found in registry, mark for reinstall. 
            Present        = $false 
        }
    }
}

<#
.SYNOPSIS
Detects if an uninstall entry is a WiX/Burn bundle and resolves details.

.DESCRIPTION
Identifies Burn bundles via Bundle* registry property names, Package Cache evidence, and dependency
mapping (HKLM:\SOFTWARE\Classes\Installer\Dependencies). Returns arch when resolvable and the bundle's
uninstaller path if available.

.PARAMETER Install
A registry-derived object representing an uninstall entry.

.OUTPUTS
pscustomobject with IsWixBundle, Arch, WixUninstallerPath, ProductCodesInstalledByBundle
#>
function Test-IsWixBundle {
    param(
        [PSObject]$Install
    )

    $isWixBundle          = $false
    $installedByWixBundle = $false
    $wixUninstallerPath   = $null 

    # 1. Detect bundle-related properties
    $hasBundleProperties = $install.PSObject.Properties.Name | Where-Object {$_ -like "Bundle*"}
    if($hasBundleProperties){ 
        $isWixBundle = $true 
    } 

    # Why: Burn caches the bundle EXE under %ProgramData%\Package Cache\<bundle-id>\*.exe.
    # Extract the EXE path from BundleCachePath -> UninstallString -> QuietUninstallString -> Get-Item built manually; most to least reliable.
    $wixUninstallerPath = if($install.BundleCachePath -and $install.BundleCachePath -like "*Package Cache*.exe*"){
        $path = $install.BundleCachePath
        $isWixBundle = $true 
        if(Test-Path -LiteralPath $path){
            $path 
        }
    } elseif($install.UninstallString -and $install.UninstallString -like "*Package Cache*"){
        $path = ($install.UninstallString -replace '^(.+?\.exe).*','$1').Trim('"').Trim("'")
        $isWixBundle = $true 
        if(Test-Path -LiteralPath $path){
            $path
        }
    } elseif($install.QuietUninstallString -and $install.QuietUninstallString -like "*Package Cache*"){
        $path = ($install.QuietUninstallString -replace '^(.+?\.exe).*','$1').Trim('"').Trim("'")
        $isWixBundle = $true 
        if(Test-Path -LiteralPath $path){
            $path
        }
    } elseif($install.ProductCode){
        $path = Get-Item "$ENV:PROGRAMDATA\Package Cache\$($install.ProductCode)\*.exe" -ErrorAction Ignore | Select -ExpandProperty FullName 
        if($path){
            $isWixBundle = $true
            $path
        }
    }

    # 3. Check for state file used by Wix bundles
    if($wixUninstallerPath){
        $packageCachePath = Split-Path $wixUninstallerPath -Parent
        $hasStateRsmFile = Get-ChildItem -Path $packageCachePath -Filter "state.rsm" -File -ErrorAction Ignore 
        if($hasStateRsmFile){
            $isWixBundle = $true
        }
    }

    # 4. Resolve products installed by this bundle
    $productsInstalledByWixBundle = $installDependencyData | Where-Object {$_.DependentProductCode -eq $install.ProductCode}
    # try to resolve arch of products installed by bundle
    if($productsInstalledByWixBundle){
        # we only are flagging the wix bundle themselves, without this we would also flag the MSI registered installs as a wix bundle themselves
        #   albeit they are installed by the bundle, but they are not *the* separate bundle install entry
        if($install.ProductCode -notin $productsInstalledByWixBundle.ProductCode){
            $isWixBundle = $true
        }
        # Why: Burn bundles often register only in 32-bit uninstall view on 64-bit OS.
        # Prefer dependent MSI arch; fall back to OS bitness, then filename/display markers.

        $productCodesInstalledByBundle       = $productsInstalledByWixBundle.ProductCode 
        [array]$productArchInstalledByBundle = $productsInstalledByWixBundle.ProductArch | Sort-Object -Unique
    }

    # skip returning to $results if nothing met
    if( $isWixBundle -eq $false ) {
        return [PSCustomObject]@{
            IsWixBundle          = $isWixBundle
        }
    }

    # splice out the architecture type of the install from the installer name since it is always included
    #       Most reliable check is if all products installed by the bundle = 1 arch
    #       Next most reliable check is if 32bit OS, we know there are only 32bit installs.
    #       The next best thing is if all the installations done by this bundle were registered in x86 -> assume 32 bit, if registered in x64 -> assume 64 bit. 
    #       Since the WIX bundle registers in the 32bit path almost always, we cant assume based off the path of the bundle installation itself -- but the products it installed as a bundle. 
    #       Last resort is to check if x64/x86 or 64-bit/32-bit are present in display name
    [string]$installArch = if($productArchInstalledByBundle.Count -eq 1){
        $productArchInstalledByBundle[0]
    } elseif($Is64BitOS -eq $false){
        'x86'
    } elseif($wixUninstallerPath -like "*x64*"){
        'x64'
    } elseif($wixUninstallerPath -like "*x86*"){
        'x86'
    } elseif($install.DisplayName -match '(?i)\b(x64|64[-\s]?bit)\b'){
        'x64'
    } elseif($install.DisplayName -match '(?i)\b(x86|32[-\s]?bit)\b'){
        'x86'
    }

    return [PSCustomObject]@{
        IsWixBundle                   = $isWixBundle
        Arch                          = $InstallArch
        WixUninstallerPath            = $wixUninstallerPath
        ProductCodesInstalledByBundle = $productCodesInstalledByBundle
    }
}

<#
.SYNOPSIS
Enumerates registered MSI installations or Burn bundles for a product.

.DESCRIPTION
Searches x86/x64 uninstall hives (and optionally both for bundles), filters by DisplayName regex
and/or explicit ProductCode(s), and annotates each result with bundle metadata.

.PARAMETER RegexFilter
Case-insensitive regex matching DisplayName.

.PARAMETER ProductCodes
Expected MSI ProductCode(s) for exact matching.

.PARAMETER Arch
x86 or x64 view to search.

.PARAMETER Wix
When set, searches both x86/x64 views and returns only WiX/Burn bundles.

.OUTPUTS
pscustomobject[] with DisplayName, ProductCode, Arch, PSPath, IsWixBundle, InstalledByWixBundle, WixUninstallerPath
#>
function Get-Installs {
    param(
        [string]$RegexFilter,
        [string[]]$ProductCodes,
        [ValidateSet('x86','x64')][string]$Arch,
        [switch]$Wix = $false
    )

    $root = if($wix){
        # when identifying WIX bundles, we need to check all uninstall registry roots
        #  often the bundle runs as 32bit thus registering itself as 32 bit even if the product(s) installed within the bundle is 64bit
        @($x64Uninstall, $x86Uninstall) 
    } else {
        switch($Arch){
            'x86' {
                $x86Uninstall
            }
            'x64' {
                $x64Uninstall
            }
        }
    }

    [array]$matchingInstalls = Get-ChildItem $root -ErrorAction Ignore | 
        Where-Object { $_.PsPath -like "*{*-*-*-*}"} | # fixes errors if host has unexpected (non-guid) uninstall entries in registry 
        Foreach-Object { Get-ItemProperty $_.PsPath } |
        Where-Object { $_.DisplayName } |
        Select-Object *,@{Name='ProductCode';E={$_.PSChildName}} |
        Where-Object { $_.DisplayName -match $regexFilter -or $_.ProductCode -in $ProductCodes} |
        Where-Object { $_.DisplayName -notmatch '(?i)\b(Debug|Preview)\b' } # exclude debug/preview runtimes
    
    [array]$results = foreach($install in $matchingInstalls){
        $wixBundle = Test-IsWixBundle -Install $install

        if($wixBundle.IsWixBundle){
            # Architecture is usually determined off the location the install is registered in the registery
            #  in Test-IsWixBundle we see what products are installed as by the bundle via Dependency mapping
            # if they all have the same arch, we calculate this property 
            $installArch = $wixBundle.Arch

            # do not return data if arch is mismatch
            if($installArch -ne $Arch){
                continue
            }
        } else {
            # if this isnt a wix bundle and the wix switch = true, skip returning this obj
            if($wix){
                continue
            }
            
            $installArch = $Arch # if not a WiX search against x86+x64 use the passed $Arch as-is
        }

        [PSCustomObject]@{
            DisplayName          = $install.DisplayName
            ProductCode          = $install.ProductCode
            Arch                 = $installArch

            PSPath               = $install.PSPath

            IsWixBundle          = $wixBundle.IsWixBundle
            InstalledByWixBundle = $wixBundle.ProductCodesInstalledByBundle
            WixUninstallerPath   = $wixBundle.WixUninstallerPath
        }
    }

    return $results
}


<#
.SYNOPSIS
Evaluates a VC++ product’s compliance (DLLs, bundles, MSI registrations).

.DESCRIPTION
Combines DLL baseline results with uninstall database state:
- Flags non-compliance for WiX/Burn bundle installs.
- Computes expected/unexpected/missing MSI ProductCodes.
- Allows special handling for orphaned DLLs (2005/2008) when configured.

.PARAMETER Product
A single catalog entry (hashtable) from Get-VcRedistCatalog.

.OUTPUTS
Three objects (DLL check, WiX check, Registered Installations check)
#>
function Test-VcRedistCompliance {
    param($product)

    # Step 1 – DLL compliance
    $dllCompliance = Test-VcRedistDllCompliance -DllPaths $product.dllPaths -Baseline $product.latestDllVersion
    
    $dllComplianceResult = [PSCustomObject]@{
        Product   = $product.ProductName
        Check     = 'DLL Version Check'
        Present   = $dllCompliance.Present
        Path      = $dllCompliance.HighestPath
        Version   = $dllCompliance.HighestVersion
        Compliant = $dllCompliance.Compliant
        Note      = "greater than or equal to $($product.latestDllVersion) `n(compliant if no DLL found)"
    }

    # Step 2 – WiX compliance
    [array]$wixBundlesInstalled = Get-Installs -RegexFilter $product.RegexFilter -Arch $product.Arch -Wix

    $wixBundleProductCodes = [array]$wixBundlesInstalled.InstalledByWixBundle + [array]$wixBundlesInstalled.ProductCode

    $wixBundlesComplianceResult = [pscustomobject]@{
        Product               = $product.ProductName
        Check                 = 'WiX Bundle Installations'
        Compliant             = ($wixBundlesInstalled.Count -eq 0)
        Count                 = $wixBundlesInstalled.Count
        WixBundleCodes        = [array]$wixBundlesInstalled.ProductCode
        InstalledByWixBundle  = [array]$wixBundlesInstalled.InstalledByWixBundle
        WixUninstallPaths     = [array]$wixBundlesInstalled.WixUninstallerPath
        Note                  = "Redistributables installed via WiX bundle are always non-compliant"
    }

    # Step 3 – Registered Installations compliance
    [array]$productCodes = $product.productCodes
    [array]$installs     = Get-Installs -RegexFilter $product.RegexFilter -Arch $product.Arch | Where-Object {$_.IsWixBundle -eq $false}
    
    [array]$expectedInstalls   = $installs | Where-Object {$_.ProductCode -in $productCodes    -and $_.ProductCode -notin $wixBundleProductCodes}
    [array]$unexpectedInstalls = $installs | Where-Object {$_.ProductCode -notin $productCodes -and $_.ProductCode -notin $wixBundleProductCodes}
    [array]$wixInstalls        = $installs | Where-Object {$_.ProductCode -in $wixBundlesInstalled.InstalledByWixBundle }

    [array]$missingInstalls = $productCodes | Where-Object {$_ -notin $installs.ProductCode}

    $compliantIfOrphanedDll = if($product.doNotReinstallIfOrphanedDll){
        $true
    } else { 
        $false 
    }
    
    $registeredInstallsComplianceResult = [pscustomobject]@{
        Product                  = $product.ProductName
        Check                    = 'Registered Installations'
        Expected                 = [array]$expectedInstalls.ProductCode
        Missing                  = $missingProductCodes
        Unexpected               = [array]$unexpectedInstalls.ProductCode
        InstalledByWix           = [array]$wixInstalls.ProductCode
        Compliant                = ($missingInstalls.Count -eq 0 -and $unexpectedInstalls.Count -eq 0 -and $wixInstalls.Count -eq 0 -and $expectedInstalls.count -eq $productCodes.Count) -or `
                                   ($installs.Count -eq 0 -and $wixInstalls.count -eq 0 -and $dllComplianceResult.Present -eq $false) -or `
                                   ($installs.Count -eq 0 -and $dllComplianceResult.Compliant -eq $true -and $dllComplianceResult.Present -eq $true -and $compliantIfOrphanedDll -eq $true -and $wixInstalls.count -eq 0) # mark compliant for cases where there may not be a registered install e.g. 2005/2008 installs to WinSxS, if that version is higher, we dont want to reinstall even if its not registered 
        Count                    = $installs.Count
        Note                     = "Compliant when expected ProductCode(s) present, not installed by WiX, and the .dll version check is compliant `n(compliant if no install(s) found and no .dll found) `n(2005/2008 can be compliant without a registered install as long the .dll version check passes)"
    }

    # Return the 3 objects
    return $dllComplianceResult, $wixBundlesComplianceResult, $registeredInstallsComplianceResult
}

$allCompliant = $true

foreach($product in $products){
    # Skip x64 on 32-bit OS
    if (-not [Environment]::Is64BitOperatingSystem -and $product.arch -eq 'x64' -or ($product.OnlyOn32BitOs -and $Is64BitOS)) { continue }

    $complianceResults = Test-VcRedistCompliance -product $product

    $dllCompliance               = $complianceResults[0]
    $wixBundleCompliance         = $complianceResults[1]
    $registeredInstallCompliance = $complianceResults[2]

    if (-not ($dllCompliance.Compliant -and $wixBundleCompliance.Compliant -and $registeredInstallCompliance.Compliant)) {
        $allCompliant = $false
    }
}

# WHY MECM Application Detection script interpret any output as this "Application doesnt need ran/installed" aka the updater doesnt need to run; no output means Not Detected = updater needs to be ran
if ($allCompliant) {
    Write-Output 'All Microsoft Visual C++ Redistributables are compliant'
}