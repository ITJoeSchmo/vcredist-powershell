#Requires -RunAsAdministrator

if([Environment]::Is64BitOperatingSystem){
    $x86SystemFolder = "$ENV:SYSTEMROOT\SysWOW64"
    $x64SystemFolder = "$ENV:SYSTEMROOT\System32"

    $is64bit = $true

    $x86uninstallRegistry = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    $x64uninstallRegistry = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
} else {
    $x86SystemFolder = "$ENV:SYSTEMROOT\System32"

    $is64bit = $false

    $x86uninstallRegistry = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
}

Start-Transcript 

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
    }

    
    @{ # VC++ 2008 (major 9) x86
        productName             = "Microsoft Visual C++ 2008 Redistributable - x86"
        productCodes             = "{9BE518E6-ECC6-35A9-88E4-87755C07200F}"
        arch                    = "x86"
        latestDllVersion        = "9.0.30729.7523" 

        dllPaths                = "$ENV:SYSTEMROOT\WinSxS\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b*\msvcp90.dll",
                                  "$ENV:SYSTEMROOT\WinSxS\Fusion\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b*\*\*\msvcp90.dll"

        msiFeatureRegistry      = "HKLM:\SOFTWARE\Classes\Installer\Features\6E815EB96CCE9A53884E7857C57002F0" # VC_RED_enu_

        regexFilter             = '^(?i)\s*(?:Microsoft\s+)?Visual\s*C\+\+\s*2008\b.*?\b(?:Redistributable|Runtime)\b.*$'

        installers              = ".\2008\x86\vc_red.msi"
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
    }

    
    <#@{ # VS 2010 Tools for Office Runtime (major 10) x86
        productName          = "Microsoft  Visual Studio 2010 Tools for Office Runtime"
        productCodes         = "{888E1022-9CD3-32AC-BE6B-668FF6ABA136}"
        arch                 = "x86"

        dllPaths             = "$env:CommonProgramFiles\Microsoft Shared\VSTO\vstoee.dll"
        msiFeatureRegistry   = "HKLM:\SOFTWARE\Classes\Installer\Features\2201E8883DC9CA23EBB666F86FBA1A63" # TRIN_TRIR_SETUP

        
        latestDllVersion     = '10.0.60917.0'
        latestDisplayVersion = "10.0.60922"
    }
    @{ # VS 2010 Tools for Office Runtime (major 10) x64
        productName          = "Microsoft Visual Studio 2010 Tools for Office Runtime (x64)"
        productCodes         = "{610487D9-3460-328A-9333-219D43A75CC5}"
        arch                 = "x64"

        dllPaths             = "$env:CommonProgramW6432\Microsoft Shared\VSTO\vstoee.dll"
        msiFeatureRegistry   = "HKLM:\SOFTWARE\Classes\Installer\Features\9D7840160643A823393312D9347AC55C" # TRIN_TRIR_SETUP
        
        latestDllVersion     = '10.0.60917.0'
        latestDisplayVersion = "10.0.60922"
    }#>
    
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


foreach($product in $products){
    $needsUpdated                   = $false
    $needsReinstalled               = $false

    $dllsPresent                    = $false

    $nonCompliantProductsInRegistry = $null
    $compliantProductsInRegistry    = $null
    $matchingProductsInRegistry     = $null 
    $dlls                           = $null 

    $ifDllIsOrphanedReinstall       = if($product.productName -notlike "*2005*" -and $product.productName -notlike "*2008*"){
        $true
    } else {
        $false 
    }

    if($is64bit -eq $false -and $product.arch -eq "x64"){
        write-warning "Skipping 64-bit product check: $($product.productName)"
        continue
    }


    Write-Output "Checking $($product.productName)"

    ### check versions of DLL files
    [array]$dlls = Get-Item $product.dllPaths -ErrorAction Ignore | Select-Object -ExpandProperty VersionInfo | Select-Object FileName,@{Name='FileVersion';E={$_.FileVersionRaw}}
    
    if($dlls){
        $dllsPresent = $true
        Write-Output "- Found $($dlls.count) associated .dll files:"
        Write-Output $($dlls.FileName | % { "`t$_" } )
        Write-Output ""
        $latestVersionDLL = $dlls | Sort-Object FileVersion -Descending | Select-Object -First 1
        Write-Output "`tHighest version: $($latestVersionDLL.FileVersion)"
        Write-Output "`tPath: $($latestVersionDLL.FileName)"
        Write-Output ""
        if([version]$latestVersionDLL.FileVersion -ge [version]$product.latestDllVersion){
            # Newer or equal version installed
            Write-Output "`tHighest version DLL is compliant: $($latestVersionDLL.FileVersion) is greater than or equal to $($product.latestDllVersion)"
        } else {
            Write-Output "`t.dll version is lower than baseline: $($latestVersionDLL.FileVersion) is less than $($product.latestDllVersion)"
            $needsUpdated = $true 
        }
        Write-Output ""
    } else {
        Write-Output  "- No DLLs found."
    }



   ### find registered WIX bundle installations via uninstall registry using displayname regex filter 

   [array]$nonCompliantWixBundles = if($is64bit){
        if($product.arch -eq "x64"){
            # WIX x64 
            Get-ChildItem $x64uninstallRegistry | Foreach-Object { Get-ItemProperty $_.PsPath} | Where-Object {$_.DisplayName -match $product.regexFilter} | Where-Object {$_.UninstallString -like "*Package Cache*" -and $_.DisplayName -like "*x64*"}    | Select DisplayName,@{Name="ProductCode";E={$_.PSChildName}},@{Name='InstallType';E={"WIX"}},UninstallString,QuietUninstallString,PSPath
            # WIX x86
            Get-ChildItem $x86uninstallRegistry | Foreach-Object { Get-ItemProperty $_.PsPath} | Where-Object {$_.DisplayName -match $product.regexFilter} | Where-Object {$_.UninstallString -like "*Package Cache*" -and $_.DisplayName -like "*x64*"}    | Select DisplayName,@{Name="ProductCode";E={$_.PSChildName}},@{Name='InstallType';E={"WIX"}},UninstallString,QuietUninstallString,PSPath
        } else {
            # WIX x86
            Get-ChildItem $x86uninstallRegistry | Foreach-Object { Get-ItemProperty $_.PsPath} | Where-Object {$_.DisplayName -match $product.regexFilter} | Where-Object {$_.UninstallString -like "*Package Cache*" -and $_.DisplayName -notlike "*x64*"}    | Select DisplayName,@{Name="ProductCode";E={$_.PSChildName}},@{Name='InstallType';E={"WIX"}},UninstallString,QuietUninstallString,PSPath
        }
    } else {
        # WIX x86
        Get-ChildItem $x86uninstallRegistry | Foreach-Object { Get-ItemProperty $_.PsPath} | Where-Object {$_.DisplayName -match $product.regexFilter} | Where-Object {$_.UninstallString -like "*Package Cache*"}    | Select DisplayName,@{Name="ProductCode";E={$_.PSChildName}},@{Name='InstallType';E={"WIX"}},UninstallString,QuietUninstallString,PSPath
    }
    # uninstall ANY found WIX bundles 
    if($nonCompliantWixBundles){
        $needsReinstalled = $true 
        Write-Output "- Uninstalling $($nonCompliantWixBundles.count)non-compliant WIX bundles for product: $($product.productName)"
        foreach($uninstall in $nonCompliantWixBundles){
            $uninstallExePath = if($uninstall.QuietUninstallString){
                ($uninstall.QuietUninstallString -replace '^(.+?\.exe).*','$1').Trim('"')
            } elseif($uninstall.UninstallString){
                ($uninstall.UninstallString -replace '^(.+?\.exe).*','$1').Trim('"')
            } elseif($uninstall.ProductCode){
                Get-Item "$ENV:PROGRAMDATA\Package Cache\$($uninstall.ProductCode)\vc*.exe" | Select -ExpandProperty FullName
            }

            if(Test-Path -LiteralPath $uninstallExePath){
                Write-Output "`t- Uninstalling $($uninstall.DisplayName)"
                Start-Process $uninstallExePath -ArgumentList '/uninstall','/quiet','/norestart' -Wait
            } else {
                Write-Warning "Unable to locate WIX uninstaller for product: $($uninstall.DisplayName); registry will be cleaned and the latest version installed."
            }

            # after uninstall, check + clean registry if needed
            Start-Sleep -seconds 5 # small buffer
            # clean up registry if needed
            if(Test-Path -LiteralPath $uninstall.PSPath){
                Remove-Item $uninstall.PSPath -Force -Recurse
            }
        }
        Write-Output ""
    } else {
        Write-Output "- No WIX bundle installations found"
    }

   ### find registered MSI installations via uninstall registry by matching displayname regex
   [array]$matchingProductsInRegistry = if($is64bit){
        if($product.arch -eq "x64"){
            # MSI x64
            Get-ChildItem $x64uninstallRegistry | Foreach-Object { Get-ItemProperty $_.PsPath} | Where-Object {$_.DisplayName -match $product.regexFilter} | Select DisplayName,@{Name="ProductCode";E={$_.PSChildName}},@{Name='InstallType';E={"MSI"}},UninstallString,QuietUninstallString,PSPath | Where-Object {$_.ProductCode -notin $nonCompliantWixBundles.ProductCode}
        } else {
            # MSI x86
            Get-ChildItem $x86uninstallRegistry | Foreach-Object { Get-ItemProperty $_.PsPath} | Where-Object {$_.DisplayName -match $product.regexFilter} | Select DisplayName,@{Name="ProductCode";E={$_.PSChildName}},@{Name='InstallType';E={"MSI"}},UninstallString,QuietUninstallString,PSPath | Where-Object {$_.ProductCode -notin $nonCompliantWixBundles.ProductCode}
        }
    } else {
        # MSI x86
        Get-ChildItem $x86uninstallRegistry | Foreach-Object { Get-ItemProperty $_.PsPath} | Where-Object {$_.DisplayName -match $product.regexFilter} | Select DisplayName,@{Name="ProductCode";E={$_.PSChildName}},@{Name='InstallType';E={"MSI"}},UninstallString,QuietUninstallString,PSPath | Where-Object {$_.ProductCode -notin $nonCompliantWixBundles.ProductCode}
    }

    if($matchingProductsInRegistry){
        Write-Output "- Found $($matchingProductsInRegistry.count) installations in registry by DisplayName:"
        # if there are 2 product codes, ensure both minimum and additional are installed -- if not, we need to flag for reinstallation.
        if($product.productCodes.Count -gt 1){
            $minimumProductCode    = $product.productCodes[0]
            $additionalProductCode = $product.productCodes[1]

            if($minimumProductCode -notin $matchingProductsInRegistry.ProductCode){
                $needsReinstalled = $true
            }
            if($additionalProductCode -notin $matchingProductsInRegistry.ProductCode){
                $needsReinstalled = $true
            }
        }    

        # if needsUpdated or needsReinstalled we know that all the registered installations need to be seen as non-compliant + uninstalled before the latest package is re-installed 
        if($needsUpdated -or $needsReinstalled){
            [array]$nonCompliantProductsInRegistry = $matchingProductsInRegistry 
        } else {
            [array]$nonCompliantProductsInRegistry = $matchingProductsInRegistry | Where-Object {$_.ProductCode -notin [array]$product.productCodes}
        }

        [array]$compliantProductsInRegistry = $matchingProductsInRegistry | Where-Object {$_.ProductCode -in [array]$product.productCodes -and $_ -notin $nonCompliantProductsInRegistry}
        if($compliantProductsInRegistry){
            Write-Output "`t- $($compliantProductsInRegistry.count) compliant:"
            Write-Output $($compliantProductsInRegistry | % { 
                "`tNAME:        $($_.DisplayName)" 
                "`tPRODUCTCODE: $($_.ProductCode)" 
                "`tINSTALLTYPE: $($_.InstallType)" 
                "`tPATH:        $($_.PSPath)"
                ""
            })
        }

        if($nonCompliantProductsInRegistry){
            Write-Output "`t- $($nonCompliantProductsInRegistry.count) non-compliant:"
            Write-Output $($nonCompliantProductsInRegistry | % { 
                "`tNAME:        $($_.DisplayName)" 
                "`tPRODUCTCODE: $($_.ProductCode)" 
                "`tINSTALLTYPE: $($_.InstallType)" 
                "`tPATH:        $($_.PSPath)"
                ""
            })
        }
    } else {
        Write-Output "- No registered installations found"

        # if we have dll present but no registered installation, we need to install the latest over to fix orphaned DLLs. Doesn't apply to 2005/2008 as they are installed in WinSxS (and arent expected to be registered)
        if($dllsPresent -and $ifDllIsOrphanedReinstall){
            $needsReinstalled = $true 
        }
    }

    if($nonCompliantProductsInRegistry.count -gt 0){
        Write-Output "- Uninstalling non-compliant registered installations for product: $($product.productName)"
        foreach($uninstall in $nonCompliantProductsInRegistry){
            Write-Output "`t- Uninstalling $($uninstall.DisplayName)"
            Start-Process "MsiExec.exe" -ArgumentList "/X$($uninstall.ProductCode)","/norestart","/quiet" -Wait
            # after uninstall, check + clean registry if needed
            Start-Sleep -seconds 5 # small buffer
            # clean up registry if needed
            if(Test-Path -LiteralPath $uninstall.PSPath){
                Remove-Item $uninstall.PSPath -Force -Recurse
            }
        }
    }

    if($needsUpdated -or $needsReinstalled){
        Write-Output "Installing latest packaged version of $($product.productName)"

        foreach($installer in [array]$product.installers){
            Start-Process "MsiExec.exe" -ArgumentList "/i",$installer,"/qn","/norestart" -Wait 
        }
    }

    Write-Output ""
    Write-Output ""
    Write-Output ""

    if($compliantProductsInRegistry.Count    -eq $product.productCodes.Count -and `
       $nonCompliantProductsInRegistry.count -eq 0                           -and `
       $needsUpdated                         -eq $false                      -and `
       $needsReinstalled                     -eq $false                          ){
            Write-Output ""
            Write-Output ""
            Write-Output ""
            Write-Output "- ALL COMPLIANCE CHECKS PASSED; NO UPDATES OR RE-INSTALL NEEDED FOR: $($product.productName)"
            Write-Output "`tDLL Version $($latestVersionDLL.FileVersion) is greater than or equal to $($product.latestDllVersion)"
            Write-Output "`tExpected ProductCode(s) found in registry: $($compliantProductsInRegistry.ProductCode -join ', ')"
            Write-Output ""
            Write-Output ""
            continue
    }
}

Stop-Transcript
