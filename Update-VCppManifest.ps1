function Get-MSIProperty {
    param(
        [parameter(ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("ProductCode", "ProductVersion", "ProductName", "Manufacturer", "ProductLanguage", "FullVersion")]
        [string]$Property = "ProductVersion"
    )
    Process {
        try {
            # Read property from MSI database
            $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
            $MSIDatabase = $WindowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $WindowsInstaller, @($Path.FullName, 0))
            $Query = "SELECT Value FROM Property WHERE Property = '$($Property)'"
            $View = $MSIDatabase.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $MSIDatabase, ($Query))
            $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $null) | Out-Null
            $Record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $View, $null)
            $Value = $Record.GetType().InvokeMember("StringData", "GetProperty", $null, $Record, 1)

            # Commit database and close view
            $MSIDatabase.GetType().InvokeMember("Commit", "InvokeMethod", $null, $MSIDatabase, $null) | Out-Null
            $View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null) | Out-Null
            $MSIDatabase = $null
            $View = $null 

            return $Value
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
    End {
        # Run garbage collection and release ComObject
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WindowsInstaller) | Out-Null
        [System.GC]::Collect() | Out-Null
    }
}

$products = Get-Content -Raw .\VisualCppRedistsManifest.json | ConvertFrom-Json

$changesMade = $false
$verbose     = $true 

foreach($product in $products){
    Write-Output $product.productName
    # sync ProductCodes from installers; when there are multiple installers, we assume the indexes between .ProductCode and .Installers match i.e. Minimum = 0, Additional = 1
    for($i = 0; $i -lt @($product.productCodes).Count; $i++){
        $installer   = Get-Item @($product.installers)[$i]

        $msiProductCode = Get-MSIProperty -Path $installer -Property "ProductCode"

        if($msiProductCode -ne @($product.productCodes)[$i]){
            Write-Output "Product Code: [$i] $(@($product.productCodes)[$i]) -> $($msiProductCode)"
            $changesMade = $true 
            @($product.productCodes)[$i] = $msiProductCode
        } elseif($verbose) {
            "$(@($product.productCodes)[$i]) == $($msiProductCode)"
        }
    }

    # sync latestDllVersion
    $installerFolder = Split-Path -Parent $product.installers | Sort-Object -Unique
    $dllFileName     = Split-Path -Leaf $product.dllPaths     | Sort-Object -Unique

    $dllFileVersion = Get-ChildItem -Recurse -Path $installerFolder -Filter $dllFileName | Select-Object -ExpandProperty VersionInfo | 
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
        } | Select-Object -ExpandProperty Version | Sort-Object -Unique

    if($dllFileVersion -ne $product.latestDllVersion){
        Write-Output "DLL Version: $($product.latestDllVersion) -> $($dllFileVersion.ToString())"
        $changesMade = $true 
        $product.latestDllVersion = $dllFileVersion.ToString()
    } elseif($verbose) {
        "$($product.latestDllVersion) == $($dllFileVersion.ToString())"
    }
}

if($changesMade){
    Write-Output "Changes made; updating file: VisualCppRedistsManifest.json"
    $products | ConvertTo-Json | Set-Content .\VisualCppRedistsManifest.json -Encoding UTF8
}