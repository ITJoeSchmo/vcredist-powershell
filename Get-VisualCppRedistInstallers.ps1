<#
.SYNOPSIS
    Retrieves the latest (or prerelease) asset download URL from a GitHub repository, and optionally downloads the file.

.DESCRIPTION
    The Get-GitHubRelease function fetches the latest release (or the latest prerelease if -IncludePrerelease is specified) 
    from the specified GitHub repository. It filters release assets based on a file name pattern using * wildcards. 

    If a download path is provided using the -DownloadPath parameter, the function downloads the matched asset to that location. 
    Otherwise, it returns the download URL.

.PARAMETER repo
    The GitHub repository in the format 'owner/repo' (e.g., "ip7z/7zip").

.PARAMETER fileNamePattern
    A wildcard pattern used to match the desired asset file name (e.g., "7z*.msi").

.PARAMETER downloadPath
    Optional. The path on the local file system where the asset will be downloaded. 
    If not provided, the function only returns the asset's download URL.

.PARAMETER IncludePrerelease
    Switch. If specified, the function considers prereleases when fetching the latest release.

.EXAMPLE
    PS> Get-GitHubRelease -repo "ip7z/7zip" -fileNamePattern "7z*.msi"

    PS> https://github.com/ip7z/7zip/releases/download/24.09/7z2409-x64.msi
    PS> https://github.com/ip7z/7zip/releases/download/24.09/7z2409.msi

    Returns the download URL(s) for the latest stable 7-Zip release matching the file pattern.

.EXAMPLE
    PS> Get-GitHubRelease -repo "ip7z/7zip" -fileNamePattern "7z*.msi" -downloadPath 'C:\Tools\7-Zip'

    PS> C:\Tools\7-Zip\7z2409-x64.msi
    PS> C:\Tools\7-Zip\7z2409.msi

    Downloads the matched release asset to the specified path.

.EXAMPLE
    PS> Get-GitHubRelease -repo "ip7z/7zip" -fileNamePattern "7z*.msi"  -IncludePrerelease

    Returns the download URL from the latest *prerelease* matching the file pattern.

.NOTES
    Author: Joey Eckelbarger
    Created: 2025-04-22
#>
function Get-GitHubRelease{
    param(
        [string]$Repo,
        [string]$FileNamePattern,
        [string]$DownloadPath,
        [switch]$IncludePrelease = $false
    )
    
    if ($IncludePrelease) {
        $releasesUri = "https://api.github.com/repos/$repo/releases"
        [array]$downloadUris = ((Invoke-RestMethod -Method GET -Uri $releasesUri)[0].assets | Where-Object name -like $filenamePattern ).browser_download_url
    } else {
        $releasesUri = "https://api.github.com/repos/$repo/releases/latest"
        [array]$downloadUris = ((Invoke-RestMethod -Method GET -Uri $releasesUri).assets | Where-Object name -like $filenamePattern ).browser_download_url
    }

    if($downloadPath){
        $progressPreference = 'silentlyContinue' # this progress UI slows down download speeds so we disable it. 

        foreach($fileUri in $downloadUris){
            $fulldownloadPath = Join-Path -Path $downloadPath -ChildPath $(Split-Path -Path $fileUri -Leaf)
            Invoke-WebRequest -Uri $fileUri -OutFile $fulldownloadPath  
            
            $fulldownloadPaths += $fulldownloadPath  
        }

        return $fulldownloadPaths
    } else {
        return $downloadUris
    }
}
"Downloading latest Visual C++ redistributable repack from GitHub abbodi1406/vcredist..."
$latestVcppRedistPackage = Get-GitHubRelease -repo "abbodi1406/vcredist" -fileNamePattern "VisualCppRedist_AIO_x86_x64.exe" -DownloadPath $PWD
Unblock-File $latestVcppRedistPackage

$progressPreference = 'silentlyContinue' # this progress UI slows down download speeds so we disable it. 
"Downloading portable 7-zip exe to extract the installers..."
Invoke-WebRequest -Uri "https://www.7-zip.org/a/7zr.exe" -OutFile "$PWD\7zr.exe"
Unblock-File "$PWD\7zr.exe"

.\7zr.exe x "$latestVcppRedistPackage" -o"$PWD" -y
"Cleaning up..."
Remove-Item $latestVcppRedistPackage, "$PWD\7zr.exe" -Force