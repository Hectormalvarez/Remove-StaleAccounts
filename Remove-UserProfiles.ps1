function Remove-UserProfiles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$UserList,
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\Logs",
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )

    # Create log file
    $logFile = Join-Path $LogPath "ProfileRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    New-Item -ItemType Directory -Force -Path (Split-Path $logFile)

    # Check initial drive space
    $drive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
    $initialFreeSpace = $drive.FreeSpace
    $initialFreeSpaceGB = [math]::Round($initialFreeSpace / 1GB, 2)
    $message = "Initial free space on C: drive: $initialFreeSpaceGB GB"
    Write-Host $message -ForegroundColor Cyan
    Add-Content -Path $logFile -Value $message

    # Initialize total space saved
    $totalSpaceSaved = 0
    $successCount = 0
    $failureCount = 0

    foreach ($profile in $UserList) {
        try {
            Write-Host "`nProcessing profile: $profile" -ForegroundColor Yellow
            
            $userProfile = Get-WMIObject -Class Win32_UserProfile | 
                Where-Object { $_.LocalPath -like "*$profile*" }
            
            if ($userProfile) {
                # Check folder size before deletion
                $profilePath = "C:\Users\$profile"
                if (Test-Path $profilePath) {
                    $folderSize = (Get-ChildItem $profilePath -Recurse -ErrorAction SilentlyContinue | 
                        Measure-Object -Property Length -Sum).Sum
                    $folderSizeMB = [math]::Round($folderSize / 1MB, 2)
                    Write-Host "Profile size: $folderSizeMB MB" -ForegroundColor Cyan
                } else {
                    $folderSize = 0
                    Write-Host "Profile folder not found" -ForegroundColor Yellow
                }

                if (-not $WhatIf) {
                    try {
                        # Try WMI deletion first
                        $userProfile.Delete()
                        $message = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Successfully removed profile via WMI: $profile (Size: $folderSizeMB MB)"
                        Write-Host $message -ForegroundColor Green
                        $successCount++
                    }
                    catch {
                        # If WMI fails, try manual deletion
                        Write-Host "WMI deletion failed, attempting manual removal..." -ForegroundColor Yellow
                        
                        # Remove profile from registry
                        $registryPaths = @(
                            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*"
                            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid\*"
                        )
                        
                        foreach ($regPath in $registryPaths) {
                            Get-ItemProperty -Path $regPath | 
                            Where-Object { $_.ProfileImagePath -like "*$profile*" } | 
                            ForEach-Object { Remove-Item $_.PSPath -Force -Recurse }
                        }

                        # Remove profile directory
                        if (Test-Path $profilePath) {
                            Remove-Item -Path $profilePath -Force -Recurse -ErrorAction Stop
                        }
                        
                        $message = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Successfully removed profile via manual deletion: $profile (Size: $folderSizeMB MB)"
                        Write-Host $message -ForegroundColor Green
                        $successCount++
                    }
                } else {
                    $message = "WHATIF: Would remove profile: $profile (Size: $folderSizeMB MB)"
                    Write-Host $message -ForegroundColor Cyan
                }
                Add-Content -Path $logFile -Value $message
                $totalSpaceSaved += $folderSize
            }
            else {
                $message = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Profile not found: $profile"
                Write-Host $message -ForegroundColor Yellow
                Add-Content -Path $logFile -Value $message
                $failureCount++
            }
        }
        catch {
            $message = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Error removing profile $profile : $($_.Exception.Message)"
            Write-Host $message -ForegroundColor Red
            Add-Content -Path $logFile -Value $message
            $failureCount++
        }
    }

    # Check final drive space
    $drive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
    $finalFreeSpace = $drive.FreeSpace
    $finalFreeSpaceGB = [math]::Round($finalFreeSpace / 1GB, 2)
    $totalSpaceSavedGB = [math]::Round($totalSpaceSaved / 1GB, 2)
    $actualSpaceFreedGB = [math]::Round(($finalFreeSpace - $initialFreeSpace) / 1GB, 2)

    $summary = @"

-------- Operation Summary --------
Initial free space: $initialFreeSpaceGB GB
Final free space: $finalFreeSpaceGB GB
Total profile sizes: $totalSpaceSavedGB GB
Actual space freed: $actualSpaceFreedGB GB
Successful removals: $successCount
Failed removals: $failureCount
--------------------------------
"@

    Write-Host $summary -ForegroundColor Green
    Add-Content -Path $logFile -Value $summary

    Write-Host "`nProfile removal complete. Check log file at: $logFile" -ForegroundColor Cyan

    # Return results as an object
    return [PSCustomObject]@{
        InitialFreeSpace = $initialFreeSpaceGB
        FinalFreeSpace = $finalFreeSpaceGB
        TotalProfileSizes = $totalSpaceSavedGB
        ActualSpaceFreed = $actualSpaceFreedGB
        SuccessCount = $successCount
        FailureCount = $failureCount
        LogFile = $logFile
    }
}
