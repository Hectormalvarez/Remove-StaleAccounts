#Requires -Modules ActiveDirectory

function Remove-StaleAccounts {
    <#
    .SYNOPSIS
    Remove accounts that are no longer actively using a computer.

    .DESCRIPTION
    connects to a remote computer and collects the folder names within
    c:\users which matches up with ADUser object SamAccountName property
    and uses the folder names to find accounts that are no longer actively using 

    .PARAMETER ComputerName
    System.String ComputerName
    name of remote computer. This parameter is mandatory.

    .INPUTS
    System.String ComputerName
    None You cannot pipe objects to this function.

    .OUTPUTS
    System.Object
    $Output This variable contains the output of the script in a PSCustomObject 
    with the following properties:
    LocalUserFolders -  local user folders found
    ADUserResults - results of looking up users in Active Directory
    UsersNotInAD -  users not found in Active Directory
    UsersInDeprovisioningOU -  users found in a deprovisioning OU
    UsersAtDifferentStore -  users whose home location doesn't match the store
    WorkstationADObject - the Active Directory object of the workstation

    .NOTES
    Computer validation check
	- Try to create remote session; throw error and stop script if it fails

	1. Gets folders on c:\users of the remote computer
	2. Runs aduser against the folder names (sam account names)
	3. Identify user folders that can be removed
		a. not found in active directory - clearNotInAD
		b. home location is different from computer - clearNotAtStore
			i. Parse OU location of workstation to begin script
			ii. Compare region OU and store OU to user
			iii. Put users not matching store in list
		c. Users in deprovisioning - clearRecentlyLeft
	4. Default to just display results
    Options to clear a certain group, or clearAll

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )
    
    Begin {
        try {            
            Import-Module ActiveDirectory
            if (-not (Get-Module -Name ActiveDirectory)) {
                Write-Error "The Active Directory module is required. Please import it and try again."
                return
            }
            
            # Verify computer exists in AD first
            $adComputer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
            if (-not $adComputer) {
                throw "Computer not found in Active Directory"
            }

            # Test connection before creating session
            if (-not (Test-Connection -ComputerName $ComputerName -Quiet -Count 1)) {
                throw "Cannot connect to $ComputerName"
            }

            $RemoteSession = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            Write-Error "Initialization failed: $_"
            throw
        }

        $Output = [pscustomobject]@{
            LocalUserFolders        = @() 
            ADUserResults           = @()
            UsersNotInAD            = @()
            UsersInDeprovisioningOU = @()
            UsersAtDifferentStore   = @() 
            WorkstationADObject     = $null
            UsersToRemove           = @()
        }

        $Output.WorkstationADObject = $adComputer

        Invoke-Command -Session $RemoteSession -ScriptBlock {
            function Get-LocalUserFolders {
                <#
                 .SYNOPSIS
                    Retrieves local user folders
                 .DESCRIPTION
                    Returns an array containing the names of local user folders, excluding system accounts
                 #>
                 
                $SystemAccounts = @(
                   'administrator',
                   'Public', 
                   'default',
                   'DOMAIN\administrator',
                   'NetworkService',
                   'LocalService',
                   'systemprofile'
                )
                 
                Get-ChildItem "C:\Users" -Directory | 
                Where-Object { $_.Name -notin $SystemAccounts } | 
                Select-Object Name, FullName, LastWriteTime
            }
        }
    }
    
    Process {
        try {
            $Output.LocalUserFolders = Invoke-Command -Session $RemoteSession -ScriptBlock { 
                Get-LocalUserFolders 
            }

            if ($Output.LocalUserFolders.Count -gt 0) {
                $Filter = $($Output.LocalUserFolders | ForEach-Object { "SamAccountName -eq '$($_.Name)'" }) -join " -or "
                $Output.ADUserResults = Get-ADUser -Filter $Filter -Properties DisplayName, DistinguishedName

                # Get usernames not found in AD
                $UsersNames = $Output.ADUserResults | Select-Object -ExpandProperty SamAccountName
                $FolderNames = $Output.LocalUserFolders | Select-Object -ExpandProperty Name
                $Output.UsersNotInAD = Compare-Object -ReferenceObject $FolderNames -DifferenceObject $UsersNames -IncludeEqual |
                    Where-Object SideIndicator -eq '<=' |
                    Select-Object -ExpandProperty InputObject

                if ($Output.WorkstationADObject.DistinguishedName) {
                    $WorkstationStore = $Output.WorkstationADObject.DistinguishedName.Split(",")[2]
                    
                    foreach ($user in $Output.ADUserResults) {
                        $UserStore = $user.DistinguishedName.Split(",")[2]
                        switch ($UserStore) {
                            $WorkstationStore { break }
                            "OU=DEPROVISIONING" { 
                                $Output.UsersInDeprovisioningOU += $user
                                break 
                            }
                            Default {
                                if ($user.DisplayName -match "\((.+?)\)") {
                                    $values = $matches[1] -split " "
                                    $storeCode = $values[1]
                                    if ($storeCode -ne $UserStore) {
                                        $Output.UsersAtDifferentStore += $user
                                    }
                                }
                            }
                        }
                    }
                }

                # Combine all users that need to be removed
                $Output.UsersToRemove = @($Output.UsersNotInAD) + 
                                      ($Output.UsersAtDifferentStore | Select-Object -ExpandProperty SamAccountName) +
                                      ($Output.UsersInDeprovisioningOU | Select-Object -ExpandProperty SamAccountName) |
                                      Select-Object -Unique
            }
        }
        catch {
            Write-Error "Process block error: $_"
        }
        
        Write-Output $Output
    }
    
    End {
        if ($RemoteSession) {
            Remove-PSSession $RemoteSession
        }
    } 
}
