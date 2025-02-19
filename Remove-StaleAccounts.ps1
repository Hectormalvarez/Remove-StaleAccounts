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
        # active directory module check
        try {            
            if (-not (Get-Module -Name ActiveDirectory)) {
                Write-Error "The Active Directory module is required. Please import it and try again."
                return
            } else {
                Write-Verbose "Active Directory module found!"
            }
            # initialize pssession for use during script
            # script will fail if unable to initiate a pssession
            $RemoteSession = new-pssession -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            Write-Error "Initialization failed please check error messages and try again"
            throw
        }

        # setup output structure
        $Output = [pscustomobject]@{
            LocalUserFolders        = @() 
            ADUserResults           = @()
            UsersNotInAD            = @()
            UsersInDeprovisioningOU = @()
            UsersAtDifferentStore   = @() 
            WorkstationADObject     = $null
        }

        # gets remote computer AD object, used to check if user is at same store
        $Output.WorkstationADObject = Get-ADComputer -Filter { Name -like $ComputerName }
        # defines get-localusersfolders function in remote session
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
                 
                $Folders = @()
                 
                Get-ChildItem "C:\Users" -Directory |
                Where-Object { $_.Name -notin $SystemAccounts } |
                ForEach-Object {
                   $Folders += $_
                }
                 
                Write-Output $Folders
            }
        }
            }
    
    Process {
        # collects list of folder names within c:\users
        $Output.LocalUserFolders = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-LocalUserFolders } -ErrorAction Stop


        # Create a filter string to find active users not in the $Output.LocalUserFolders list
        # building this filter allows for one call to AD vs one for each user
        $Filter = $($Output.LocalUserFolders | ForEach-Object { "SamAccountName -eq '$($_.Name)'" }) -join " -or "
        # save users found in Active Directory to output
        $Output.ADUserResults = Get-ADUser -Filter $Filter -Properties DisplayName
        

        # extracts SamAccountNames from ADUserResults
        $UsersNames = $Output.ADUserResults |
        Select-Object -ExpandProperty SamAccountName
        $FolderNames = $Output.LocalUserFolders |
        Select-Object -ExpandProperty Name
        # compares LocalUserFolders and usersNames variables to get
        # list of folders of users that are not in active directory
        # Filter to only get items from LocalUserFolders not in usersNames
        # (indicated by <= in SideIndicator)
        $Output.UsersNotInAD = Compare-Object -ReferenceObject $FolderNames -DifferenceObject $UsersNames -IncludeEqual |
        Where-Object SideIndicator -eq '<=' |
        Select-Object -ExpandProperty InputObject


        $WorkstationStore = $Output.WorkstationADObject.DistinguishedName.Split(",")[2] # 3 alpha 
        foreach ($user in $Output.ADUserResults) {
            # gets 3rd block from fqdn which is usually the store block
            # will be used to compare to workstation store ou
            $UserStore = $user.distinguishedname.Split(",")[2]
            switch ($UserStore) {
                # if user store code = store code continue to next user
                $WorkstationStore { break }
                # if store code matches region user is in wrong OU (not in a store OU)
                # need to extract TM store location from display name: first last (RR SSS) R=region, S=store
                # find users in deprovisioning OU
                "OU=DEPROVISIONING" { $Output.UsersInDeprovisioningOU += $user; break }
                Default {
                    if ($user.DisplayName -match "\((.+?)\)") {
                        $values = $matches[1] -split " "
                        $storeCode = $values[1]
                        if ($storeCode -eq $UserStore) { break }
                        else {
                            $Output.UsersAtDifferentStore += $user
                        }
                    }
                }
            }
        }
        
        Write-Output $Output
    }
    
    End {
        # cleanup remote session
        Remove-PSSession $RemoteSession
    } 
}

     