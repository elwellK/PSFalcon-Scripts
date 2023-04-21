#Requires -Version 5.1
#Requires -Modules @{ ModuleName="PSFalcon"; ModuleVersion="2.2.4" }


<#
.SYNOPSIS
  This script will retrieve all of the users setup within the CrowdStrike console and return their roles

.DESCRIPTION
  Script that leverages the PSFalcon PowerShell module
  https://github.com/CrowdStrike/psfalcon

.INPUTS
  Users are prompted to select the appropriate CrowdStrike Cloud
  Users must supply their clientID and secret API keys

.OUTPUTS
  Verbose logging to C:\Temp\PSFalcon\PSFalcon-Get-All-Users-with-Roles.log
  Exported results to C:\Temp\PSFalcon\Falcon-Users-and-Roles.csv

.NOTES
  Version:        2.0
  Changelog:      Updated script to work with PSFalcon 2.2.4
  Script Name:    Get All Users and Their Roles.ps1
  Author:         Booz Allen Hamilton
  Creation Date:  4/5/2022
  Purpose/Change: Initial script development
  Credits: Luca Sturlese for the logging functions - https://github.com/9to5IT/PSLogging

  Copyright (c) 2022, Booz Allen Hamilton
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
  1. Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>


# Import the psfalcon module - REQUIRES the PSFalcon PowerShell Module be placed in one of the PowerShell Modules directories
Import-Module -Name PSFalcon -Force -PassThru


#region Variables

# Initialize some Variables
$sLogPath = "C:\Temp\PSFalcon"
$sLogName = "PSFalcon-Get-All-Users-with-Roles.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#Script Version
$ScriptVersion = "2.0"

#endregion Variables



#region functions

Function Start-Log{
  <#
  .SYNOPSIS
    Creates log file

  .DESCRIPTION
    Creates log file with path and name that is passed. Checks if log file exists, and if it does deletes it and creates a new one.
    Once created, writes initial logging data

  .PARAMETER LogPath
    Mandatory. Path of where log is to be created. Example: C:\Windows\Temp

  .PARAMETER LogName
    Mandatory. Name of log file to be created. Example: Test_Script.log

  .PARAMETER ScriptVersion
    Mandatory. Version of the running script which will be written in the log. Example: 1.5

  .INPUTS
    Parameters above

  .OUTPUTS
    Log file created

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development

    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support

  .EXAMPLE
    Start-Log -LogPath "C:\Windows\Temp" -LogName "Test_Script.log" -ScriptVersion "1.5"
  #>

     [CmdletBinding(SupportsShouldProcess)]

  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LogName, [Parameter(Mandatory=$true)][string]$ScriptVersion)

  Process{
    $sFullPath = $LogPath + "\" + $LogName

    #Create file and start logging
    New-Item -Path $LogPath -Value $LogName -ItemType File -Force -ErrorAction SilentlyContinue

    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
    Add-Content -Path $sFullPath -Value "Running script version [$ScriptVersion]."
    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value ""

    #Write to screen for debug mode
    Write-Debug "***************************************************************************************************"
    Write-Debug "Started processing at [$([DateTime]::Now)]."
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
    Write-Debug "Running script version [$ScriptVersion]."
    Write-Debug ""
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
  }
}

Function Write-Log{
  <#
  .SYNOPSIS
    Writes to a log file

  .DESCRIPTION
    Appends a new line to the end of the specified log file

  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log

  .PARAMETER LineValue
    Mandatory. The string that you want to write to the log

  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development

    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support

  .EXAMPLE
    Write-Log -LogPath "C:\Windows\Temp\Test_Script.log" -LineValue "This is a new line which I am appending to the end of the log file."
  #>

  [CmdletBinding(SupportsShouldProcess)]

  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LineValue)

  Process{
    Add-Content -Path $LogPath -Value $LineValue

    #Write to screen for debug mode
    Write-Debug $LineValue
  }
}

Function Write-ErrorLog{
  <#
  .SYNOPSIS
    Writes an error to a log file

  .DESCRIPTION
    Writes the passed error to a new line at the end of the specified log file

  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log

  .PARAMETER ErrorDesc
    Mandatory. The description of the error you want to pass (use $_.Exception)

  .PARAMETER ExitGracefully
    Mandatory. Boolean. If set to True, runs Close-Log and then exits script

  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development

    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support. Added -ExitGracefully parameter functionality

  .EXAMPLE
    Write-ErrorLog -LogPath "C:\Windows\Temp\Test_Script.log" -ErrorDesc $_.Exception -ExitGracefully $True
  #>

  [CmdletBinding(SupportsShouldProcess)]

  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$ErrorDesc, [Parameter(Mandatory=$true)][boolean]$ExitGracefully)

  Process{
    Add-Content -Path $LogPath -Value "Error: An error has occurred [$ErrorDesc]."

    #Write to screen for debug mode
    Write-Debug "Error: An error has occurred [$ErrorDesc]."

    #If $ExitGracefully = True then run Close-Log and exit script
    If ($ExitGracefully -eq $True){
      Close-Log -LogPath $LogPath
      Break
    }
  }
}

Function Close-Log{
  <#
  .SYNOPSIS
    Write closing logging data & exit

  .DESCRIPTION
    Writes finishing logging data to specified log and then exits the calling script

  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write finishing data to. Example: C:\Windows\Temp\Test_Script.log

  .PARAMETER NoExit
    Optional. If this is set to True, then the function will not exit the calling script, so that further execution can occur

  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development

    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support

    Version:        1.2
    Author:         Luca Sturlese
    Creation Date:  01/08/12
    Purpose/Change: Added option to not exit calling script if required (via optional parameter)

  .EXAMPLE
    Close-Log -LogPath "C:\Windows\Temp\Test_Script.log"

.EXAMPLE
    Close-Log -LogPath "C:\Windows\Temp\Test_Script.log" -NoExit $True
  #>

  [CmdletBinding(SupportsShouldProcess)]

  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$false)][string]$NoExit)

  Process{
    Add-Content -Path $LogPath -Value ""
    Add-Content -Path $LogPath -Value "***************************************************************************************************"
    Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
    Add-Content -Path $LogPath -Value "***************************************************************************************************`n"

    #Write to screen for debug mode
    Write-Debug ""
    Write-Debug "***************************************************************************************************"
    Write-Debug "Finished processing at [$([DateTime]::Now)]."
    Write-Debug "***************************************************************************************************"

    #Exit calling script if NoExit has not been specified or is set to False
    If(!($NoExit) -or ($NoExit -eq $False)){
      Exit
    }
  }
}

Function New-LogDir{

  [CmdletBinding(SupportsShouldProcess)]

  Param ()

    If(!(Test-Path -Path $sLogPath)) {

        # Create C:\Temp\PSFalcon directory
        New-Item -Path $sLogPath -ItemType Directory

        # Start logging
        Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $ScriptVersion

        # Log that we are created the C:\Temp\PSFalcon directory
        Write-Log -LogPath $sLogFile -LineValue "Created $sLogPath directory"

    }else{

        # Start logging
        Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $ScriptVersion

    }

}

Function Select-CSCloud{
Clear-Host

    do {
    Write-Host "`n============= SELECT THE APPROPRIATE CROWDSTRIKE CLOUD =============="
    Write-Host "`'1' for US-1 Cloud"
    Write-Host "`'2' for US-2 Cloud"
    Write-Host "`'3' for EU Cloud"
    Write-Host "`'4' for GOV Cloud"
    Write-Host "`'Q' to Quit"
    Write-Host "======================================================================="

    # Prompt user to select one of the CrowdStrike Cloud environments
    $choice = Read-Host "`nEnter Choice"

        } until (($choice -eq '1') -or ($choice -eq '2') -or ($choice -eq '3') -or ($choice -eq '4') -or ($choice -eq 'Q') )

            switch ($choice) {
                '1'{
                    Write-Host "`nYou have selected the US-1 Cloud" -ForegroundColor Green
                    $cloud = "us-1"
            }
                '2'{
                    Write-Host "`nYou have selected the US-2 Cloud" -ForegroundColor Green
                    $cloud = "us-2"
            }
                '3'{
                    Write-Host "`nYou have selected the EU Cloud" -ForegroundColor Yellow
                    $cloud = "eu-1"
            }
                '4'{
                    Write-Host "`nYou have selected the GOV Cloud" -ForegroundColor Cyan
                    $cloud = "us-gov-1"
            }
                'Q'{
                    Write-Host "`nExiting menu. Please note you MUST select one of the CrowdStrike Cloud environments." -ForegroundColor Red
                    $cloud = "quit"

            }
    }

    If($cloud -ne "quit") {
        # Log that the CrowdStrike Cloud the user choose
        Write-Log -LogPath $sLogFile -LineValue "User choose the CrowdStrike $cloud Cloud."
        Return $cloud

    }

    If($cloud -eq "quit") {
        # Log that the user choose to quit
        Write-Log -LogPath $sLogFile -LineValue "User choose to quit the menu. Execution halting."
        Close-Log -LogPath $sLogFile
        Break
    }

}

Function Get-UserRoles{

[CmdletBinding(SupportsShouldProcess)]

  Param ([Parameter(Mandatory=$true)][string]$csvOutDir)

    # Get all Falcon Users
    $fusers = Get-FalconUser -detailed

    # Get user metadata and Falcon roles assigned to each Falcon user
    $fusers | ForEach-Object {
        $fuserroles = Get-FalconRole -UserId $_.uuid -Detailed
        
        $fuserInfo =[pscustomobject]@{
            'First Name' = $_.first_name
            'Last Name' = $_.last_name
            'Email' = $_.uid
            'UUID' = $_.uuid
            'Falcon Roles' = ($fuserroles.role_name -join ", ")
        
         }

        $fuserInfo | Export-CSV $csvOutDir\Falcon-Users-and-Roles.csv -Append -NoTypeInformation -Force -NoClobber
    }

}

#endregion functions

# Create the log directory if it does not already exist
New-LogDir

# Prompt the user for the CrowdStrike Cloud environment
$cloudenv = Select-CSCloud

# Prompt for the API clientid and secret
$clientid = Read-Host -Prompt 'INPUT YOUR CLIENT ID API KEY'
$secret = Read-Host -Prompt 'INPUT YOUR API SECRET'

# Force TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Request an oAUTH2 token and Validate its received
try {

Request-FalconToken -ClientId $clientid -ClientSecret $secret -Cloud $cloudenv;
    If ((Test-FalconToken).Token -eq $true) {
        Write-Host "`n`rWE RECEIVED A TOKEN. PROCEEDING.`n`r" -ForegroundColor Green;
            # Log that a token was received
            Write-Log -LogPath $sLogFile -LineValue "Token received successfully."
    }

} catch {

        Write-Host "`n`rERROR! WE DID NOT RECEIVE A TOKEN!`n`r" -ForegroundColor Red;
            # Log that a token was NOT received
            Write-ErrorLog -LogPath $sLogFile -ErrorDesc "Token was NOT received successfully." -ExitGracefully $True;
            Break
}


Try {

Get-UserRoles -csvOutDir $sLogPath

    Write-Host "Exported Falcon users and roles successfully." -ForegroundColor Green
    # Log that a token was received
    Write-Log -LogPath $sLogFile -LineValue "Exported Falcon users and roles successfully."
    # Finalize the log
    Close-Log -LogPath $sLogFile
    Break

}catch{

    Write-Host "Export of Falcon users and roles was NOT successful." -ForegroundColor Red
    # Log that a token was received
    Write-ErrorLog -LogPath $sLogFile -ErrorDesc "Export of Falcon users and roles was NOT successful. Exiting." -ExitGracefully $True
    Break

}


