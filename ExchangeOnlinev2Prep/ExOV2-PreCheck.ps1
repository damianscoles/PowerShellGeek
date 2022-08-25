CLS

Function NugetCheck {
    CLS
    Write-Host '---------------' -ForegroundColor White
    Write-Host ' NuGet Upgrade ' -ForegroundColor Magenta
    Write-Host '---------------' -ForegroundColor White
    # Prerequisite One: Upgrade NuGet PowerShell Module if needed:
    Write-Host 'Checking Nuget Version first' -ForegroundColor Green
	$PackageProviders = (Get-PackageProvider -ListAvailable).Name
	If ($PackageProviders -NotContains 'NuGet'){
        Write-Host ' * NuGet is missing - Installing NuGet Package Provider ...' -ForegroundColor Yellow
        Try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False
            $Major = ((Get-PackageProvider Nuget).Version).Major
            $Minor = ((Get-PackageProvider Nuget).Version).Minor
            $NugetVer = "$Major"+"."+"$Minor"
            If ($NugetVer -gt 2.8) {
                write-host ' [' -ForegroundColor Cyan -NoNewLine;Write-Host 'PASSED' -ForegroundColor Green -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
                Write-Host ': Prerequisite One: NuGet Module Check' -ForegroundColor White
                Write-Host '';Write-Host '';Write-Host ''
            }
        } Catch {   
            write-host ' [' -ForegroundColor Cyan -NoNewLine;Write-Host 'FAILED' -ForegroundColor Red -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
            Write-Host ' - Cannot update NuGet PowerShell module...' -ForegroundColor Yellow
            Write-Host '';Write-Host '';Write-Host ''
        }
    } Else {
        $Major = ((Get-PackageProvider Nuget).Version).Major
        $Minor = ((Get-PackageProvider Nuget).Version).Minor
        $NugetVer = "$Major"+"."+"$Minor"
        If ($NugetVer -gt 2.8) {
            write-host ' [' -ForegroundColor Cyan -NoNewLine;Write-Host 'PASSED' -ForegroundColor Green -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
            Write-Host ': Prerequisite One: NuGet Module Check' -ForegroundColor White
            Write-Host '';Write-Host '';Write-Host ''
        }

    }
} # End of NugetCheck Function

Function PSGalleryTrusted {
    CLS
    Write-Host '------------------------' -ForegroundColor White
    Write-Host ' PSGallery Trusted Test ' -ForegroundColor Magenta
    Write-Host '------------------------' -ForegroundColor White
    Write-Host ''
    Write-Host 'Checking PsGallery Trust status:' -ForegroundColor Green
    # Prerequisite Two: Set PSGallery Repository to Trusted:
    $GalleryPolicy = (Get-PSRepository -Name "PSGallery").InstallationPolicy
    If ($GalleryPolicy -eq 'Untrusted') {
        Write-Host '- PSGallery is not a trusted PS repository. Fixing ...' -ForegroundColor Yellow
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction STOP
        $GalleryPolicy = (Get-PSRepository -Name "PSGallery").InstallationPolicy
        If ($GalleryPolicy -eq 'Trusted') {
            # Write-Host 'PASSED' -ForegroundColor Green -NoNewLine
            write-host ' [' -ForegroundColor Cyan -NoNewLine;Write-Host 'PASSED' -ForegroundColor Green -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
            Write-Host ': Prerequisite Two: PSGallery Trusted Check' -ForegroundColor White
        }
    } Else {
        # Write-Host 'PASSED' -ForegroundColor Green -NoNewLine
        write-host ' [' -ForegroundColor Cyan -NoNewLine;Write-Host 'PASSED' -ForegroundColor Green -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
        Write-Host ': Prerequisite Two: PSGallery Trusted Check' -ForegroundColor White
    }
    Write-Host '';Write-Host '';Write-Host ''
} # End of PSGalleryTrusted Function

Function PackageManagementUpgrade {
    CLS
    Write-Host '----------------------------' -ForegroundColor White
    Write-Host ' Package Management Upgrade ' -ForegroundColor Magenta
    Write-Host '----------------------------' -ForegroundColor White
    Write-Host ''
    Write-Host 'Checking version of Packacge Management installed:' -ForegroundColor Green
    # Prerequisite Three: PackageManagement is 1.4.5 or greater
    Try {
        $PackageManagementTest = Get-Package PackageManagement -MinimumVersion 1.4.5 -ErrorAction STOP
    } Catch {
        $PackageManagementTest = $Null
    }
        # If ([string]::IsNullOrWhiteSpace($PackageMgmtCheck)) {
        If ([string]::IsNullOrWhiteSpace($PackageManagementTest)) {
            # Resolve version issue:
            Remove-Module PowerShellGet
            Remove-Module PackageManagement
            Install-Module PackageManagement -Force -SkipPublisherCheck
            Import-Module PackageManagement
        } 

        # $PostPackageMgmtCheck = Find-PackageProvider PackageManagement -MinimumVersion 1.4.5
    Try {
            $PackageManagementTest = Get-Package PackageManagement -MinimumVersion 1.4.5 -ErrorAction STOP
    } Catch {
        $PackageManagementTest = $Null
    }
    If ([string]::IsNullOrWhiteSpace($PackageManagementTest)) {
        Write-Host 'PowerShellGet Upgrade Failed.  Exiting ....' -ForegroundColor Yellow
        Break
    } Else {
        # Write-Host 'PASSED' -ForegroundColor Green -NoNewLine
        write-host '[' -ForegroundColor Cyan -NoNewLine;Write-Host 'PASSED' -ForegroundColor Green -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
        Write-Host ': Prerequisite Three: PackageManagement Module Check' -ForegroundColor White
    }

    Write-Host '';Write-Host '';Write-Host ''

} # End of PackageManagementCheck Function

Function PowerShellGetCheck {
    CLS
    Write-Host '----------------------------' -ForegroundColor White
    Write-Host ' PowerShell Get Upgrade ' -ForegroundColor Magenta
    Write-Host '----------------------------' -ForegroundColor White
    Write-Host ''
    Write-Host 'Checking version of PowerShell Get installed:' -ForegroundColor Green
    # Prerequisite Four: PowerShell Get is 2.0.0.0 or newer:
    $PSGetVerMajor = [int32]((Get-Module PowerShellGet).Version).Major
    $PSGetModuleUpdate = $True
    $PSGetUpdateRun = $True
    If ($PSGetVerMajor -lt 2)  {
        Write-Host ' * Version too low ' -ForegroundColor yellow -NoNewline
        Write-Host '--> Updating the PowerShellGet module which is required to download the ExO v2 module.' -ForegroundColor White
        Try {   
            Update-Module PowershellGet -ErrorAction Stop
        } Catch {
            $PSGetUpdateRun = $False
        }
        # If Update fails, then try to install instead:
        $PSGetVerMajor = [int32]((Get-Module PowerShellGet).Version).Major
        If ($PSGetVerMajor -lt 2)  {
            Remove-Module PowerShellGet
            Remove-Module Packagemanagement
            $PSGetModuleUpdate = $True
            Try {
                Install-module PowerShellGet -MinimumVersion 2.0.0.0 -Force -Confirm:$False -SkipPublisherCheck -ErrorAction STOP
            } Catch {
                Write-Host "Error message - $_.Exception.Message" -ForegroundColor Yellow
                $PSGetModuleUpdate = $False       
            }
        }
        $PSGetVerMajor = [int32]((get-module PoweRshellGet).Version).Major
        If ($PSGetVerMajor -lt 2)  {
            # Write-Host 'PASSED' -ForegroundColor Green -NoNewLine
            write-host '[' -ForegroundColor Yellow -NoNewLine;Write-Host 'FAILED' -ForegroundColor Red -NoNewline;Write-Host ']' -ForegroundColor Yellow -NoNewLine
            Write-Host ': Prerequisite Four: PowerShellGet Check.' -ForegroundColor White -NoNewLine
            Write-Host ' Try to close the PowerShell window and try once more, or update PowerShellGet manually.' -ForegroundColor Yellow
        } Else {
            write-host '[' -ForegroundColor Cyan -NoNewLine;Write-Host 'PASSED' -ForegroundColor Green -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
            Write-Host ': Prerequisite Four: PowerShellGet Check' -ForegroundColor White
            $PSGetUpdateRun = $False
        }
    } Else {
        write-host '[' -ForegroundColor Cyan -NoNewLine;Write-Host 'PASSED' -ForegroundColor Green -NoNewline;Write-Host ']' -ForegroundColor Cyan -NoNewLine
        Write-Host ': Prerequisite Four: PowerShellGet Check' -ForegroundColor White
        $PSGetUpdateRun = $False
    }

    If (!$PSGetModuleUpdate){
        Write-Host 'PowerShellGet module upgrade failed, please fix manually or rerun this script to try again.' -ForegroundColor Yellow
        Write-Host 'Exiting ....' -ForegroundColor Red

    }

    Write-Host '';Write-Host '';Write-Host ''

} # End if PowerShellGetFunction

Function InstallExOv2Cmdlets {
    # Check for ExO V2 Module
Try {
        $ExOPackgMgmtStatus = Get-Package ExchangeOnlineManagement -ErrorAction STOP
    $ExOPackgMgmtStatus = $True
} Catch {
    $ExOPackgMgmtStatus = $False	
}
    # Attempt to install Exchange V2 PowerShell Module
    If (!$ExOPackgMgmtStatus) {
        $ExOV2Install = $True
        Try {
            Write-Host ' * Installing ExO v2 Module (ExchangeOnlineManagement)' -ForegroundColor Green
            Install-Module -Name ExchangeOnlineManagement -Confirm:$False -AcceptLicense -Force -ErrorAction STOP -WarningAction STOP
            # Install-Module -Name ExchangeOnlineManagement -Confirm:$False -Force -ErrorAction STOP
        } Catch {
            Write-Host 'REQUIRED MODULE FAILURE - ExchangeOnlineManagement Module failed to install.' -ForegroundColor Red
            Write-Host "Error message - $_.Exception.Message" -ForegroundColor Yellow
            Write-Host ' ... Exiting ...' -ForegroundColor Yellow
        Write-Host 'Try closing PowerShell and starting a new Window, then run this script again.' -ForegroundColor Blue
            $ExOV2Install = $False
            Break
        }

        # Import the ExchangeOnlineManagement Module if the install is successfull:
        If ($ExOV2Install) {
            Try {
                Import-Module ExchangeOnlineManagement -ErrorAction STOP
            } Catch {
                Write-Host 'REQUIRED MODULE FAILURE - ExchangeOnlineManagement Module failed to load.' -ForegroundColor Red
                Write-Host "Error message - $_.Exception.Message" -ForegroundColor Yellow
                Write-Host ' ... Exiting ...' -ForegroundColor Yellow
                Break
            }
        }
    } Else {
        Try {
            Import-Module ExchangeOnlineManagement -ErrorAction STOP
            $ExOV2StatusFinal = $True
        } Catch {
            Write-Host 'REQUIRED MODULE FAILURE - ExchangeOnlineManagement Module failed to load.' -ForegroundColor Red
            Write-Host "Error message - $_.Exception.Message" -ForegroundColor Yellow
            Write-Host ' ... Exiting ...' -ForegroundColor Yellow
            Break
        }
    }
    Write-Host '--- END CHECK ExO V2 MODULE PREREQUISITES ---' -ForegroundColor Green
    Write-Host ''
} # End of InstallExOv2Cmdlets Function

Function CheckAllPreReq {
    cls
    $Status = 0
    Write-Host ''
    Write-Host 'Checking ExO v2 Cmdlet Prerequisites.  Four checks ....' -ForegroundColor Yellow
    Write-Host ''
    # Nuget
    $PackageProviders = (Get-PackageProvider -ListAvailable).Name
    If ($PackageProviders -NotContains 'NuGet'){ 
        Write-Host 'Failed' -ForegroundColor Red -NoNewLine ; Write-Host ' - NuGet Provider not available' -ForegroundColor White
    } Else {
        $Major = ((Get-PackageProvider Nuget).Version).Major
        $Minor = ((Get-PackageProvider Nuget).Version).Minor
        $NugetVer = "$Major"+"."+"$Minor"
        If ($NugetVer -gt 2.8) {
            Write-Host "PASSED" -ForegroundColor Green -NoNewline
            Write-Host " - Nuget is version $NugetVer, which is greater than the required v2.8." -ForegroundColor White
            $Status++
        }
    }

    # PSGallery
    $GalleryPolicy = (Get-PSRepository -Name "PSGallery").InstallationPolicy
    If ($GalleryPolicy -eq 'Untrusted') {
        Write-Host 'FAILED' -ForegroundColor Red -NoNewline
        Write-Host ' - PSGallery is not a trusted PowerShell repository.' -ForegroundColor White
    } Else {
        Write-Host 'PASSED' -ForegroundColor Green -NoNewline
        Write-Host ' - PSGallery is a trusted PowerShell repository.' -ForegroundColor White
        $Status++
    }

    # Package Management
    Try {
        $PackageMgmtCheck = Get-Package PackageManagement -MinimumVersion 1.4.5 -ErrorAction STOP
        Write-Host 'PASSED' -ForegroundColor Green -NoNewline
        Write-Host ' - Package Management is at least 1.4.5.' -ForegroundColor White
        $Status++
    } Catch {
        Write-Host 'FAILED' -ForegroundColor Red -NoNewline
        Write-Host ' - Package Management is less than version 1.4.5.' -ForegroundColor White
    }

    # PowerShell Get
    $PSGetVerMajor = [int32]((Get-Module PowerShellGet).Version).Major
    If ($PSGetVerMajor -lt 2)  {
        Write-Host 'FAILED' -ForegroundColor Red -NoNewline
        Write-Host ' - PowerShell get is less than the required 2.0.0' -ForegroundColor White
    } Else {
        Write-Host 'PASSED' -ForegroundColor Green -NoNewline
        Write-Host ' - PowerShell get is greater than the required 2.0.0' -ForegroundColor White
        $Status++
    }
    If ($Status -eq 4) {
        Write-Host ''
        Write-Host 'All 4 tests'  -ForegroundColor White -NoNewLine
        Write-Host ' passed' -ForegroundColor Green -NoNewLine
        Write-Host ', go ahead and install the ExO v2 cmdlets.' -ForegroundColor White -NoNewline
        Write-Host ' [Option 6]' -ForegroundColor Cyan
    } Else {
        Write-Host ''
        Write-Host 'At least one test ' -ForegroundColor White -NoNewline
        Write-Host 'failed' -ForegroundColor Red -NoNewline
        Write-Host ', you cannot install the ExO v2 cmdlets at this time.' -ForegroundColor White
    }

    Write-Host ''
    Write-Host ''
    Write-Host ''
}

$Menu = {
    Write-Host "    ******************************************" -ForegroundColor White
    Write-Host "     Exchange Online v2 Cmdlet Prep / Install " -ForegroundColor Cyan
    Write-Host "    ******************************************" -ForegroundColor White
    Write-Host "    "
    Write-Host "    1) Nuget Upgrade"
    Write-Host "    2) PSGallery Trusted"
    Write-Host "    3) Package Management Upgrade"
    Write-Host "    4) PowerShell Get Upgrade"
    Write-Host "    5) Check all prerequisited"
    Write-Host "    6) Install ExO v2 Cmdlets"
    Write-Host ' '
    Write-Host "    99) Exit health check" -ForegroundColor Red
    Write-Host "    "
    Write-Host "    Select an option.. [1-99]? " -ForegroundColor White -NoNewLine
}


Do {
    Invoke-Command -ScriptBlock $Menu
    $Choice = Read-Host

        Switch ($Choice)    {
        1 {
            NugetCheck
        }
        2 {
            PSGalleryTrusted
        }
        3 {
            PackageManagementUpgrade 
        }
        4 {
            PowerShellGetCheck
        }
        5 {
            CheckAllPreReq
        }
        6 {
            InstallExOv2Cmdlets
        }
        99 {# Exit
            If ($Environment -eq 'Office365') {
                Get-PSSession | Remove-PSSession
            }
            Popd
            Write-Host "Exiting..."
        }
        Default {Write-Host "You haven't selected any of the available options. "}
    }
} while ($Choice -ne 99)