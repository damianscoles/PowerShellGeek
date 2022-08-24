# Purpose - Validate current installed .NET and install newer .NET version
#
# Supported installs are .NEt 4.7, 4.71, 4.72 and 4.80
#

# Variables
$Ver = (Get-WMIObject win32_OperatingSystem).Version
$OSCheck = $false
$Choice = "None"
$Date = get-date -Format "MM.dd.yyyy-hh.mm-tt"
$CurrentPath = (Get-Item -Path ".\" -Verbose).FullName
$DownloadFolder = $CurrentPath

# Download version of Dot Net

# Clear Screen
cls

Function BITSCheck {
    $Bits = Get-Module BitsTransfer
    if ($Bits -eq $null) {
        Write-Host "Importing the BITS module." -ForegroundColor cyan
        try {
            Import-Module BitsTransfer -erroraction STOP
        } catch {
            Write-Host "Server Management module could not be loaded." -ForegroundColor Red
        }
    }
} # End BITSCheck Function

Function Check-DotNetVersion {
    # Formatting
    Write-Host " "
    Write-Host " "
    $DotNetFound = $False
    # .NET 4.8 or less check
	$NETval = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release"

    # Parse through most .NET possibilities:
    If ($NETval.Release -gt "528049") {
        Write-Host "Greater than .NET 4.8 is installed"
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "528049") {
        Write-Host ".NET 4.8 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "461814") {
        Write-Host ".NET 4.7.2 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "461310") {
        Write-Host ".NET 4.7.1 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "460805") {
        Write-Host ".NET 4.7.0 is installed."
        DotNetFound = $True
    }
    If ($NETval.Release -eq "394806") {
        Write-Host ".NET 4.6.2 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "394271") {
        Write-Host ".NET 4.6.1 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "393297") {
        Write-Host ".NET 4.6.0 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "379893") {
        Write-Host ".NET 4.5.2 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "378758") {
        Write-Host ".NET 4.5.1 is installed."
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "378389") {
        Write-Host ".NET 4.5.0 is installed"
        $DotNetFound = $True
    }
    If ($NETval.Release -lt "378389") {
        Write-Host "Version less than .NET 4.5.0 is installed."
        $DotNetFound = $True
    }
    If ($DotNetFound -ne $True) {
        Write-Host 'A valid .NET Version was not found - ' -NoNewLine
        Write-host 'Failed' -ForegroundColor Red
    }

    $global:NetVersion = $NETVal

} # End Check-DotNetVersion

Function FileDownload {
    Param ($sourcefile)
    If (Test-path $DownloadFolder) {
        Write-Host "Target folder $DownloadFolder exists." -ForegroundColor White
    } Else {
        New-Item $DownloadFolder -type Directory | Out-Null
    }
    BITSCheck
    [string] $DownloadFile = $sourcefile.Substring($sourcefile.LastIndexOf("/") + 1)
    If (Test-Path "$DownloadFolder\$DownloadFile"){
        Write-Host "The file $DownloadFile already exists in the $DownloadFolder folder." -ForegroundColor Cyan
    } Else {
        Try {
            Start-BitsTransfer -Source "$SourceFile" -Destination "$DownloadFolder\$DownloadFile" -ErrorAction STOP
        } Catch {
            Write-host "Failed to download file as BitsTransfer failed." -ForegroundColor Yellow
        }
    }
} # End FileDownload Function

Function Install-NET470 {

    Write-Host " * Downloading .NET 4.7 now! *" -ForegroundColor Yellow
    # Download .NET 4.7 installer
    FileDownload "http://download.microsoft.com/download/D/D/3/DD35CC25-6E9C-484B-A746-C5BE0C923290/NDP47-KB3186497-x86-x64-AllOS-ENU.exe"
    Set-Location $DownloadFolder
    Write-Host " "
    Write-Host "File: NDP47-KB3186497-x86-x64-AllOS-ENU.exe installing..." -NoNewLine

    # New Code (Waits for completion)
    .\NDP47-KB3186497-x86-x64-AllOS-ENU.exe /quiet /norestart | Out-Null
    
    # Pause for completion
    start-sleep 2

} # End of Function .NET 4.7.0 Install

Function Install-NET471 {
    Write-Host " * Downloading .NET 4.7.1 now! *" -ForegroundColor Yellow
    # Download .NET 4.7.1 installer
    FileDownload "https://download.microsoft.com/download/9/E/6/9E63300C-0941-4B45-A0EC-0008F96DD480/NDP471-KB4033342-x86-x64-AllOS-ENU.exe"
    Set-Location $DownloadFolder
    Write-Host " "
    Write-Host "File: NDP471-KB4033342-x86-x64-AllOS-ENU.exe installing..." -NoNewLine

    # New Code (Waits for completion)
    .\NDP471-KB4033342-x86-x64-AllOS-ENU.exe /quiet /norestart | Out-Null
        
    # Pause for completion
    start-sleep 2

} # End of Function .NET 4.7.1 Install

Function Install-NET472 {
    Write-Host " * Downloading .NET 4.7.2 now! *" -ForegroundColor Yellow
    # Download .NET 4.7.2 installer
    FileDownload "https://download.microsoft.com/download/6/E/4/6E48E8AB-DC00-419E-9704-06DD46E5F81D/NDP472-KB4054530-x86-x64-AllOS-ENU.exe"
    Set-Location $DownloadFolder
    Write-Host " "
    Write-Host "File: NDP472-KB4054530-x86-x64-AllOS-ENU.exe installing..." -NoNewLine

    # New Code (Waits for completion)
    .\NDP472-KB4054530-x86-x64-AllOS-ENU.exe /quiet /norestart | Out-Null
        
    # Pause for completion
    start-sleep 2

} # End of Function .NET 4.7.1 Install

Function Install-NET48 {

    Write-Host " * Downloading .NET 4.8 now! *" -ForegroundColor Yellow
    # Download .NET 4.8 installer
    FileDownload "https://download.visualstudio.microsoft.com/download/pr/7afca223-55d2-470a-8edc-6a1739ae3252/abd170b4b0ec15ad0222a809b761a036/ndp48-x86-x64-allos-enu.exe"
    Set-Location $DownloadFolder
    Write-Host " "
    Write-Host "File: ndp48-x86-x64-allos-enu.exe installing..." -NoNewLine

    # New Code (Waits for completion)
    .\Ndp48-x86-x64-allos-enu.exe /quiet /norestart | Out-Null
        
    # Pause for completion
    start-sleep 2

} # End of Function .NET 4.8.0 Install

Function Install-DotNetMain {
    cls
    Write-Host '**********************' -ForegroundColor White
    Write-Host ' Install .NET Function' -ForegroundColor Magenta
    Write-Host '**********************' -ForegroundColor White
    Check-DotNetVersion
    $DotNetVersion = ($global:NetVersion).release
    $Valid = $False
    $Decision = $Null
    Write-Host ''
    Do {
        $Decision = Read-Host -Prompt "Which version of .Net do you want to install? [4.7, 4.7.1, 4.7.2 or 4.8?  'x' for main menu] "
        
        If ($Decision -eq '4.7') {
            If ($DotNetVersion -lt '460805') {
                Install-NET470
                $Valid = $True
                Write-Host 'Please make sure to reboot your server now.' -ForegroundColor Yellow
            } else {
                Write-Host ''
                Write-Host 'This version of .NET is too low for this server.' -ForegroundColor Yellow
                $Valid = $True
            }
        }
        If ($Decision -eq '4.7.1') {
            If ($DotNetVersion -lt '461310') {
                Install-NET471
                $Valid = $True
                Write-Host 'Please make sure to reboot your server now.' -ForegroundColor Yellow
            } else {
                Write-Host ''
                Write-Host 'This version of .NET is too low for this server.' -ForegroundColor Yellow
                $Valid = $True
            }          
        }
        If ($Decision -eq '4.7.2') {
            If ($DotNetVersion -lt '461814') {
                Install-NET472
                $Valid = $True
                Write-Host 'Please make sure to reboot your server now.' -ForegroundColor Yellow
            } else {
                Write-Host ''
                Write-Host 'This version of .NET is too low for this server.' -ForegroundColor Yellow
                $Valid = $True
            }
        }
        If ($Decision -eq '4.8') {
            If ($DotNetVersion -lt '528049') {
                Install-NET48
                $Valid = $True
                Write-Host 'Please make sure to reboot your server now.' -ForegroundColor Yellow
            } else {
                Write-Host ''
                Write-Host 'This version of .NET is too low for this server.' -ForegroundColor Yellow
                $Valid = $True
            }
        }
        If ($Decision -eq 'x') {
            Write-Host 'Exiting .NET installation function ...' -ForegroundColor Yellow
            $Valid = $True
        }
        If (!$Valid) {
            Write-Host '';;write-host '';Write-Host ' Invalid selection.  Please choose again.' -ForegroundColor Yellow;write-host '';write-host ''
        }
    } While ($Valid -ne $True)
    Write-Host ' '
    Write-Host 'Going back to main menu.' -ForegroundColor cyan
    Write-Host ' '
    Start-sleep 3
}

$Menu = {
    Write-Host "	****************************" -ForegroundColor Cyan
    Write-Host "	 .NET Checker and Installer " -ForegroundColor White
    Write-Host "	****************************" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "	1) Check .NET Version" -ForegroundColor White
    Write-Host "	2) Install newer .NET version" -ForegroundColor White
    Write-Host ''
    Write-Host "	50) REBOOT" -ForegroundColor Yellow
    Write-Host "	99) Exit" -ForegroundColor Red
    Write-Host ''
    Write-Host "	Select an option.. [1, 2, 98 or 99]? " -ForegroundColor White -nonewline
}

Do { 	
    If ($Choice -ne "None") {Write-Host "Last command: "$Choice -foregroundcolor Yellow}	
    Invoke-Command -ScriptBlock $Menu
    $Choice = Read-Host

    Switch ($Choice)    {

        1 { # Check .NET versions
            cls
            Check-DotNetVersion
        }
        2{ # Install newer .NET
            Install-DotNetMain
        }
        50 { # Exit and restart
            Stop-Transcript
            restart-computer -computername localhost -force
        }
        99 {# Exit
            If (($WasInstalled -eq $false) -and (Get-Module BitsTransfer)){
            Write-Host "BitsTransfer: Removing..." -NoNewLine
            Remove-Module BitsTransfer
            Write-Host "`b`b`b`b`b`b`b`b`b`b`bremoved!   " -ForegroundColor Green
            }
        Popd
        Write-Host "Exiting..."
        }
    }
} While ($Choice -ne 99)
