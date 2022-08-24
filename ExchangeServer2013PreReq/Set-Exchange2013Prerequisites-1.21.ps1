#####################################################################################################################################################################
#  SCRIPT DETAILS																																					#
#	Configures the necessary prerequisites to install Exchange 2013 CU23+ on a Windows Server 2012 (R2) server.											            #
#	Installs all required Windows 2012 (R2) components and configures service startup settings. Provides options for downloading latest Update Rollup	            #
#	and more.  First the script will determine the version of the OS you are running and then provide the correct menu items. 										#
#																																									#
# SCRIPT VERSION HISTORY																																			#
#	Current Version		: 1.21  [LOCKED - NO MORE UPDATES]																																	#
#	Change Log			: 1.21 - Removed .NET 4.7.  .NET 4.8 is default (CU23+)
#                       : 1.20 - Added .NET 4.8, TCP Keep Alive, TLS Checks, additional checks, alphabetized functions, consolidated checks, rewmoved .NET 4.7.1    #
#                       : 1.19 - Fix .NET install, some post checks                                                                                                 #
#                       : 1.18 - Added .NET 4.7.1 and C++ 2013 requirements to the installation - Complete menu rewrite                                             #
#                       : 1.17 - Fixed .NET 4.6.1 installation, added .NET 4.6.1 and corrected the RC4 registry entry to DWORD per Microsoft						#
#						:			Removed Windows 2008 R2 support    																			                    #
#                       : 1.16 - Fixed bugs, additional testing                                                                                                     #
#                       : 1.15 - Tweaked a couple of directories, corrected bad code and further testing, added PageFile Configuration, reduced length to 1400 lines#
#						: 1.14 - Completely recoded, removed duplicate code, removed old code, added colors to menu													#
#    					: 1.13 - Added hotfix for .NET 4.6.1 and changed the menu for .4.6.1 and .4.5.1 (2012 (R2) Only)											#
#                       : 1.12 - Added .NET 4.6.1 for both 2008 and 2012(R2) - good ONLY for CU13 +, removed some old code											#
#                       : 1.11 - Tweak Office Filter Pack and C++ installation and removal																			#
#                       : 1.10 - Bug Fixes																															#
#                       : 1.09 - Added a way to disable SSL 3.0 and RC4 encryption.																					#
#				        : 1.08 - Added PowerManagement																												#
#				        : 1.07 - Removed old versions of .NET (performance isue) and Windows Framework 3.0, add Edge Transport chk and Office 2010 SP2 Filter Pack	#
#				        : 1.06 - Added support for Windows 2012 R2, added options for Edge Role installation and cleaned up old items								#
#				        : 1.05 - Added support for Exchange 2013 RTM CU1, additional error suppression																#
#				        : 1.04 - Added support for Exchange 2013 RTM																								#
#				        : 1.03 - Fixed Reboot for Windows Server 2012 RTM																							#
#				        : 1.02 - fixed install commands for Windows Server 2012.  Split CAS/MX role install.														#
#				        : 1.01 - Added Windows Server 2012 Preview support																							#
#				        : 1.00 - Created script for Windows Server 2008 R2 installs																					#
#																																									#
# DATE RELEASED         : 09/01/2012 (10/23/2019 - Last Update)  - FINAL - 1/19/21 - NO MORE UPDATES										                        #
#																																									#
# OTHER SCRIPT INFORMATION																																			#
#    Wish list			:  																														                    #
#    Rights Required	: Local admin on server																														#
#    Exchange Version	: 2013																																		#
#    Author       		: Damian Scoles																																#
#    My Blog			: http://justaucguy.wordpress.com																											#
#    Disclaimer   		: You are on your own.  This was not written by, supported by, or endorsed by Microsoft.													#
#    Info Stolen from 	: Anderson Patricio, Bhargav Shukla and Pat Richard [Exchange 2010 script]																	#
#    					: http://msmvps.com/blogs/andersonpatricio/archive/2009/11/13/installing-exchange-server-2010-pre-requisites-on-windows-server-2008-r2.aspx #
#						: http://www.bhargavs.com/index.php/powershell/2009/11/script-to-install-exchange-2010-pre-requisites-for-windows-server-2008-r2/			#
# 						: SQL Soldier - http://www.sqlsoldier.com/wp/sqlserver/enabling-high-performance-power-plan-via-powershell									#
#																																									#
# EXECUTION																																							#
#	.\Set-Exchange2013Prerequisites-1-21.ps1																														#
#																																									#
#####################################################################################################################################################################

##################################
#   Global 	 Definitions  #
##################################
$ver = (Get-WMIObject win32_OperatingSystem).Version
$UCMAHold = $False
$OSCheck = $False
$Choice = "None"
$Date = get-date -Format "MM.dd.yyyy-hh.mm-tt"
$DownloadFolder = "c:\install"
$currentpath = (Get-Item -Path ".\" -Verbose).FullName
$Reboot = $False
$error.clear()
Start-Transcript -path "$CurrentPath\$date-Set-Prerequisites.txt" | Out-Null
Clear-Host
# Pushd

############################################################
#   Global Functions - 2012 (R2)   #
############################################################

# Function Additional Checks
Function AdditionalChecks { 
    CLS
    Write-Host '----------------------------------------------' -ForegroundColor White
    Write-Host 'Checking additional settings for Exchange 2019' -ForegroundColor Magenta
    Write-Host '----------------------------------------------' -ForegroundColor White
    Write-Host ' '
    Write-Host ' '

    # Server Power Management
	$HighPerf = powercfg -l | %{If($_.contains("High performance")) {$_.split()[3]}}
	$CurrPlan = $(powercfg -getactivescheme).split()[3]
	If ($CurrPlan -eq $HighPerf) {
        Write-Host "Server Power Plan set to High Performance - " -NoNewLine
        Write-Host "Passed" -ForegroundColor Green
	} Else {
        Write-Host "Server Power Plan set to High Performance - " -NoNewLine
        Write-Host "Failed" -ForegroundColor Red
    }

    # NIC Power Management
	$NICs = Get-WmiObject -Class Win32_NetworkAdapter|Where-Object{$_.PNPDeviceID -notlike "ROOT\*" -and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22} 
	Foreach($NIC in $NICs) {
		$NICName = $NIC.Name
		$DeviceID = $NIC.DeviceID
		If([Int32]$DeviceID -lt 10) {
			$DeviceNumber = "000"+$DeviceID 
		} Else {
			$DeviceNumber = "00"+$DeviceID
		}
		$KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$DeviceNumber"
  
		If(Test-Path -Path $KeyPath) {
			$PnPCapabilities = (Get-ItemProperty -Path $KeyPath).PnPCapabilities
            # Verify the value is now set to or was set to 24
			If($PnPCapabilities -eq 24) {
                Write-Host "NIC Power Management is disabled - " -NoNewline
                Write-Host "Passed" -ForegroundColor Green
            } Else {
                Write-Host "NIC Power Management is enabled -  " -NoNewline
                Write-Host "Failed" -ForegroundColor Red
            }
   		 } 
 	 } 

    # Pagefile
    $MaximumSize = (Get-CimInstance -Query "Select * from win32_PageFileSetting" | select-object MaximumSize).MaximumSize
    $InitialSize = (Get-CimInstance -Query "Select * from win32_PageFileSetting" | select-object InitialSize).InitialSize

    $WMIQuery = $False
    Try {
        $RamInMb = (Get-CIMInstance -computername $name -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1MB
        $RamInGb = (Get-CIMInstance -computername $name -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
		
        $ExchangeRAM = $RAMinMb+10


    } Catch {
        Write-Host "Cannot acquire the amount of RAM in the server." -ForegroundColor Red
	    $WMIQuery = $True
    }
    
    # Get RAM and set ideal PageFileSize - WMI Method
    If ($WMIQuery) {
	    Try {
		    $RamInMb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1MB
            $RamInGb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
		    $ExchangeRAM = $RAMinMb + 10
		} Catch {
		    Write-Host "Cannot acquire the amount of RAM in the server with CIM or WMI queries." -ForegroundColor Red
		$Stop = $True
	    }
    }

    If ($MaximumSize -eq $InitialSize) {
        Write-Host 'Pagefile Initial and Maximum Size are the same - ' -NoNewline
        Write-Host ' Passed' -ForegroundColor Green
        $PageFileTestPass = $True
    } Else {
        Write-Host 'Pagefile Initial and Maximum Size are NOT the same - ' -NoNewline
        Write-Host ' Failed' -ForegroundColor Red
    }

    If ($PageFileTestPass) {
        If ($MaximumSize -eq $ExchangeRAM) {
            Write-Host 'Pagefile is configured [RAM + 10Mb] - ' -NoNewline
            Write-Host ' Passed' -ForegroundColor Green
        } Else {
            $RAMDifference = $ExchangeRAM - $MaximumSize
            If ($RAMDifference -gt 0) {
                Write-Host 'Pagefile is configured [RAM + 10Mb] - ' -NoNewline
                Write-Host 'Failed' -ForegroundColor Red -NoNewline
                Write-Host ' --> Pagefile is too SMALL' -ForegroundColor Yellow
                Write-host "   Server RAM - $RamInMb MB" -ForegroundColor White
                Write-Host "   Ideal Pagefile size - $ExchangeRAM MB" -ForegroundColor White
                Write-host "   Maximum PageFile Size - $MaximumSize MB" -ForegroundColor White
                Write-host "   Initial PageFile Size - $InitialSize MB" -ForegroundColor White
            } 
            If ($RAMDifference -lt 0) {
                Write-Host 'Pagefile is configured [RAM + 10Mb] - ' -NoNewline
                Write-Host 'Failed' -ForegroundColor Red -NoNewline
                Write-Host ' --> Pagefile is too BIG' -ForegroundColor Yellow
                Write-host "   Server RAM - $RamInMb MB" -ForegroundColor White
                Write-Host "   Ideal Pagefile size - $ExchangeRAM MB" -ForegroundColor White
                Write-host "   Maximum PageFile Size - $MaximumSize MB" -ForegroundColor White
                Write-host "   Initial PageFile Size - $InitialSize MB" -ForegroundColor White
            }
        }
    } Else {
        Write-Host 'Pagefile is configured (RAM + 10 MB) - ' -NoNewline
        Write-Host ' Failed' -ForegroundColor Red -NoNewline
        Write-Host ' --> Pagefile is Managed and against best practices.'
    }    

    # HyperThreading
    $Processors = Get-WMIObject Win32_Processor
    $LogicalCPU = ($Processors | measure-object -Property NumberOfLogicalProcessors -sum).Sum
    $PhysicalCPU = ($Processors | measure-object -Property NumberOfCores -sum).Sum
    If ($LogicalCPU -gt $PhysicalCPU)  {
        Write-Host 'Hyperthreading is Enabled - ' -NoNewline
        Write-Host 'Failed' -ForegroundColor Red
    } Else {
        Write-Host 'Hyperthreading is Disbaled - ' -NoNewline
        Write-Host 'Passed' -ForegroundColor Green
    }
    If ($LogicalCPU -gt 24) {
        Write-Host 'Maximum CPU cores is under 24 - ' -NoNewline
        Write-Host 'Failed' -ForegroundColor Red
    } Else {
        Write-Host 'Maximum CPU cores is under 24 - ' -NoNewline
        Write-Host 'Passed' -ForegroundColor Green
    }

    # SSL 3.0 Disabled (Windows 2019 version)
    $RegisTryPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    $Name = "Enabled"
    Try {
        If( (Get-ItemProperty -Path $regisTryPath -Name $name -ErrorAction STOP).Enabled -eq '0') {
            Write-Host 'SSL 3.0 is Disabled - ' -NoNewLine 
            Write-Host 'Passed' -ForegroundColor Green
        } Else {
            Write-Host 'SSL 3.0 is Enabled - ' -NoNewline
            Write-Host 'Failed' -ForegroundColor Red
        }
    } Catch {
            Write-Host 'SSL 3.0 is Disabled - ' -NoNewLine 
            Write-Host 'Passed' -ForegroundColor Green
    }

    # Get TCP Keep Alive value to process:
    TCPKeepAliveValue

    # MAPI Check
    $MAPIDetection = $True
    Try {
        $MAPIEnabled = (Get-OrganizationConfig -ErrorAction STOP).MAPIHttpEnabled
    } Catch {
        $MAPIDetection = $False
    }
    If ($MAPIDetection) {
        If ($MAPIEnabled) {
            Write-Host 'MAPI Enabled - ' -NoNewline
            Write-Host 'Passed' -ForegroundColor Green
        } Else {
            Write-Host 'MAPI Enabled - ' -NoNewline
            Write-Host 'Failed' -ForegroundColor Green
        }
    } Else {
        Write-Host 'MAPI Enabled - ' -NoNewline
        Write-Host 'Unknown' -ForegroundColor Yellow
    }

    # TLS Version Support
    TLSCheck

    # Formatting
    Write-host ' '
    Write-host ' '
} # End of Additional Checks Function

# Begin BITSCheck Function
Function BITSCheck {
    $Bits = Get-Module BitsTransfer
    If ($Bits -eq $null) {
        Write-Host "Importing the BITS module." -ForegroundColor Cyan
        try {
            Import-Module BitsTransfer -erroraction STOP
        } catch {
            Write-Host "Server Management module could not be loaded." -ForegroundColor Red
        }
    }
} # End BITSCheck Function

# Function Check Dot Net Version
Function Check-DotNetVersion {

    $DotNetFound = $False
    # .NET 4.8 or less check
	$NETval = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release"

    # Parse through most .NET possibilities:
    If ($NETval.Release -gt "528049") {
        Write-Host "Greater than .NET 4.8 is installed - " -NoNewLine 
        Write-Host " Unsupported" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "528049") {
        Write-Host ".NET 4.8 is installed. Suitable for Exchange 2013 CU23+ - " -NoNewLine 
        Write-Host " Passed" -ForegroundColor Green
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "461814") {
        Write-Host ".NET 4.7.2 is installed. Suitable for Exchange 2013 CU21+ - " -NoNewLine 
        Write-Host " Passed" -ForegroundColor Green
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "461310") {
        Write-Host ".NET 4.7.1 is installed. Suitable for Exchange 2013 CU19 to CU22 - " -NoNewLine
        Write-Host " Passed" -ForegroundColor Green
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "460805") {
        Write-Host ".NET 4.7.0 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        DotNetFound = $True
    }
    If ($NETval.Release -eq "394806") {
        Write-Host ".NET 4.6.2 is installed. Suitable for Exchange 2013 CU15 to CU20" -NoNewLine
        Write-Host " Passed" -ForegroundColor Yellow
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "394271") {
        Write-Host ".NET 4.6.1 is installed. Suitable for Exchange 2013 CU13 to CU15" -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "393297") {
        Write-Host ".NET 4.6.0 is installed and not supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "379893") {
        Write-Host ".NET 4.5.2 is installed. Suitable for Exchange 2013 CU4 to CU15 - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "378758") {
        Write-Host ".NET 4.5.1 is installed. Suitable for Exchange 2013 CU4 to CU15" -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "378389") {
        Write-Host ".NET 4.5.0 is installed. Suitable for Exchange 2013 RTM to CU14" -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -lt "378389") {
        Write-Host "Version less than .NET 4.5.0 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($DotNetFound -ne $True) {
        Write-Host 'A valid .NET Version was not found - ' -NoNewLine
        Write-host 'Failed' -ForegroundColor Red
    }

    $global:NetVersion = $NETVal

} # End Check-DotNetVersion

# Edge CAS / Mailbox requirements
Function CheckCASMailboxPrerequisites{
    CLS
    Write-Host '--------------------------------------' -ForegroundColor White
    Write-Host 'Checking CAS/Mailbox Role Requirements' -ForegroundColor Magenta
    Write-Host '--------------------------------------' -ForegroundColor White
    Write-Host ' '
    Write-Host ' '

    # .NET 4.7.1
	Check-DotNetVersion

    # Windows Management Framework 4.0 - Check - Needed for CU3+
	$wmf = $PSVersionTable.psversion
	If ($wmf.major -ge "4") {
        Write-Host "Windows Management Framework 4.0 is " -NoNewLine 
	    Write-Host "installed." -ForegroundColor Green
	} else {
	    Write-Host "Windows Management Framework 4.0 is " -NoNewLine 
	    Write-Host "not installed!" -ForegroundColor red
	}

    # Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit 
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
    If($val.DisplayVersion -ne "5.0.8308.0"){
        If($val.DisplayVersion -ne "5.0.8132.0"){
            If ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A41CBE7D-949C-41DD-9869-ABBD99D753DA}") -eq $False) {
                Write-Host "UCMA 4.0, Core Runtime 64-bit is " -NoNewLine 
                Write-Host "not installed!" -ForegroundColor red
                Write-Host "    ** Please install the newest UCMA 4.0 from http://www.microsoft.com/en-us/download/details.aspx?id=34992. **" -ForegroundColor Yellow
            }else {
            Write-Host "The Preview version of Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is " -NoNewLine 
            Write-Host "installed." -ForegroundColor red
            Write-Host "This is the incorrect version of UCMA. "  -NoNewLine -ForegroundColor red
            Write-Host "Please install the newest UCMA 4.0 from http://www.microsoft.com/en-us/download/details.aspx?id=34992." -ForegroundColor Yellow
            }
        } else {
        Write-Host "The wrong version of Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is " -NoNewLine
        Write-Host "installed." -ForegroundColor red
        Write-Host "This is the incorrect version of UCMA. "  -NoNewLine -ForegroundColor red 
        Write-Host "Please install the newest UCMA 4.0 from http://www.microsoft.com/en-us/download/details.aspx?id=34992." -ForegroundColor Yellow
        }   
    } else {
         Write-Host "The correct version of Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is " -NoNewLine
         Write-Host "installed." -ForegroundColor Green
    }

    # C++ 2012 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\7C9F8B73BF303523781852719CD9C700" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '184610406'){
		Write-Host "Microsoft Visual C++ 2012 x64 Runtime - 11.0.61030 is" -NoNewline
        Write-Host " installed." -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Visual C++ 2012 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    # C++ 2013 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\AB297010A1550CA37AFEF0BA14653C28" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '201367256'){
		Write-Host "Microsoft Visual C++ 2013 x64 Runtime - 12.0.40664 is " -NoNewline
        Write-Host "installed." -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Visual C++ 2013 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    # Check Windows Feature Install
	$Values = @("AS-HTTP-Activation","Desktop-Experience","NET-Framework-45-Features","RPC-over-HTTP-proxy","RSAT-Clustering","RSAT-Clustering-CmdInterface","Web-Mgmt-Console","WAS-Process-Model","Web-Asp-Net45","Web-Basic-Auth","Web-Client-Auth","Web-Digest-Auth","Web-Dir-Browsing","Web-Dyn-Compression","Web-Http-Errors","Web-Http-Logging","Web-Http-Redirect","Web-Http-Tracing","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Lgcy-Mgmt-Console","Web-Metabase","Web-Mgmt-Console","Web-Mgmt-Service","Web-Net-Ext45","Web-Request-Monitor","Web-Server","Web-Stat-Compression","Web-Static-Content","Web-Windows-Auth","Web-WMI","Windows-Identity-Foundation")
	Foreach ($Item in $Values){
	    $Val = Get-Windowsfeature $Item
	    If ($Val.Installed -eq $True){
	        Write-Host "The Windows Feature $Item is " -NoNewLine 
	        Write-Host "installed." -ForegroundColor Green
	    } Else {
	        Write-Host "The Windows Feature $Item is " -NoNewLine 
	        Write-Host "not installed!" -ForegroundColor red
	    }
	}

    Write-Host ' '
    Write-Host ' '
    Write-Host ' '
}

# Edge CAS / Mailbox requirements
Function CheckCASPrerequisites {
    CLS
    Write-Host '------------------------------' -ForegroundColor White
    Write-Host 'Checking CAS Role Requirements' -ForegroundColor Magenta
    Write-Host '------------------------------' -ForegroundColor White
    Write-Host ' '
    Write-Host ' '

    # .NET Check
	Check-DotNetVersion

    # Windows Management Framework 4.0 - Check - Needed for CU3+
	$wmf = $PSVersionTable.psversion
	If ($wmf.major -ge "4") {
        Write-Host "Windows Management Framework 4.0 is " -NoNewLine 
	    Write-Host "installed." -ForegroundColor Green
	} else {
	    Write-Host "Windows Management Framework 4.0 is " -NoNewLine 
	    Write-Host "not installed!" -ForegroundColor red
	}

    # Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit 
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
    If($val.DisplayVersion -ne "5.0.8308.0"){
        If($val.DisplayVersion -ne "5.0.8132.0"){
            If ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A41CBE7D-949C-41DD-9869-ABBD99D753DA}") -eq $False) {
                Write-Host "UCMA 4.0, Core Runtime 64-bit is " -NoNewLine 
                Write-Host "not installed!" -ForegroundColor red
                Write-Host "    ** Please install the newest UCMA 4.0 from http://www.microsoft.com/en-us/download/details.aspx?id=34992. **" -ForegroundColor Yellow
            }else {
            Write-Host "The Preview version of Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is " -NoNewLine 
            Write-Host "installed." -ForegroundColor red
            Write-Host "This is the incorrect version of UCMA. "  -NoNewLine -ForegroundColor red
            Write-Host "Please install the newest UCMA 4.0 from http://www.microsoft.com/en-us/download/details.aspx?id=34992." -ForegroundColor Yellow
            }
        } else {
        Write-Host "The wrong version of Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is " -NoNewLine
        Write-Host "installed." -ForegroundColor red
        Write-Host "This is the incorrect version of UCMA. "  -NoNewLine -ForegroundColor red 
        Write-Host "Please install the newest UCMA 4.0 from http://www.microsoft.com/en-us/download/details.aspx?id=34992." -ForegroundColor Yellow
        }   
    } else {
         Write-Host "The correct version of Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is " -NoNewLine
         Write-Host "installed." -ForegroundColor Green
    }

    # C++ 2012 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\7C9F8B73BF303523781852719CD9C700" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '184610406'){
		Write-Host "Microsoft Visual C++ 2012 x64 Runtime - 11.0.61030 is" -NoNewline
        Write-Host " installed." -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Visual C++ 2012 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    # C++ 2013 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\AB297010A1550CA37AFEF0BA14653C28" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '201367256'){
		Write-Host "Microsoft Visual C++ 2013 x64 Runtime - 12.0.40664 is " -NoNewline
        Write-Host "installed." -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Visual C++ 2013 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    $Values = @("AS-HTTP-Activation","Desktop-Experience","NET-Framework-45-Features","RPC-over-HTTP-proxy","RSAT-Clustering","Web-Mgmt-Console","WAS-Process-Model","Web-Asp-Net45","Web-Basic-Auth","Web-Client-Auth","Web-Digest-Auth","Web-Dir-Browsing","Web-Dyn-Compression","Web-Http-Errors","Web-Http-Logging","Web-Http-Redirect","Web-Http-Tracing","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Lgcy-Mgmt-Console","Web-Metabase","Web-Mgmt-Console","Web-Mgmt-Service","Web-Net-Ext45","Web-Request-Monitor","Web-Server","Web-Stat-Compression","Web-Static-Content","Web-Windows-Auth","Web-WMI","Windows-Identity-Foundation")
	Foreach ($Item in $Values){
	    $Val = Get-WindowsFeature $Item
	    If ($Val.Installed -eq $True){
	        Write-Host "The Windows Feature $Item is " -NoNewLine 
	        Write-Host "installed." -ForegroundColor Green
	    } else {
	        Write-Host "The Windows Feature $Item is " -NoNewLine 
	        Write-Host "not installed!" -ForegroundColor red
	    }
	}

    Write-Host "Make sure to open port 139 in the Windows firewall. See the link below:"
	Write-Host "    ** http://technet.microsoft.com/en-us/library/bb691354(v=exchg.150).aspx **" -ForegroundColor yellow

    # Formatting
    Write-Host ' '
    Write-Host ' '
    Write-Host ' '
}

# Edge Transport requirements
Function CheckEdgeTransportPrerequisites {
    CLS
    Write-Host '-----------------------------------------------------------' 
    Write-Host 'Checking Edge Transport Role Requirements for Exchange 2013' -ForegroundColor Magenta
    Write-Host '-----------------------------------------------------------'
    Write-Host ' '

    # Windows Feature AD LightWeight Services
	$Values = @("ADLDS")
	Foreach ($Item in $Values){
		$Val = Get-Windowsfeature $Item
		If ($Val.Installed -eq $True){
			Write-Host "The Windows Feature"$item" is " -NoNewLine 
			Write-Host "installed." -ForegroundColor Green
		}else{
			Write-Host "The Windows Feature"$item" is " -NoNewLine 
			Write-Host "not installed!" -ForegroundColor red
		}
	}

    # .NET 4.5.2 [for CU7+] or .NET 4.6.1 [CU13+]
    Check-DotNetVersion

    # Windows Management Framework 4.0 - Check - Needed for CU3+
	$wmf = $PSVersionTable.psversion
	If ($wmf.major -ge "4") {
    	Write-Host "Windows Management Framework 4.0 is " -NoNewLine 
	    Write-Host "installed." -ForegroundColor Green
	} else {
	    Write-Host "Windows Management Framework 4.0 is " -NoNewLine 
	    Write-Host "not installed!" -ForegroundColor red
	}

    # C++ 2012 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\7C9F8B73BF303523781852719CD9C700" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '184610406'){
		Write-Host "Microsoft Visual C++ 2012 x64 Runtime - 11.0.61030 is" -NoNewline
        Write-Host " installed." -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Visual C++ 2012 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    # C++ 2013 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\AB297010A1550CA37AFEF0BA14653C28" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '201367256'){
		Write-Host "Microsoft Visual C++ 2013 x64 Runtime - 12.0.40664 is " -NoNewline
        Write-Host "installed." -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Visual C++ 2013 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    # Formatting
    Write-Host ' '
    Write-Host ' '
} # End Edge Transport requirements

# Check the server power management
Function CheckPowerPlan {
	$HighPerf = powercfg -l | %{If($_.contains("High performance")) {$_.split()[3]}}
	$CurrPlan = $(powercfg -getactivescheme).split()[3]
	If ($CurrPlan -eq $HighPerf) {
		Write-Host " ";Write-Host "The power plan now is set to " -NoNewLine;Write-Host "High Performance." -ForegroundColor Green
	}
}

# Final Cleanup - C++ and register ASP .NET
Function Cleanup-Final {
	# Old C++ from the old UCMA
	# [STRING] $downloadfile2 = "C:\ProgramData\Package Cache\{5b2d190f-406e-49cf-8fea-1c3fc6777778}"
	[STRING] $downloadfile2 = "C:\ProgramData\Package Cache\{15134cb0-b767-4960-a911-f2d16ae54797}"
	Set-Location $DownloadFolder2
	[string]$expression = ".\vcredist_x64.exe /q /uninstall /norestart"
	Invoke-Expression $expression
	c:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe -ir -enable
	iisreset
}

#Configure TCP Keep Alive value Function
Function ConfigureTCPKeepAlive {

    # Get current values
    $TCPPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $TCPParam = Get-ItemProperty -Path $TCPPath
    $TCPVal = $TCPParam.KeepAliveTime

    If($TCPVal -eq $Null){

        # Set TCP Keep Alive to 1800000
        New-ItemProperty -Path $TCPPath -Name "KeepAliveTime" -Value 1800000 -Force -PropertyType DWord
        Write-Host "TCP Keep Alive Value now set at " -NoNewline
        Write-Host "1800000" -ForegroundColor Green

    } Else {
        If ((899999 -lt $TCPVal) -and ($TCPVal -lt 1800001)) {
              
            # Value is already set and optimal
            Write-Host "TCP Keep Alive Value is properly set at " -NoNewline
            Write-Host "$TCPVal" -ForegroundColor Green      

        } Else {

            # Set TCP Keep Alive to 1800000
            New-ItemProperty -Path $TCPPath -Name "KeepAliveTime" -Value 1800000 -Force -PropertyType DWord
            Write-Host "TCP Keep Alive Value now set at " -NoNewline
            Write-Host "1800000" -ForegroundColor Green

        }
    }

} # End of Configure TCP Keep Alive value Function

# Configure PageFile for Exchange
Function ConfigurePagefile {
    $stop = $False

    # Remove Existing PageFile
    try {
        Set-CimInstance -Query “Select * from win32_computersystem” -Property @{automaticmanagedpagefile=”False”} 
    } catch {
        Write-Host "Cannot remove the existing Pagefile." -ForegroundColor Red
        $stop = $true
    }
    # Get RAM and set ideal PageFileSize
    $GB = 1048576
    try {
        $RamInMb = (Get-CIMInstance -computername $name -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/$GB
    } catch {
        Write-Host "Cannot acquire the amount of RAM in the server." -ForegroundColor Red
        $stop = $true
    }
    $ExchangeRAM = $RAMinMb + 10

    If ($stop -ne $true) {
        # Configure PageFile
        try {
            Set-CimInstance -Query “Select * from win32_PageFileSetting” -Property @{InitialSize=$ExchangeRAM;MaximumSize=$ExchangeRAM}
        } catch {
            Write-Host "Cannot configure the PageFile correctly." -ForegroundColor Red
        }
        $pagefile = Get-CimInstance win32_PageFileSetting -Property * | select-object Name,initialsize,maximumsize
        $name = $pagefile.name;$max = $pagefile.maximumsize;$min = $pagefile.initialsize
        Write-Host " "
        Write-Host "The page file of $name is now configured for an initial size of " -ForegroundColor White -NoNewline
        Write-Host "$min " -ForegroundColor Green -NoNewline
        Write-Host "and a maximum size of " -ForegroundColor White -NoNewline
        Write-Host "$max." -ForegroundColor Green
        Write-Host " "
    } else {
        Write-Host "The PageFile cannot be configured at this time." -ForegroundColor Red
    }
}

# Function Install C++ 2013 and C++ 2012
Function CPlusPlus {
    
    # Install C++ 2012 (Current - 2019/06/11)
    # First check if 2012 is installed already
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\C3AEB2FCAE628F23AAB933F1E743AB79" -ErrorAction Silentlycontinue
    If($val.Version -ge '184610406'){
		Write-Host 'Microsoft Visual C++ 2012 x64 Runtime - 11.0.61030 is already' -NoNewLine
        Write-Host ' installed.' -ForegroundColor Green
    } Else {

        If (Test-Path "$DownloadFolder\vcRedist_x64.exe") {
            Del "$DownloadFolder\vcRedist_x64.exe"
        }
        FileDownload "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcRedist_x64.exe"
        While (!(Test-Path "c:\Install\vcRedist_x64.exe")) { Start-Sleep 1}
        If (Test-Path "$DownloadFolder\2012-vcRedist_x64.exe") {
            Del "$DownloadFolder\2012-vcRedist_x64.exe"
        }
        REN c:\Install\vcRedist_x64.exe c:\Install\2012-vcRedist_x64.exe
        Set-Location $DownloadFolder
        [string]$expression = ".\2012-vcRedist_x64.exe /quiet /norestart /l* $targetfolder\2012-cPlusPlus.log"
        Write-Host "Installing C++ 2012..." -NoNewLine -ForegroundColor Yellow
        Invoke-Expression $expression | Out-Null
    
        # C++ 2012 Check - Post Install Check
        $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\C3AEB2FCAE628F23AAB933F1E743AB79" -ErrorAction Silentlycontinue
        If($val.Version -ge '184610406'){
		    Write-Host 'Microsoft Visual C++ 2012 x64 Runtime - 11.0.61030 is now ' -NoNewline
            Write-Host 'installed.' -ForegroundColor Green
	    } Else {
            Write-Host 'Microsoft Visual C++ 2012 x64 Runtime was' -ForegroundColor White -NoNewline
            Write-Host ' not detected! ' -ForegroundColor Yellow -NoNewline
            Write-Host 'A reboot may be needed.' -ForegroundColor White
        }
    }

    # Install C++ 2013 (Current - 2019/06/11)
    # First check if 2012 is installed already
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\4396FC35D89A48D31964CFE4FDD36514" -ErrorAction Silentlycontinue
    If($val.Version -ge '201367256'){
		Write-Host 'Microsoft Visual C++ 2013 x64 Runtime - 12.0.40664 is already ' -NoNewLine
        Write-Host 'installed.' -ForegroundColor Green
    } Else {
        If (Test-Path "$DownloadFolder\vcRedist_x64.exe") {
            Del "$DownloadFolder\vcRedist_x64.exe"
        }
        FileDownload "https://download.visualstudio.microsoft.com/download/pr/10912041/cee5d6bca2ddbcd039da727bf4acb48a/vcRedist_x64.exe"
        While (!(Test-Path "c:\Install\vcRedist_x64.exe")) { Start-Sleep 1} 
        If (Test-Path "$DownloadFolder\2013-vcRedist_x64.exe") {
            Del "$DownloadFolder\2013-vcRedist_x64.exe"
        }
        REN c:\Install\vcRedist_x64.exe c:\Install\2013-vcRedist_x64.exe
        Set-Location $DownloadFolder
        [string]$expression = ".\2013-vcRedist_x64.exe /quiet /norestart /l* $targetfolder\2013-cPlusPlus.log"
        Write-Host "Installing C++ 2013..." -NoNewLine -ForegroundColor Yellow
        Invoke-Expression $expression | Out-Null

        # C++ 2013 Check
        $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\4396FC35D89A48D31964CFE4FDD36514" -ErrorAction Silentlycontinue
        If($val.Version -ge '201367256'){
		    Write-Host 'Microsoft Visual C++ 2013 x64 Runtime - 12.0.40664 is now ' -NoNewline
            Write-Host 'installed.' -ForegroundColor Green
	    } Else {
            Write-Host 'Microsoft Visual C++ 2013 x64 Runtime was' -ForegroundColor White -NoNewline
            Write-Host ' not detected! ' -ForegroundColor Yellow -NoNewline
            Write-Host 'A reboot may be needed.' -ForegroundColor White
        }
    }
    
} # End of CPlusPlus Function

# Function Install C++ 2012
Function CPlusPlus2012 {

    # Install C++ 2012 (Current - 2019/06/11)
    If (Test-Path "$DownloadFolder\vcRedist_x64.exe") {
        Del "$DownloadFolder\vcRedist_x64.exe"
    }
    FileDownload "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcRedist_x64.exe"
    While (!(Test-Path "c:\Install\vcRedist_x64.exe")) { Start-Sleep 1}
    If (Test-Path "$DownloadFolder\2012-vcRedist_x64.exe") {
        Del "$DownloadFolder\2012-vcRedist_x64.exe"
    }
    REN c:\Install\vcRedist_x64.exe c:\Install\2012-vcRedist_x64.exe
    Set-Location $DownloadFolder
    [string]$expression = ".\2012-vcRedist_x64.exe /quiet /norestart /l* $targetfolder\2012-cPlusPlus.log"
    Write-Host "Installing C++ 2012..." -NoNewLine -ForegroundColor Yellow
    Invoke-Expression $expression | Out-Null
    
    # C++ 2012 Check
    # $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\7C9F8B73BF303523781852719CD9C700" -ErrorAction Silentlycontinue
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\C3AEB2FCAE628F23AAB933F1E743AB79" -ErrorAction Silentlycontinue
    
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '184610406'){
		Write-Host "`nMicrosoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030 is now installed." -ForegroundColor Green
	} Else {
        Write-Host "`nMicrosoft Visual C++ 2012 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }
    Write-Host " "

} # End of CPlusPlus2012 Install Function

# Function Install C++ 2013
Function CPlusPlus2013 {
    
    # Install C++ 2013 (Current - 2019/06/11)
    If (Test-Path "$DownloadFolder\vcRedist_x64.exe") {
        Del "$DownloadFolder\vcRedist_x64.exe"
    }
    FileDownload "https://download.visualstudio.microsoft.com/download/pr/10912041/cee5d6bca2ddbcd039da727bf4acb48a/vcRedist_x64.exe"
    While (!(Test-Path "c:\Install\vcRedist_x64.exe")) { Start-Sleep 1}
    If (Test-Path "$DownloadFolder\2013-vcRedist_x64.exe") {
        Del "$DownloadFolder\2013-vcRedist_x64.exe"
    }
    REN c:\Install\vcRedist_x64.exe c:\Install\2013-vcRedist_x64.exe
    Set-Location $DownloadFolder
    [string]$expression = ".\2013-vcRedist_x64.exe /quiet /norestart /l* $targetfolder\2013-CPlusPlus2013.log"
    Write-Host "Installing C++ 2013..." -NoNewLine -ForegroundColor Yellow
    Invoke-Expression $expression | Out-Null

    # C++ 2013 Check
    # $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\AB297010A1550CA37AFEF0BA14653C28" -ErrorAction Silentlycontinue
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\4396FC35D89A48D31964CFE4FDD36514" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '201367256'){
		Write-Host "`nMicrosoft Visual C++ 2013 x64 Runtime - 12.0.40664 is now installed." -ForegroundColor Green
	} Else {
        Write-Host "`nMicrosoft Visual C++ 2013 x64 Runtime was" -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

} # End of CPlusPlus2013 Function

# CPlusPlus2013 Function Check
Function CPlusPlus2013Check {
    # C++ 2013 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\AB297010A1550CA37AFEF0BA14653C28" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '201367256'){
		Write-Host "Microsoft Visual C++ 2013 x64 Runtime - 12.0.40664 is " -NoNewline
        Write-Host "installed." -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Visual C++ 2013 x64 Runtime was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }
}# End CPlusPlus2013 Function Check

 # Disable RC4
Function DisableRC4 {
    Write-Host " "
	# Define Registry keys to look for
	$base = Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" -erroraction silentlycontinue
	$val1 = Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128\" -erroraction silentlycontinue
	$val2 = Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128\" -erroraction silentlycontinue
	$val3 = Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128\" -erroraction silentlycontinue
	
	# Define Values to add
	$registryBase = "Ciphers"
	$registryPath1 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128\"
	$registryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128\"
	$registryPath3 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128\"
	$Name = "Enabled"
	$value = "0"
	$ssl = 0
	$checkval1 = Get-Itemproperty -Path "$registrypath1" -name $name -erroraction silentlycontinue
	$checkval2 = Get-Itemproperty -Path "$registrypath2" -name $name -erroraction silentlycontinue
	$checkval3 = Get-Itemproperty -Path "$registrypath3" -name $name -erroraction silentlycontinue
    
# Formatting for output
	Write-Host " "

# Add missing registry keys as needed
	If ($base -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", $true)
		$key.CreateSubKey('Ciphers')
		$key.Close()
	} else {
		Write-Host "The " -NoNewLine
        Write-Host "Ciphers" -ForegroundColor Green -NoNewline
        Write-Host " Registry key already exists."
	}

	If ($val1 -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
		$key.CreateSubKey('RC4 128/128')
		$key.Close()
	} else {
		Write-Host "The " -NoNewLine
        Write-Host "Ciphers\RC4 128/128" -ForegroundColor Green -NoNewline
        Write-Host " Registry key already exists."
	}

	If ($val2 -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
		$key.CreateSubKey('RC4 40/128')
		$key.Close()
		New-ItemProperty -Path $registryPath2 -Name $name -Value $value -force -PropertyType "DWord"
	} else {
		Write-Host "The " -NoNewLine
        Write-Host "Ciphers\RC4 40/128" -ForegroundColor Green -NoNewline
        Write-Host " Registry key already exists."
	}

	If ($val3 -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
		$key.CreateSubKey('RC4 56/128')
		$key.Close()
	} else {
		Write-Host "The " -NoNewLine
        Write-Host "Ciphers\RC4 56/128" -ForegroundColor Green -NoNewline
        Write-Host " Registry key already exists."
	}
	
# Add the enabled value to disable RC4 Encryption
	If ($checkval1.enabled -ne "0") {
		try {
			New-ItemProperty -Path $registryPath1 -Name $name -Value $value -force -PropertyType "DWord"
            $ssl++
		} catch {
			$SSL--
		} 
	} else {
		Write-Host "The registry value " -NoNewLine
        Write-Host "Enabled" -ForegroundColor Green -NoNewline
        Write-Host " exists under the RC4 128/128 Registry Key."
        $ssl++
	}
	If ($checkval2.enabled -ne "0") {
		Write-Host $checkval2
		try {
			New-ItemProperty -Path $registryPath2 -Name $name -Value $value -force -PropertyType "DWord"
            $ssl++
		} catch {
			$SSL--
		} 
	} else {
		Write-Host "The registry value " -NoNewLine
        Write-Host "Enabled" -ForegroundColor Green -NoNewline
        Write-Host " exists under the RC4 40/128 Registry Key."
        $ssl++
	}
	If ($checkval3.enabled -ne "0") {
		try {
			New-ItemProperty -Path $registryPath3 -Name $name -Value $value -force -PropertyType "DWord"
            $ssl++
		} catch {
			$SSL--
		} 
	} else {
		Write-Host "The registry value " -NoNewLine
        Write-Host "Enabled" -ForegroundColor Green -NoNewline
        Write-Host " exists under the RC4 56/128 Registry Key."
        $ssl++
	}

# SSL Check totals
	If ($ssl -eq "3") {
		Write-Host " "
        Write-Host "RC4 " -ForegroundColor yellow -NoNewline
        Write-Host "is completely disabled on this server."
        Write-Host " "
	} 
	If ($ssl -lt "3"){
		Write-Host " "
        Write-Host "RC4 " -ForegroundColor yellow -NoNewline
        Write-Host "only has $ssl part(s) of 3 disabled.  Please check the registry to manually to add these values"
        Write-Host " "
	}
} # End of Disable RC4 Function

# Disable SSL 3.0
Function DisableSSL3 {
    Write-Host " "
    $TestPath1 = Get-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" -erroraction silentlycontinue
    $TestPath2 = Get-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -erroraction silentlycontinue
    $registrypath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    $Name = "Enabled"
	$value = "0"
    $checkval1 = Get-Itemproperty -Path "$registrypath" -name $name -erroraction silentlycontinue

# Check for SSL 3.0 Reg Key
	If ($TestPath1 -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols", $true)
		$key.CreateSubKey('SSL 3.0')
		$key.Close()
	} else {
		Write-Host "The " -NoNewLine;Write-Host "SSL 3.0" -ForegroundColor Green -NoNewline;Write-Host " Registry key already exists."
	}

# Check for SSL 3.0\Server Reg Key
	If ($TestPath2 -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0", $true)
		$key.CreateSubKey('Server')
		$key.Close()
	} else {
		Write-Host "The " -NoNewLine;Write-Host "SSL 3.0\Servers" -ForegroundColor Green -NoNewline;Write-Host " Registry key already exists."
	}

# Add the enabled value to disable SSL 3.0 Support
	If ($checkval1.enabled -ne "0") {
		try {
			New-ItemProperty -Path $registryPath -Name $name -Value $value -force;$ssl++
		} catch {
			$SSL--
		} 
	} else {
		Write-Host "The registry value " -NoNewLine;Write-Host "Enabled" -ForegroundColor Green -NoNewline;Write-Host " exists under the SSL 3.0\Server Registry Key."
	}
} # End of Disable SSL 3.0 Function

# Set Event Log Limits
Function EventLogLimits {
    CLS
    Write-Host "-------------------------------------------------------------------" -ForegroundColor White
	Write-Host "Setting the following Event Logs to 100 MB and Overwrite As Needed:" -ForegroundColor Magenta
	Write-Host "-------------------------------------------------------------------" -ForegroundColor White
	Write-Host "  Application" -ForegroundColor Yellow
	Write-Host "  System" -ForegroundColor Yellow
	Write-Host "  Security" -ForegroundColor Yellow

	# Set Limits and Overflow value
	Limit-EventLog -LogName Application -MaximumSize 100032Kb -OverflowAction OverwriteAsNeeded
	Limit-EventLog -LogName System -MaximumSize 100032Kb -OverflowAction OverwriteAsNeeded
	Limit-EventLog -LogName Security -MaximumSize 100032Kb -OverflowAction OverwriteAsNeeded
    Write-Host ""
    Write-Host ""
    Start-Sleep 3

    $Sizes = EventLog -list | where {($_.log -eq 'Application') -or ($_.log -eq 'system') -or ($_.log -eq 'Security')}
    Foreach ($Size in $Sizes) {
        $Log = $Size.Log
        If ($Size.maximumkilobytes -eq '100032') {
            If ($Size.OverFlowAction -eq 'OverwriteAsNeeded') {
                Write-host "SUCCESS! - " -ForegroundColor Green -NoNewLine
                Write-host "$Log was changed to " -ForegroundColor White -NoNewLine
                Write-host "100MB " -ForegroundColor Green -NoNewLine
                Write-host "and set to " -ForegroundColor White -NoNewLine
                Write-host "Overwrite As Needed." -ForegroundColor Green
            } Else {
                Write-host "WARNING! - " -ForegroundColor Yellow -NoNewLine
                Write-host "$Log was changed to " -ForegroundColor White -NoNewLine
                Write-host "100MB " -ForegroundColor Green -NoNewLine
                Write-host "but not set to " -ForegroundColor White -NoNewLine
                Write-host "Overwrite As Needed." -ForegroundColor Yellow
            }
        } Else {
           If ($Size.OverFlowAction -eq 'OverwriteAsNeeded') {
                Write-host "WARNING! - " -ForegroundColor Yellow -NoNewLine
                Write-host "$Log was NOT changed to " -ForegroundColor White -NoNewLine
                Write-host "100MB " -ForegroundColor Yellow -NoNewLine
                Write-host "but was set to " -ForegroundColor White -NoNewLine
                Write-host "Overwrite As Needed." -ForegroundColor Green
           } Else {
                Write-host "FAILURE! - " -ForegroundColor Red -NoNewLine
                Write-host "$Log was not changed to " -ForegroundColor White -NoNewLine
                Write-host "100MB " -ForegroundColor Yellow -NoNewLine
                Write-host "NOR set to " -ForegroundColor White -NoNewLine
                Write-host "Overwrite As Needed." -ForegroundColor Yellow
           }
        }
    }
    Write-Host ""
    Write-Host ""
    Start-Sleep 3
} # End Set Event Log Limits function

# Begin FileDownload Function
Function FileDownload {
    Param ($sourcefile)
    $Internetaccess = $Null
    Try {
        $Internetaccess = (Get-NetConnectionProfile -IPv4Connectivity Internet -ErrorAction STOP).ipv4connectivity
    } Catch {
        # Write-Host "This machine does not have internet access and thus cannot download required files. Please resolve!" -ForegroundColor Red
        $Download = $False
        Return $Download
    }
    If ($Internetaccess -eq "Internet") {
        If (Test-path $DownloadFolder) {
            Write-Host "Target folder $DownloadFolder exists." -ForegroundColor White
        } else {
            New-Item $DownloadFolder -type Directory | Out-Null
        }
        BITSCheck
        [string] $DownloadFile = $sourcefile.Substring($sourcefile.LastIndexOf("/") + 1)
        If (Test-Path "$DownloadFolder\$DownloadFile"){
            Write-Host "The file $DownloadFile already exists in the $DownloadFolder folder." -ForegroundColor Cyan
        } else {
            Start-BitsTransfer -Source "$SourceFile" -Destination "$DownloadFolder\$DownloadFile"
        }
        $Download = $True
        Return $Download
    } else {
        Write-Host "This machine does not have internet access and thus cannot download required files. Please resolve!" -ForegroundColor Red
        $Download = $False
        Return $Download
    }
} # End FileDownload Function

# Function - .NET 4.8
Function Install-NET48 {

    # VerIfy .NET 4.8 is not already installed
    Check-DotNetVersion
    $DotNetVersion = ($global:NetVersion).release
    If ($DotNetVersion -lt 528049) {
        Write-Host "  ***  .NET 4.8 is not installed.  Downloading now!!  ***" -ForegroundColor Yellow
        # Download .NET 4.8 installer
        FileDownload "https://download.visualstudio.microsoft.com/download/pr/7afca223-55d2-470a-8edc-6a1739ae3252/abd170b4b0ec15ad0222a809b761a036/ndp48-x86-x64-allos-enu.exe"
	    Set-Location $DownloadFolder
        Write-Host " "
	    Write-Host "File: ndp48-x86-x64-allos-enu.exe installing..." -NoNewLine

        # New Code (Waits for completion)
        .\ndp48-x86-x64-allos-enu.exe /quiet /norestart | Out-Null

        # Old Code (removed)
        # [string]$expression = ".\ndp48-x86-x64-allos-enu.exe /quiet /norestart /l* $DownloadFolder\DotNET48.log"
        # Invoke-Expression $Expression | Out-Null
        # Start-Sleep -Seconds 60
        
        Write-Host "`n.NET 4.8 is now installed" -ForegroundColor Green
        Write-Host " "
        $Reboot = $true
    } 
    start-sleep 2

} # End of Function .NET 4.8 Install

# Install Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit
Function Install-NewWinUniComm4{
	$File = "http://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe"
    $Download = FileDownload $File
    If ($Download) {
	    Set-Location $DownloadFolder
        # [string]$expression = ".\UcmaRuntimeSetup.exe /quiet /norestart /l* $downloadfolder\WinUniComm4.log"
	    Write-Host "File: UcmaRuntimeSetup.exe installing..." -NoNewLine
	    # Invoke-Expression $expression

        Start-Process '.\UcmaRuntimeSetup.exe' -ArgumentList '/quiet','/norestart' –Wait 

	    Start-Sleep -Seconds 20
	    $Val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
	    If($val.DisplayVersion -ne "5.0.8308.0"){
		    Write-Host "`nMicrosoft UnIfied Communications Managed API 4.0 is now installed" -ForegroundColor Green
	    }
        Write-Host " "
    }
} # End Install-NewWinUniComm4

# Pre .NEt Installer
Function Install-PreDotNet {
    # VerIfy .NET 4.7.2 or 4.8 is not already installed
    Check-DotNetVersion
    $DotNetVersion = ($global:NetVersion).release
    If ($DotNetVersion -lt 461310) {
        Write-Host " "
        Write-Host "A version of .NET less than 4.7.2 is installed." -ForegroundColor Yellow
        Write-Host "Installing all patches required in order to install .NET 4.7.2 or .NET 4.8." -ForegroundColor White
        Write-Host " "

        # KB2919442 Install
        $Download = FileDownload "https://download.microsoft.com/download/D/6/0/D60ED3E0-93A5-4505-8F6A-8D0A5DA16C8A/Windows8.1-KB2919442-x64.msu"
        If ($Download) {
            Set-Location $DownloadFolder
            Write-Host " "
            Write-Host "File: Windows8.1-KB2919442-x64.msu installing..." -NoNewLine
            $HotFixInstall={
                $arglist='Windows8.1-KB2919442-x64.msu','/quiet','/norestart'
                Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
            }
            Invoke-Command -ScriptBlock $HotFixInstall
            Start-Sleep -Seconds 60
            Write-Host "`nKB2919442 is now installed" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download KB2919442.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }

        # clearcompressionflag.exe Install
        $Download = FileDownload "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/clearcompressionflag.exe"
        If ($Download) {
            Set-Location $DownloadFolder
            # [string]$expression = ".\clearcompressionflag.exe /quiet /norestart /l* $DownloadFolder\clearcompressionflag.log"
            [string]$expression = ".\clearcompressionflag.exe /norestart /l* $DownloadFolder\clearcompressionflag.log"
            Write-Host " "
            Write-Host "File: clearcompressionflag.exe installing..." -NoNewLine
            Invoke-Expression $expression
            Start-Sleep -Seconds 60
            Write-Host "`nClearcompressionflag.exe has been run" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download ClearCompressionFlag.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }

        # KB2919355 Install
        $Download = FileDownload "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2919355-x64.msu"
        If ($Download) {
            Set-Location $DownloadFolder
            Write-Host " "
            Write-Host "WARNING: THIS HOTFIX COULD TAKE 25 MINUTES TO INSTALL!!!" -ForegroundColor Red
            Write-Host " "
            Write-Host "File: Windows8.1-KB2919355-x64.msu installing..." -NoNewLine
            $HotFixInstall={
                $arglist='Windows8.1-KB2919355-x64.msu','/quiet','/norestart'
                Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
            }
            Invoke-Command -ScriptBlock $HotFixInstall
            Start-Sleep -Seconds 60
            Write-Host "`nKB2919355 is now installed" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download KB2919355.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }

        # KB2932046 Install
        $Download = FileDownload "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2932046-x64.msu"
        If ($Download) {
            Set-Location $DownloadFolder
            Write-Host " "
            Write-Host "File: Windows8.1-KB2932046-x64.msu installing..." -NoNewLine
            $HotFixInstall={
                $arglist='Windows8.1-KB2932046-x64.msu','/quiet','/norestart'
                Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
            }
            Invoke-Command -ScriptBlock $HotFixInstall
            Start-Sleep -Seconds 60
            Write-Host "`nKB2932046 is now installed" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download KB2932046.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }

        # KB2959977 Install    
        $Download = FileDownload "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2959977-x64.msu"
        If ($Download) {
            Set-Location $DownloadFolder
            Write-Host " "
            Write-Host "File: Windows8.1-KB2959977-x64.msu installing..." -NoNewLine
            $HotFixInstall={
                $arglist='Windows8.1-KB2959977-x64.msu','/quiet','/norestart'
                Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
            }
            Invoke-Command -ScriptBlock $HotFixInstall
            Start-Sleep -Seconds 60
            Write-Host "`nKB2959977 is now installed" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true    
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download KB2959977.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }

        # KB2937592 Install    
        $Download = FileDownload "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2937592-x64.msu"
        If ($Download) {
            Set-Location $DownloadFolder
            Write-Host " "
            Write-Host "File: Windows8.1-KB2937592-x64.msu installing..." -NoNewLine
            $HotFixInstall={
                $arglist='Windows8.1-KB2937592-x64.msu','/quiet','/norestart'
                Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
            }
            Invoke-Command -ScriptBlock $HotFixInstall
            Start-Sleep -Seconds 60
            Write-Host "`nKB2937592 is now installed" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true    
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download KB2937592.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }

        # KB2938439 Install
        $Download = FileDownload "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2938439-x64.msu"
        If ($Download) {
            Set-Location $DownloadFolder
            Write-Host " "
            Write-Host "File: Windows8.1-KB2938439-x64.msu installing..." -NoNewLine
            $HotFixInstall={
                $arglist='Windows8.1-KB2938439-x64.msu','/quiet','/norestart'
                Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
            }
            Invoke-Command -ScriptBlock $HotFixInstall
            Start-Sleep -Seconds 60
            Write-Host "`nKB2938439 is now installed" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download KB2938439.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }

        # KB2934018 Install    
        $Download = FileDownload "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2934018-x64.msu"
        If ($Download) {
            Set-Location $DownloadFolder
            Write-Host " "
            Write-Host "File: Windows8.1-KB2934018-x64.msu installing..." -NoNewLine
            $HotFixInstall={
                $arglist='Windows8.1-KB2934018-x64.msu','/quiet','/norestart'
                Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
            }
            Invoke-Command -ScriptBlock $HotFixInstall
            Start-Sleep -Seconds 60
            Write-Host "`nKB2934018 is now installed" -ForegroundColor Green
            Write-Host " "
            $Reboot = $true
        } Else {
            Write-Host 'No Internet access detected.  ' -ForegroundColor Red -NoNewline
            Write-host 'Can not download KB2934018.  Please resolve your Internet connectivity issue (DNS?).' -ForegroundColor Yellow
        }
    }
    Write-host ' '
    Write-host ' '
    Write-host ' '
    start-sleep 2
} # End PreNET471 Function

# Function - Windows Management Framework 4.0 - Install - Needed for CU3+
Function Install-WinMgmtFW4{
    # Windows Management Framework 4.0
	$wmf = $PSVersionTable.psversion
	If ($wmf.major -eq "4") {
	    	Write-Host "`nWindows Management Framework 4.0 is already installed" -ForegroundColor Green
	} Else {
	    $Download = FileDownload "http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows8-RT-KB2799888-x64.msu"
        If ($Download) {
    	    Set-Location $DownloadFolder
	        [string]$expression = ".\Windows8-RT-KB2799888-x64.msu /quiet /norestart"
	        Write-Host "File: Windows8-RT-KB2799888-x64 installing..." -NoNewLine
	        Invoke-Expression $expression
    	    Start-Sleep -Seconds 20
		    $wmf = $PSVersionTable.psversion
	        If ($wmf.major -ge "4") {Write-Host "`b`b`b`b`b`b`b`b`b`b`b`b`binstalled!   " -ForegroundColor Green} else {Write-Host "`b`b`b`b`b`b`b`b`b`b`b`b`bFAILED!" -ForegroundColor Red}
        }
    }
} # End Install-WinMgmtFW4

# Function - Windows Management Framework 4.0 - Install - Needed for CU3+
Function Install-WinMgmtFW4{
    # Windows Management Framework 4.0
	$wmf = $PSVersionTable.psversion
	If ($wmf.major -eq "4") {
	    	Write-Host 'Windows Management Framework 4.0 is already' -NoNewLine
            Write-Host ' installed' -ForegroundColor Green
	} else {
	    	$Download = FileDownload "http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows8-RT-KB2799888-x64.msu"
            If ($Download) {
    		    Set-Location $DownloadFolder
	    	    [string]$expression = ".\Windows8-RT-KB2799888-x64.msu /quiet /norestart"
	    	    Write-Host "File: Windows8-RT-KB2799888-x64 installing..." -NoNewLine
	    	    Invoke-Expression $expression
    		    Start-Sleep -Seconds 20
		        $wmf = $PSVersionTable.psversion
	
	    	    If ($wmf.major -ge "4") {Write-Host "`b`b`b`b`b`b`b`b`b`b`b`b`binstalled!   " -ForegroundColor Green} else {Write-Host "`b`b`b`b`b`b`b`b`b`b`b`b`bFAILED!" -ForegroundColor Red}
            }
    }
} # End Install-WinMgmtFW4

# Function - Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit
Function Install-WinUniComm4 {
	$Val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
	If($val.DisplayVersion -ne "5.0.8308.0"){
		If($val.DisplayVersion -ne "5.0.8132.0"){
			If ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A41CBE7D-949C-41DD-9869-ABBD99D753DA}") -eq $False) {
				Write-Host 'Microsoft UnIfied Communications Managed API 4.0 is not installed.' -NoNewline
                Write-Host '  Downloading and installing now.' -ForegroundColor yellow
				Install-NewWinUniComm4
			} else {
    			Write-Host 'An old version of Microsoft UnIfied Communications Managed API 4.0 is ' -NoNewline
                Write-Host 'installed.' -ForegroundColor Yellow
				UnInstall-WinUniComm4
				Write-Host 'Microsoft UnIfied Communications Managed API 4.0 has been uninstalled.' -NoNewline
                Write-Host '  Downloading and installing now.'  -ForegroundColor Green
				Install-NewWinUniComm4
			}
   		} else {
   			Write-Host 'The Preview version of Microsoft UnIfied Communications Managed API 4.0 is ' -NoNewline
            Write-Host 'installed.' -ForegroundColor Yellow
   			UnInstall-WinUniComm4
   			Write-Host 'Microsoft UnIfied Communications Managed API 4.0 has been uninstalled.' -NoNewline
            Write-Host '  Downloading and installing now.' -ForegroundColor Green
   			Install-NewWinUniComm4
		}
	} else {
		Write-Host 'The correct version of Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is ' -NoNewLine
		Write-Host 'installed.' -ForegroundColor Green
	}
} # End Install-WinUniComm4

# Configure the Server for the High Performance power plan
Function HighPerformance {
	$HighPerf = powercfg -l | %{If($_.contains("High performance")) {$_.split()[3]}}
	$CurrPlan = $(powercfg -getactivescheme).split()[3]
	If ($CurrPlan -ne $HighPerf) {
		powercfg -setactive $HighPerf
		CheckPowerPlan
	} else {
		If ($CurrPlan -eq $HighPerf) {
			Write-Host 'The power plan is already set to ' -NoNewLine
            Write-Host 'High Performance.' -ForegroundColor Green
		}
	}
}

# Begin ModuleStatus Function
Function ModuleStatus {
        $module = Get-Module -name "ServerManager" -erroraction STOP

    If ($Module -eq $Null) {
        Try {
            Import-Module -Name "ServerManager" -erroraction STOP
            # return $null
        } Catch {
            Write-Host 'Server Manager module could not be loaded.' -ForegroundColor Red
        }
    } else {
        # Write-Host "Server Manager module is already imported." -ForegroundColor Cyan
        # return $null
    }
    Write-Host " "
} # End ModuleStatus Function

# Configure Net TCP Port Sharing - RunOnce
Function NetTCPPortSharing {

	$Server = (hostname)
	$NetTCP = "Set-Content \\$server config NetTcpPortSharing start= auto"
	If (Get-ItemProperty -Name "NetTCPPortSharing" -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue) { 
	    Write-host "Registry key HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\NetTCPPortSharing already exists." -ForegroundColor yellow
		Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "NetTCPPortSharing" -Value $NetTCP | Out-Null
	} else { 
	    New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "NetTCPPortSharing" -Value $NetTCP -PropertyType "String" | Out-Null
	} 

} # End configure Net TCP Port Sharing

# Turn off NIC power management
Function PowerMgmt {

	$NICs = Get-WmiObject -Class Win32_NetworkAdapter|Where-Object{$_.PNPDeviceID -notlike "ROOT\*" -and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22} 
	Foreach($NIC in $NICs) {
		$NICName = $NIC.Name
		$DeviceID = $NIC.DeviceID
		If([Int32]$DeviceID -lt 10) {
			$DeviceNumber = "000"+$DeviceID 
		} Else {
			$DeviceNumber = "00"+$DeviceID
		}
		$KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$DeviceNumber"
  
		If(Test-Path -Path $KeyPath) {
			$PnPCapabilities = (Get-ItemProperty -Path $KeyPath).PnPCapabilities
            # Check to see If the value is 24 and If not, set it to 24
            If($PnPCapabilities -ne 24){Set-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 24 | Out-Null}
            # VerIfy the value is now set to or was set to 24
			If($PnPCapabilities -eq 24) {Write-Host 'Power Management has already been ' -NoNewline;Write-Host 'disabled' -ForegroundColor Green}
   		 } 
 	 } 
 }

 # Check/Change the TCP Keep Alive Value
 Function TCPKeepAliveValue {
    
    # Get TCP Keep Alive value to process:
    Try {
        $TCPParam = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction Silentlycontinue
    } Catch {
        Write-Host 'Cannot find Registry Path ' -NoNewLine
        Write-Host 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -ForegroundColor Yellow
    }
    
    # Process the value:
    If($TCPParam.KeepAliveTime -eq $Null){
	    Write-Host 'TCP Keep Alive Value is empty -' -NoNewLine
	    Write-Host ' Test Failed' -ForegroundColor Red
    } Else {
	    $Val = $TCPParam.KeepAliveTime
	    If ((899999 -lt $Val) -and ($Val -lt 1800001)) {
		    Write-Host 'TCP Keep Alive value is ' -NoNewLine
		    Write-Host "$Val" -ForegroundColor Green -NoNewLine
		    Write-Host ' [optimal]'
	    } Else {
		    Write-Host 'TCP Keep Alive value is ' -NoNewLine
		    Write-Host "$Val" -ForegroundColor Yellow -NoNewLine
            Write-Host ' [Not optimal]'
	    }
    }
} # End of TCP Keep Alive Value Function

# Function TLS Check
Function TLSCheck {
    $ExchangeClient = $Env:ComputerName

    Write-Host "TLS 1.0" -ForegroundColor Cyan
    # TLS 1.0
    $TLS10ServerPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server"
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeServer)
    $RegKey= $Reg.OpenSubKey("$TLS10ServerPath")
    If ($Null -ne $RegKey) {
        $TLS10ServerEnableValue = $RegKey.GetValue("Enabled")
        $TLS10ServerDisabledValue = $RegKey.GetValue("DisabledByDefault")
        If ($TLS10ServerEnableValue -eq '0') {
            Write-Host 'Server Enabled: ' -NoNewLine
            Write-host 'False' -ForegroundColor Green
        } Else {
            Write-Host 'Server Enabled: ' -NoNewLine
            Write-host 'True' -ForegroundColor Red
        }
        If ($TLS10ServerDisabledValue -eq '0') {
            Write-Host 'Server Disabled by Default:' -NoNewLine
            Write-host ' False' -ForegroundColor Yellow
        } Else {
            Write-Host 'Server Disabled by Default' -NoNewLine
            Write-host ' True' -ForegroundColor Green
        }
    }  Else {
        Write-Host 'Server Enabled' -NoNewline
        Write-Host ' False' -ForegroundColor Green
    }

    # TLS 1.0
    $TLS10ClientPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client"
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeClient)
    $RegKey= $Reg.OpenSubKey("$TLS10ClientPath")
    If ($Null -ne $RegKey) {
        $TLS10ClientEnableValue = $RegKey.GetValue("Enabled")
        $TLS10ClientDisabledValue = $RegKey.GetValue("DisabledByDefault")
        If ($TLS10ClientEnableValue -eq '0') {
            Write-Host 'Client Enabled: ' -NoNewLine
            Write-host 'False' -ForegroundColor Green
        } Else {
            Write-Host 'Client Enabled: ' -NoNewLine
            Write-host 'True' -ForegroundColor Red
        }
        If ($TLS10ClientDisabledValue -eq '0') {
            Write-Host 'Client Disabled by Default:' -NoNewLine
            Write-host ' False' -ForegroundColor Yellow
        } Else {
            Write-Host 'Client Disabled by Default:' -NoNewLine
            Write-host ' True' -ForegroundColor Green
        }
    } Else {
        Write-Host 'Client Enabled ' -NoNewline
        Write-Host 'False' -ForegroundColor Green
    }

    Write-Host "TLS 1.1" -ForegroundColor Cyan
    # TLS 1.1
    $TLS11ServerPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server"
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeServer)
    $RegKey= $Reg.OpenSubKey("$TLS11ServerPath")
    If ($Null -ne $RegKey) {
        $TLS11ServerEnableValue = $RegKey.GetValue("Enabled")
        $TLS11ServerDisabledValue = $RegKey.GetValue("DisabledByDefault")
        If ($TLS11ServerEnableValue -eq '0') {
            Write-Host 'Server Enabled:' -NoNewLine
            Write-host ' False' -ForegroundColor Green
        } Else {
            Write-Host 'Server Enabled:' -NoNewLine
            Write-host ' True' -ForegroundColor Red
        }
        If ($TLS11ServerDisabledValue -eq '0') {
            Write-Host 'Server Disabled by Default:' -NoNewLine
            Write-host ' False' -ForegroundColor Yellow
        } Else {
            Write-Host 'Server Disabled by Default:' -NoNewLine
            Write-host ' True' -ForegroundColor Green
        }
    } Else {
        Write-Host 'Server Enabled:' -NoNewline
        Write-Host ' False' -ForegroundColor Green
    }
    # TLS 1.1
    $TLS11ClientPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client"
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeClient)
    $RegKey= $Reg.OpenSubKey("$TLS11ClientPath")
    If ($Null -ne $RegKey) {
        $TLS11ClientEnableValue = $RegKey.GetValue("Enabled")
        $TLS11ClientDisabledValue = $RegKey.GetValue("DisabledByDefault")
        If ($TLS11ClientEnableValue -eq '0') {
            Write-Host 'Client Enabled:' -NoNewLine
            Write-host ' False' -ForegroundColor Green
        } Else {
            Write-Host 'Client Enabled:' -NoNewLine
            Write-host ' True' -ForegroundColor Red
        }
        If ($TLS11ClientDisabledValue -eq '0') {
            Write-Host 'Client Disabled by Default:' -NoNewLine
            Write-host ' False' -ForegroundColor Yellow
        } Else {
            Write-Host 'Client Disabled by Default:' -NoNewLine
            Write-host ' True' -ForegroundColor Green
        }
    } Else {
        Write-Host 'Client Enabled:' -NoNewline
        Write-Host ' False' -ForegroundColor Green
    }

Write-Host "TLS 1.2" -ForegroundColor Cyan
    # TLS 1.2
    $TLS12ServerPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server"
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeServer)
    $RegKey= $Reg.OpenSubKey("$TLS12ServerPath")
    If ($Null -ne $RegKey) {
        $TLS12ServerEnableValue = $RegKey.GetValue("Enabled")
        $TLS12ServerDisabledValue = $RegKey.GetValue("DisabledByDefault")
        If ($TLS12ServerEnableValue -eq '0') {
            Write-Host 'Server Enabled:' -NoNewLine
            Write-host ' False' -ForegroundColor Red
        } Else {
            Write-Host 'Server Enabled:' -NoNewLine
            Write-host ' True' -ForegroundColor Green
        }
        If ($TLS12ServerDisabledValue -eq '0') {
            Write-Host 'Server Disabled by Default:' -NoNewLine
            Write-host ' False' -ForegroundColor Green
        } Else {
            Write-Host 'Server Disabled by Default:' -NoNewLine
            Write-host ' True' -ForegroundColor Red
        }
    } Else {
        Write-Host 'Server Enabled:' -NoNewline
        Write-Host ' False' -ForegroundColor Yellow
    }
    # TLS 1.2
    $TLS12ClientPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client"
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeClient)
    $RegKey= $Reg.OpenSubKey("$TLS12ClientPath")
    If ($Null -ne $RegKey) {
        $TLS12ClientEnableValue = $RegKey.GetValue("Enabled")
        $TLS12ClientDisabledValue = $RegKey.GetValue("DisabledByDefault")
        If ($TLS12ClientEnableValue -eq '0') {
            Write-Host 'Client Enabled:' -NoNewLine
            Write-host ' True' -ForegroundColor Red
        } Else {
            Write-Host 'Client Enabled:' -NoNewLine
            Write-host ' False' -ForegroundColor Green
        }
        If ($TLS12ClientDisabledValue -eq '0') {
            Write-Host 'Client Disabled by Default:' -NoNewLine
            Write-host ' False' -ForegroundColor Green
        } Else {
            Write-Host 'Client Disabled by Default:' -NoNewLine
            Write-host ' True' -ForegroundColor Red
        }
    } Else {
        Write-Host 'Client Enabled:' -NoNewline
        Write-Host ' False' -ForegroundColor Green
    }
} # End of TLScheck function

# Uninstall Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit
Function UnInstall-WinUniComm4{
	$Download = FileDownload "http://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe"
    If ($Download) {
 	    Set-Location $DownloadFolder
  	    [string]$expression = ".\UcmaRuntimeSetup.exe /quiet /norestart /l* $downloadfolder\WinUniComm4.log"
  	    Write-Host "File: UcmaRuntimeSetup.exe uninstalling..." -NoNewLine
   	    Invoke-Expression $expression
  	    Start-Sleep -Seconds 20
	    If ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}") -eq $False){
		    Write-Host "Microsoft UnIfied Communications Managed API 4.0, Core Runtime 64-bit is " -NoNewLine 
		    Write-Host "been uninstalled!" -ForegroundColor red
	    }
    }
} # End Uninstall-WinUniComm4

######################################################
#    This section is for the Windows 2012 (R2) OS    #
######################################################`

Function Code2012 {

    # Start code block for Windows 2012 or 2012 R2
    $Menu2012 = {
	    Write-Host "	******************************************************************" -ForegroundColor White
	    Write-Host "	Exchange Server 2013 [On Windows 2012 / 2012 R2] - Features script" -ForegroundColor Green
	    Write-Host "	******************************************************************" -ForegroundColor White
	    Write-Host "	"
	    Write-Host "	Please select an option from the list below." -ForegroundColor yellow
        Write-Host "	 ** .NET UPDATE - Default is .NET 4.8.0" -ForegroundColor Red
        Write-Host "	"
        Write-Host "	Client Access Server (CAS) Role Requirements" -ForegroundColor Cyan
        Write-Host "	--------------------------------------------" -ForegroundColor Cyan
        Write-Host "	1) Install Client Access Server prerequisites - Step 1 [Includes 30 & 31] " -ForegroundColor White
	    Write-Host "	2) Install Client Access Server prerequisites - Step 2" -ForegroundColor White
        Write-Host "	"
        Write-Host "	Mailbox and Client Access Server (CAS) Role Requirements" -ForegroundColor Cyan
        Write-Host "	--------------------------------------------------------" -ForegroundColor Cyan
	    Write-Host "	3) Install Mailbox and or CAS/Mailbox prerequisites - Step 1 [Includes 30 & 31]" -ForegroundColor White
	    Write-Host "	4) Install Mailbox and or CAS/Mailbox prerequisites - Step 2" -ForegroundColor White
        Write-Host "	"
        Write-Host "	Edge Transport Role Requirements" -ForegroundColor Cyan
        Write-Host "	--------------------------------" -ForegroundColor Cyan
	    Write-Host "	5) Install Edge Transport Server prerequisites - Step 1" -ForegroundColor White
	    Write-Host "	6) Install Edge Transport Server prerequisites - Step 2" -ForegroundColor White
        Write-Host "	"
        Write-Host "	Prerequisite Checks" -ForegroundColor Cyan
        Write-Host "	------------------" -ForegroundColor Cyan
	    Write-Host "	10) Launch Windows Update" -ForegroundColor White
	    Write-Host "	11) Check Prerequisites for CAS role" -ForegroundColor White
	    Write-Host "	12) Check Prerequisites for Mailbox role or Cas/Mailbox roles" -ForegroundColor White
	    Write-Host "	13) Check Prerequisites for Edge role" -ForegroundColor White
        Write-Host "	14) Additional Checks" -ForegroundColor White
        Write-Host "	"
        Write-Host "	One-Off Installations" -ForegroundColor Cyan
        Write-Host "	---------------------" -ForegroundColor Cyan
	    Write-Host "	20) Install - One Off - CAS role - Windows Components" -ForegroundColor White
	    Write-Host "	21) Install - One Off - Mailbox (or CAS/Mailbox) Role - Windows Components" -ForegroundColor White
	    Write-Host "	22) Install - One Off - UnIfied Communications Managed API 4.0" -ForegroundColor White
	    Write-Host "	23) Install - One Off - .NET Prerequistes (4.8)" -ForegroundColor White
	    Write-Host "	24) Install - One Off - .NET 4.8" -ForegroundColor White
	    Write-Host "	25) Install - One Off - Visual C++ 2012" -ForegroundColor White
	    Write-Host "	26) Install - One Off - Visual C++ 2013" -ForegroundColor White
        Write-Host "	"
        Write-Host "	Additional Configurations" -ForegroundColor Cyan
        Write-Host "	-------------------------" -ForegroundColor Cyan
	    Write-Host "	30) Set Power Plan to High Performance" -ForegroundColor White
	    Write-Host "	31) Disable Power Management for NICs" -ForegroundColor White
	    Write-Host "	32) Disable SSL 3.0 Support" -ForegroundColor White
	    Write-Host "	33) Disable RC4 Support" -ForegroundColor White
        Write-Host "	34) Configure Event Logs (App, Sys, Sec) to 100MB" -ForegroundColor White
        Write-Host "	35) Configure PageFile to RAM + 10 MB" -ForegroundColor Green
        Write-Host "		"
	    Write-Host "	98) Restart the Server" -ForegroundColor red
	    Write-Host "	99) Exit" -ForegroundColor Cyan
        Write-Host "	"
        Write-Host "	Select an option.. [1-99]? " -ForegroundColor White -NoNewLine
    }

################################
#        2012 Functions        #
################################

# Add a firewall rule for CAS role - Port 
Function Add-FirewallRule {
   param( 
      $name,
      $tcpPorts,
      $appName = $null,
      $serviceName = $null
   )
    $fw = New-Object -ComObject hnetcfg.fwpolicy2 
    $rule = New-Object -ComObject HNetCfg.FWRule
        
    $rule.Name = $name
    If ($appName -ne $null) { $rule.ApplicationName = $appName }
    If ($serviceName -ne $null) { $rule.serviceName = $serviceName }
    $rule.Protocol = 6 #NET_FW_IP_PROTOCOL_TCP
    $rule.LocalPorts = $tcpPorts
    $rule.Enabled = $true
    $rule.Grouping = "@firewallapi.dll,-23255"
    $rule.Profiles = 7 # all
    $rule.Action = 1 # NET_FW_ACTION_ALLOW
    $rule.EdgeTraversal = $False
    
    $fw.Rules.Add($rule)
}

################################
#     2012 Menu Backend        #
################################

    Do { 	
	    If ($Reboot -eq $true){Write-Host "REBOOT REQUIRED!" -backgroundcolor red -ForegroundColor black;Write-Host "DO NOT INSTALL EXCHANGE BEFORE REBOOTING!" -backgroundcolor red -ForegroundColor black}
	    If ($Choice -ne "None") {Write-Host "Last command: "$Choice -ForegroundColor Yellow}	
        invoke-command -scriptblock $Menu2012
	    $Choice = Read-Host

        Switch ($Choice)    {

            # -- 4.8.0 --

            1 {# 	Prep CAS - Step 1
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host '-------------------------------------------' 
                Write-Host 'Install Prerequisites for CAS Role - Part 1' -ForegroundColor Magenta
                Write-Host '-------------------------------------------'
                Write-Host ' '
                ModuleStatus
			    NetTCPPortSharing
			    HighPerformance
			    PowerMgmt
			    Add-WindowsFeature AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation        
			    Add-FirewallRule "Exchange Server 2013 - CAS" "139" $null $null
                Install-PreDotNet
			    $RebootRequired = $true
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
		    }
		    2 {#	Prep CAS - Step 2
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host '-------------------------------------------' 
                Write-Host 'Install Prerequisites for CAS Role - Part 2' -ForegroundColor Magenta
                Write-Host '-------------------------------------------'
                Write-Host ' '
                ModuleStatus
			    Install-NET48
                Install-WinUniComm4
                Install-WinMgmtFW4
                CPlusPlus
                ConfigureTCPKeepAlive
			    $RebootRequired = $true
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
		    }
		    3 {# 	Prep Mailbox or CAS/Mailbox - Step 1
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host '----------------------------------------------------' 
                Write-Host 'Install Prerequisites for CAS/Mailbox Roles - Part 1' -ForegroundColor Magenta
                Write-Host '----------------------------------------------------'
                Write-Host ' '
                ModuleStatus
			    NetTCPPortSharing
			    HighPerformance
			    PowerMgmt
			    Add-WindowsFeature AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
                Install-PreDotNet
			    $RebootRequired = $true
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
		    }
		    4 {#	Prep Mailbox or CAS/Mailbox - Step 2
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host '----------------------------------------------------' 
                Write-Host 'Install Prerequisites for CAS/Mailbox Roles - Part 2' -ForegroundColor Magenta
                Write-Host '----------------------------------------------------'
                Write-Host ' '
                ModuleStatus
                Install-NET48
                Install-WinUniComm4
                Install-WinMgmtFW4
                CPlusPlus
                ConfigureTCPKeepAlive
                Write-host '';Write-host '';Write-host ''
			    $RebootRequired = $true
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
		    }
	  	    5 {#	Prep Exchange Transport - Part 1
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host '------------------------------------------------------' 
                Write-Host 'Install Prerequisites for Edge Transport Role - Part 1' -ForegroundColor Magenta
                Write-Host '------------------------------------------------------'
                Write-Host ' '
			    Install-windowsfeature ADLDS
			    Install-WinMgmtFW4
                CPlusPlus2012
                Install-PreDotNet
                Write-host '';Write-host '';Write-host ''
                $RebootRequired = $true
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
		    }
            6 {#	Prep Exchange Transport - Part 2
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host '------------------------------------------------------' 
                Write-Host 'Install Prerequisites for Edge Transport Role - Part 2' -ForegroundColor Magenta
                Write-Host '------------------------------------------------------'
                Write-Host ' '
                Install-NET48
                ConfigureTCPKeepAlive
			    $RebootRequired = $true
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
                Write-Host ' '
            }
		
             # -- Misc 1 --

	  	    10 {#	Windows Update
			    Invoke-Expression "$env:windir\system32\wuapp.exe startmenu"
		    }
		    11 {# 	CAS Requirement Check
			    CheckCASPrerequisites
		    }
		    12 {#	Mailbox or CAS/Mailbox Requirement Check
			    CheckCASMailboxPrerequisites
		    }
		    13 {#	Edge Transport Requirement Check
			    CheckEdgeTransportPrerequisites
		    }
            14 { # Check - TLS, Hyperthreading, SSL and more
                AdditionalChecks
            }

            # -- One Off Changes --

		    20 {#	Step 1 - One Off - Windows Components - CAS
			    Get-ModuleStatus -name ServerManager
			    Add-WindowsFeature AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
		    }
		    21 {#	Step 1 - One Off - Windows Components - Mailbox or CAs/Mailbox
			    Get-ModuleStatus -name ServerManager
			    Add-WindowsFeature AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
		    }
		    22 {#	Install - One Off - UnIfied Communications Managed API 4.0
			    Install-WinUniComm4
		    }
            23 { # Install prereqs for .NET 4.8
                Install-PreDotNet
                $RebootRequired = $true
            }
		    24 {#	Install - One Off - .NET 4.8
			    Install-NET48
                $RebootRequired = $true
		    }
            25 {#	Install - One Off - Microsoft C++ 2012
                CPlusPlus2012
            }
            26 {#	Install - One Off - Microsoft C++ 2013
                CPlusPlus2013
            }

            # -- New Feautures --

		    30 { # Set power plan to High Performance as per Microsoft
			    HighPerformance
		    }
		    31 { # Disable Power Management for NICs.		
			    PowerMgmt
		    }
		    32 { # Disable SSL 3.0 Support
			    DisableSSL3
		    }
		    33 { # Disable RC4 Support		
			    DisableRC4
		    }
		    34 { # Change Event Log sizes
                EventLogLimits 
            }
            35 {#   Configure the pagefile to be RAM + 10 and not system managed
                ConfigurePageFile
            }
		    98 {#	Exit and restart
			    # Stop-Transcript
			    Restart-Computer -ComputerName LocalHost -Force
		    }
		    99 {#	Exit
			    If (($WasInstalled -eq $False) -and (Get-Module BitsTransfer)){
				    Write-Host "BitsTransfer: Removing..." -NoNewLine
				    Remove-Module BitsTransfer
				    Write-Host "`b`b`b`b`b`b`b`b`b`b`bremoved!   " -ForegroundColor Green
			    }
			    popd
			    Write-Host "Exiting..."
			    # Stop-Transcript
		    }
		    default {Write-Host "You haven't selected any of the available options. "}
	    }
    } while ($Choice -ne 99)
}

######################################################
#               MAIN SCRIPT BODY                     #
######################################################

# Check for Windows 2012 or Windows 2012 R2
If (($ver -match '6.2') -or ($ver -match '6.3')) {
    $OSCheck = $true
    Code2012
}

# If Windows 2012 or 2012 R2 are found, exit with error
If ($OSCheck -ne $true) {
    Write-Host " "
    Write-Host "The server is not running Windows 2012 or 2012 R2.  Exiting the script."  -ForegroundColor Red
    Write-Host " "
    Exit
}
