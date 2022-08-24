####################################################################################################################################################################
#  SCRIPT DETAILS                                                                                                                                                  #
#    Installs all required prerequisites for Exchange Server 2019 for Windows Server 2019 components                                                               #
#        downloading latest Update Roll-up, etc.                                                                                                                   #
#																																								   #
# SCRIPT VERSION HISTORY																																		   #
#    Current Version	: 1.17                                                                                                                                     #										
#    Change Log	        : 1.17 - Added support for Windows Server 2022 and added IIS URL Rewrite module installation check                                         #
#                       : 1.16 - Added checks for IIS rewrite and Universal C, code cleanup and added more commenting in the code.                                 #
#                       : 1.15 - Added IIS URL Rewrite and Universal C Runtime in Windows (KB2999226)                                                              #
#                       : 1.14 - Better TLS checks, remove TLS 1.0/1.1, make TLS 1.2 default, SMBv1 removal, RSS enabled, Pagefile Fix                             #
#                       : 1.13 - Minor syntax fixes                                                                                                                #
#                       : 1.12 - Changed to .NET 4.8 only. Removed .NET 4.7.x.                                                                                     #
#                       : 1.11 - Added Windows Defender options - Add, Clear and Report, fixed UCMA Core process waiting, re-arranged menu                         #
#                       : 1.10 - Added .NET 4.8 as an Option (Will be default by the Fall of 2019) - CU2+, TCP Keep Alive Value, functions are alphabetized        #
#                                Additional Checks function fix, fixed anomalies in various checks and functions                                                   #
#                       : 1.09 - Changed Internet Check to alleviate issues found, Correct C++ 2012/2013 code, enhanced .NET check, pulled Windows Defender        #
#                       : 1.08 - Fixed Windows defender option and published to Gallery                                                                            #
#                       : 1.07 - Added new Pagefile (25%) change as well as RAM size check                                                                         #
#                       : 1.06 - Bug fixes                                                                                                                         #
#                       : 1.05 - RTM Support - split menu for Core/Full OS, Change requirements to install due to MS changes                                       #
#                       : 1.04 - Fixed Windows Features, checks and event log resizing verification                                                                #
#                       : 1.03 - Adding role prerequisite checks for Full/Core OS and Mailbox/Edge Transport Roles                                                 #
#                       : 1.02 - Adding Core Role Installation and Event log changes                                                                               #
#                       : 1.01 - More testing for Exchange 2019 Preview                                                                                            #																									   #
#				        : 1.00 - First iteration (TAP)                                                                                                             #
#                                                                                                                                                                  #
# DATE RELEASED         : 11/20/2018 (08/02/2022 - Last Update)  	 																                               #
#																																								   #
# OTHER SCRIPT INFORMATION																																		   #
#    Wish list			:               																														   #
#    Rights Required	: Local admin on server																												       #
#    Exchange Version	: 2019																																	   #
#    Author       		: Damian Scoles 																											  			   #
#    My Blog			: www.PowerShellGeek.com and www.PracticalPowerShell.com                                                                                   #
#    Disclaimer   		: You are on your own.  This was not written by, supported by, or endorsed by Microsoft.												   #
#																																								   #
# EXECUTION																																						   #
#  .\Set-Exchange2019Prerequisites-1.17.ps1																														   #
#																																								   #
####################################################################################################################################################################


#####################################################################################
#   Global Variable Definitions                                                     #

$Ver = (Get-WMIObject win32_OperatingSystem).Version
$OSCheck = $false
$Choice = "None"
$Date = get-date -Format "MM.dd.yyyy-hh.mm-tt"
$DownloadFolder = "c:\install"
$CurrentPath = (Get-Item -Path ".\" -Verbose).FullName
$Reboot = $false
$Error.clear()
Start-Transcript -path "$CurrenPath\$date-Set-Prerequisites.txt" | Out-Null
Clear-Host
# Pushd

# Core OS Check
$RegKey = "hklm:/software/microsoft/windows nt/currentversion"
$Core = (Get-ItemProperty $regKey).InstallationType -eq "Server Core"

#                                                                                   #
#####################################################################################


#####################################################################################
#         Global Functions - Windows Server 2019 / 2022                             #

# Function Additional Checks
Function AdditionalChecks { 
    CLS
    Write-Host '------------------------------------------------' -ForegroundColor White
    Write-Host ' Checking additional settings for Exchange 2019' -ForegroundColor Magenta
    Write-Host '------------------------------------------------' -ForegroundColor White
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
		
        $ExchangeRAM = $RAMinMb * 0.25


    } Catch {
        Write-Host "Cannot acquire the amount of RAM in the server." -ForegroundColor Red
	    $WMIQuery = $True
    }
    
    # Get RAM and set ideal PageFileSize - WMI Method
    If ($WMIQuery) {
	    Try {
		    $RamInMb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1MB
            $RamInGb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
		    $ExchangeRAM = $RAMinMb * 0.25
		} Catch {
		    Write-Host "Cannot acquire the amount of RAM in the server with CIM or WMI queries." -ForegroundColor Red
		$Stop = $True
	    }
    }

    # Max RAM Check
    $LowRAM = $True
    If ($RamInGb -gt 256) {
        Write-Host 'Server RAM check - 128 to 256 Gb - ' -NoNewline
        Write-Host 'Failed' -ForegroundColor Red -NoNewline
        Write-Host ' - [Not Optimal] - over 128 GB' -ForegroundColor Yellow
        $LowRAM = $False
    }
    If ($LowRAM) {
        If ($RaminGb -gt 128) {
            Write-Host 'Server RAM check - 128 to 256 Gb - ' -NoNewline
            Write-Host 'Passed' -ForegroundColor Green -NoNewline
            Write-Host ' - [Optimal] - 128 to 256 Gb RAM'
        } Else {
            Write-Host 'Server RAM check - 128 to 256 Gb - ' -NoNewline
            Write-Host 'Failed' -ForegroundColor red -NoNewline
            Write-Host ' - [Not Optimal] - Under 128 GB' -ForegroundColor Yellow
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
            Write-Host 'Pagefile is configured [25% of RAM] - ' -NoNewline
            Write-Host ' Passed' -ForegroundColor Green
        } Else {
            $RAMDifference = $ExchangeRAM - $MaximumSize
            If ($RAMDifference -gt 0) {
                Write-Host 'Pagefile is configured [25% of RAM] - ' -NoNewline
                Write-Host 'Failed' -ForegroundColor Red -NoNewline
                Write-Host ' --> Pagefile is too SMALL' -ForegroundColor Yellow
                Write-host "   Server RAM - $RamInMb MB" -ForegroundColor White
                Write-Host "   Ideal Pagefile size - $ExchangeRAM MB" -ForegroundColor White
                Write-host "   Maximum PageFile Size - $MaximumSize MB" -ForegroundColor White
                Write-host "   Initial PageFile Size - $InitialSize MB" -ForegroundColor White
            } 
            If ($RAMDifference -lt 0) {
                Write-Host 'Pagefile is configured [25% of RAM] - ' -NoNewline
                Write-Host 'Failed' -ForegroundColor Red -NoNewline
                Write-Host ' --> Pagefile is too BIG' -ForegroundColor Yellow
                Write-host "   Server RAM - $RamInMb MB" -ForegroundColor White
                Write-Host "   Ideal Pagefile size - $ExchangeRAM MB" -ForegroundColor White
                Write-host "   Maximum PageFile Size - $MaximumSize MB" -ForegroundColor White
                Write-host "   Initial PageFile Size - $InitialSize MB" -ForegroundColor White
            }
        }
    } Else {
        Write-Host 'Pagefile is configured [25% of RAM] - ' -NoNewline
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

    # SSL 3.0 Disabled (Windows 2019/2022 version)
    $SSL30RegistryPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    $Name = "Enabled"
    $RegistryPath = $True
    Try {
        $RegistryPath = Get-ItemProperty -Path $SSL30RegistryPath -Name $name -ErrorAction STOP
    } Catch {
        $RegistryPath = $False
    }
    If ($RegistryPath) {
        If( $SSL30RegistryPath.Enabled -eq '0') {
            Write-Host 'SSL 3.0 is Disabled - ' -NoNewLine 
            Write-Host 'Passed' -ForegroundColor Green
        } Else {
            Write-Host 'SSL 3.0 is Enabled - ' -NoNewline
            Write-Host 'Failed' -ForegroundColor Red
        }
    } Else {
        Write-Host 'SSL 3.0 is not Disabled - ' -NoNewline
        Write-Host 'Failed' -ForegroundColor Red
    }

    # TLS Version Support
    TLSCheck

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
            Write-Host 'Failed' -ForegroundColor Red
        }
    } Else {
        Write-Host 'MAPI Enabled - ' -NoNewline
        Write-Host 'Unknown' -ForegroundColor Yellow
    }

    # RSS
    $RSSAdapterNames = (Get-NetAdapterRss).Name
    $RSSCount = $RSSAdapterNames.Count
    $GoodRssAdapaters = 0
    Foreach ($RSSAdapterName in $RSSAdapterNames) {
        $RSS = (Get-NetAdapterRss -Name $RSSAdapterName).Enabled
        IF ($RSS) {
            $GoodRssAdapaters++
        }
    }
    Write-Host "$GoodRssAdapaters of $RSSCount Network Adapters have RSS Enabled - " -NoNewLine
    If ($GoodRssAdapaters -eq $RSSCount) {
        Write-Host "Passed" -ForegroundColor Green
    } Else {
        Write-Host "Fail" -ForegroundColor Red
    }

    # SMBv1
    
    If ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
        Write-host 'SMBv1 is Enabled and Installed - ' -NoNewLine
        Write-Host 'Failed' -ForegroundColor Red
    } Else {
        If((Get-WindowsFeature FS-SMB1).Installed) {
            Write-Host 'SMBv1 is disabled, but installed - ' -NoNewLine
            Write-Host 'Warning' -ForegroundColor Yellow
        } Else {
            Write-host 'SMBv1 is not enabled or installed' -NoNewLine
            Write-host ' - Passed' -ForegroundColor Green
        }
    } 

    # Formatting
    Write-host ' '
    Write-host ' '
} # End of Additional Checks Function

# Windows Defender Exclusions - Adding
Function AddWindowsDefenderExclusions {
    CLS

    #################################################################
    # Variables                                                     #

    $PSSnapinLoad = $True
    Try {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction STOP
    } Catch {
        Write-Host 'Cannot load Exchange Powershell module'
        $PSSnapinLoad = $False
    }

    #                                                               #
    #################################################################


    #################################################################
    # Variables                                                     #

    $Server = $env:COMPUTERNAME
    $ExchangeProductVersion = (GCM exsetup |%{$_.Fileversioninfo}).ProductVersion
    If ($ExchangeProductVersion -like '15.02.*') {$Version = '2019'}
    If ($ExchangeProductVersion -like '15.01.*') {$Version = '2016'}
    If ($ExchangeProductVersion -like '15.00.*') {$Version = '2013'}
    If ($ExchangeProductVersion -lt '15') {$Exit = $True}
    $ServerRole = (Get-ExchangeServer $Server).ServerRole
    $ExInstall = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath

    #                                                               #
    #################################################################

    Write-Host '--------------------------------------------------------------'
    Write-Host " Adding Windows Defender Exclusions for Exchange Server $Version" -ForegroundColor Magenta
    Write-Host '--------------------------------------------------------------'
    Write-Host ' '


    #################################################################
    # Script Body                                                   #

    If ($PSSnapinLoad) {
        If (($ServerRole -eq 'Mailbox') -And ($Version -eq '2016')) {
            # Mailbox Only and 2016
            Write-Host 'Adding Exchange 2016 Mailbox Role only exclusions....' -ForegroundColor Yellow
            Add-MpPreference -ExclusionPath "$($Exinstall)UnifiedMessaging\Grammars","$($Exinstall)UnifiedMessaging\Prompts","$($Exinstall)UnifiedMessaging\Voicemail"
            Add-MpPreference -ExclusionProcess "$($Exinstall)FrontEnd\CallRouter\Microsoft.Exchange.UM.CallRouter.exe","$($Exinstall)Bin\UmService.exe","$($Exinstall)Bin\UmWorkerProcess.exe"
            Add-MpPreference -ExclusionExtension .cfg,.grxml
        }

        If ($ServerRole -eq 'Mailbox') {

            # Mailbox Only (No Edge)
            Write-Host 'Adding Mailbox Role only exclusions....' -ForegroundColor Yellow
            Add-MpPreference -ExclusionPath "$($env:SystemRoot)\Cluster","$($Exinstall)ClientAccess\OAB","$($Exinstall)FIP-FS","$($Exinstall)GroupMetrics","$($Exinstall)Logging,$($Exinstall)Mailbox"
            Add-MpPreference -ExclusionProcess "$env:SystemDrive\inetpub\temp\IIS Temporary Compressed Files","$($env:SystemRoot)\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files","$($env:SystemRoot)\System32\Inetsrv"
            $OICEPath = (resolve-path c:\windows\temp\o*).Path
            If ($Null -ne $OICEPath) {Add-MpPreference -ExclusionPath $OICEPath}
            Add-MpPreference -ExclusionProcess "$($Exinstall)Bin\ComplianceAuditService.exe","$($Exinstall)FIP-FS\Bin\fms.exe","$($Exinstall)Bin\Search\Ceres\HostController\hostcontrollerservice.exe","$Env:SystemRoot\System32\inetsrv\inetinfo.exe","$($Exinstall)Bin\Microsoft.Exchange.AntispamUpdateSvc.exe","$($Exinstall)TransportRoles\agents\Hygiene\Microsoft.Exchange.ContentFilter.Wrapper.exe","$($Exinstall)Bin\Microsoft.Exchange.Diagnostics.Service.exe","$($Exinstall)Bin\Microsoft.Exchange.Directory.TopologyService.exe","$($Exinstall)Bin\Microsoft.Exchange.EdgeCredentialSvc.exe","$($Exinstall)Bin\Microsoft.Exchange.EdgeSyncSvc.exe","$($Exinstall)FrontEnd\PopImap\Microsoft.Exchange.Imap4.exe","$($Exinstall)ClientAccess\PopImap\Microsoft.Exchange.Imap4service.exe","$($Exinstall)Bin\Microsoft.Exchange.Notifications.Broker.exe","$($Exinstall)FrontEnd\PopImap\Microsoft.Exchange.Pop3.exe","$($Exinstall)ClientAccess\PopImap\Microsoft.Exchange.Pop3service.exe","$($Exinstall)Bin\Microsoft.Exchange.ProtectedServiceHost.exe","$($Exinstall)Bin\Microsoft.Exchange.RPCClientAccess.Service.exe","$($Exinstall)Bin\Microsoft.Exchange.Search.Service.exe","$($Exinstall)Bin\Microsoft.Exchange.Servicehost.exe","$($Exinstall)Bin\Microsoft.Exchange.Store.Service.exe","$($Exinstall)Bin\Microsoft.Exchange.Store.Worker.exe"
            Add-MpPreference -ExclusionProcess "$($Exinstall)Bin\MSExchangeCompliance.exe","$($Exinstall)Bin\MSExchangeDagMgmt.exe","$($Exinstall)Bin\MSExchangeDelivery.exe","$($Exinstall)Bin\MSExchangeFrontendTransport.exe","$($Exinstall)Bin\MSExchangeHMHost.exe","$($Exinstall)Bin\MSExchangeHMWorker.exe","$($Exinstall)Bin\MSExchangeMailboxAssistants.exe"
            Add-MpPreference -ExclusionProcess "$($Exinstall)Bin\MSExchangeMailboxReplication.exe","$($Exinstall)Bin\MSExchangeRepl.exe","$($Exinstall)Bin\MSExchangeSubmission.exe","$($Exinstall)Bin\MSExchangeTransport.exe","$($Exinstall)Bin\MSExchangeTransportLogSearch.exe","$($Exinstall)Bin\MSExchangeThrottling.exe","$($Exinstall)Bin\Search\Ceres\Runtime\1.0\Noderunner.exe","$($Exinstall)Bin\OleConverter.exe","$($Exinstall)Bin\Search\Ceres\ParserServer\ParserServer.exe","C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe","$($Exinstall)FIP-FS\Bin\ScanEngineTest.exe"
            Add-MpPreference -ExclusionProcess "$($Exinstall)FIP-FS\Bin\ScanningProcess.exe","$($Exinstall)FIP-FS\Bin\UpdateService.exe","$Env:SystemRoot\System32\inetsrv\W3wp.exe"
            Add-MpPreference -ExclusionProcess "$($Exinstall)Bin\wsbexchange.exe"
            Add-MpPreference -ExclusionExtension.dsc,.txt,.lzx
    
            # Pop and IMAP Exclusions
            Write-Host 'Adding POP3 and IMAP4 exclusions....' -ForegroundColor Yellow
            $PopLogPath = (Get-PopSettings).LogFileLocation
            Add-MpPreference -ExclusionPath $PopLogPath
            $IMAPLogPath = (Get-ImapSettings).LogFileLocation
            Add-MpPreference -ExclusionPath $IMAPLogPath

            # MBX Only
            Write-Host 'Adding Mailbox database exclusions....' -ForegroundColor Yellow
            $MailboxDatabases = @(Get-MailboxDatabase -Server $server | Sort Name | Select EdbFilePath,LogFolderPath)
            $MbxEdbPaths = $MailboxDatabases.EdbFilePath.PathName
            Foreach ($MbxEdbPath in $MbxEdbPaths) {Add-MpPreference -ExclusionPath $MbxEdbPath}
            $MbxDbLogPaths = $MailboxDatabases.LogFolderPath.PathName
            Foreach ($MbxDbLogPath in $MbxDbLogPaths) {Add-MpPreference -ExclusionPath $MbxDbLogPath}

            # Front End Logs
            Write-Host 'Adding FrontEnd Transport Log exclusions....' -ForegroundColor Yellow
            $FrontEndLogs = @(Get-FrontEndTransportService $server | Select *logpath*)
            $FrontEndPaths = @($FrontEndLogs | Get-Member | Where {$_.membertype -eq "NoteProperty"})
            Foreach ($FrontEndPath in $FrontEndPaths) {Try {Add-MpPreference -ExclusionPath $FrontEndLogs.($FrontEndPath.Name).PathName -ErrorAction STOP} Catch {Write-Verbose 'Empty file path, nothing to exclude.'}}

            # EXAMPLE
            # Foreach ($FrontEndPath in $FrontEndPaths) {Try {Add-MpPreference -ExclusionPath $FrontEndLogs.($FrontEndPath.Name).PathName -ErrorAction STOP} Catch {Write-host 'bad data to exclude'}}
            # END EXAMPLE

            # Transport Server Logs
            Write-Host 'Adding Transport Log exclusions....' -ForegroundColor Yellow
            $TransportLogs = @(Get-MailboxTransportService $server | Select *logpath*)
            $TransportLogPaths = @($TransportLogs | Get-Member | Where {$_.MemberType -eq "NoteProperty"})
            Foreach ($TransportLogPath in $TransportLogPaths) {Try {Add-MpPreference -ExclusionPath $TransportLogs.($TransportLogPath.Name).PathName -ErrorAction STOP} Catch {Write-Verbose 'Empty file path, nothing to exclude.'}}

            # Transport Service Log Files
            Write-Host 'Adding Transport Service Log exclusions....' -ForegroundColor Yellow
            $TransportServiceLogs = Get-TransportService $server | Select ConnectivityLogPath,MessageTrackingLogPath,IrmLogPath,ActiveUserStatisticsLogPath,ServerStatisticsLogPath,ReceiveProtocolLogPath,RoutingTableLogPath,SendProtocolLogPath,QueueLogPath,WlmLogPath,AgentLogPath,FlowControlLogPath,ProcessingSchedulerLogPath,ResourceLogPath,DnsLogPath,JournalLogPath,TransportMaintenanceLogPath,PipelineTracingPath,PickupDirectoryPath,ReplayDirectoryPath,RootDropDirectoryPath
            $TransportServiceLogPaths = @($TransportServiceLogs | Get-Member | Where {$_.membertype -eq "NoteProperty"})
            Foreach ($TransportServiceLogPath in $TransportServiceLogPaths) {Try {Add-MpPreference -ExclusionPath $TransportServiceLogs.($TransportServiceLogPath.Name).PathName -ErrorAction STOP} Catch {Write-Verbose 'Empty file path, nothing to exclude.'}}

            # Mailbox Server Log Paths
            Write-Host 'Adding Mailbox Server Log exclusions....' -ForegroundColor Yellow
            $MailboxServerLogs = Get-MailboxServer $server | Select DataPath,CalendarRepairLogPath,LogPathForManagedFolders,MigrationLogFilePath,TransportSyncLogFilePath,TransportSyncMailboxHealthLogFilePath
            $MailboxServerLogPaths = @($MailboxServerLogs | Get-Member | Where {$_.membertype -eq "NoteProperty"})
            Foreach ($MailboxServerLogPath in $MailboxServerLogPaths) {Try {Add-MpPreference -ExclusionPath $MailboxServerLogs.($TransportServiceLogPath.Name).PathName -ErrorAction STOP} Catch {Write-Verbose 'Empty file path, nothing to exclude.'}}

        } Else {

            # Edge Transport Only
            Write-Host 'Adding Edge Server only exclusions....' -ForegroundColor Yellow
            Add-MpPreference -ExclusionPath "$($Exinstall)TransportRoles\Data\Adam","$($Exinstall)TransportRoles\Data\IpFilter"
            Add-MpPreference -ExclusionProcess "$($Exinstall)Bin\EdgeTransport.exe","$Env:SystemRoot\System32\Dsamain.exe"

        }

        # Both Roles
        Write-Host 'Adding exclusions for any Exchange server role.... ' -ForegroundColor Yellow
        Add-MpPreference -ExclusionPath "$($Exinstall)TransportRoles\Data\Queue","$($Exinstall)TransportRoles\Data\SenderReputation","$($Exinstall)TransportRoles\Data\Temp","$($Exinstall)TransportRoles\Logs","$($Exinstall)TransportRoles\Pickup","$($Exinstall)TransportRoles\Replay","$($Exinstall)Working\OleConverter"
        Add-MpPreference -ExclusionExtension .config,.chk,.edb,.jfm,.jrs,.log,.que

        # End - Notification of completion
        Write-Host 'Completed Windows Defender exclusion configuration.' -ForegroundColor Cyan

    } Else {
        Write-Host 'Could not load Exchange PS Snapin.  Cannot add Windows Defender exclusions' -ForegroundColor Red
    }

    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '

} # End of Adding Windows Defender Exclusions Function

# Begin BITSCheck Function
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

# Function Check Dot Net Version
Function Check-DotNetVersion {
    # Formatting
    Write-Host " "
    Write-Host " "
    $DotNetFound = $False
    # .NET 4.8 or less check
	$NETval = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release"
    $OS = (Get-WmiObject -class Win32_OperatingSystem).Caption
    # Parse through most .NET possibilities:
    If ($NETval.Release -gt "528049") {
        If ($OS -like '*2022*') {
            If ($NETval.Release -gt "528449") {
                Write-Host "Greater than .NET 4.8 is installed - " -NoNewLine 
                Write-Host " Unsupported" -ForegroundColor Red
                $DotNetFound = $True
            }
        } Else {
            Write-Host "Greater than .NET 4.8 is installed - " -NoNewLine 
            Write-Host " Unsupported" -ForegroundColor Red
            $DotNetFound = $True
	}
    }
    If (($OS -like '*2022*') -and ($NETval.Release -eq "528449")) {
        Write-Host ".NET 4.8 is installed. Suitable for Exchange 2019 CU2+ - " -NoNewLine 
        Write-Host " Installed" -ForegroundColor Green
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "528049") {
        Write-Host ".NET 4.8 is installed. Suitable for Exchange 2019 CU2+ - " -NoNewLine 
        Write-Host " Installed" -ForegroundColor Green
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "461814") {
        Write-Host ".NET 4.7.2 is installed. Suitable for Exchange 2019 - " -NoNewLine 
        Write-Host " Installed" -ForegroundColor Green
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "461310") {
        Write-Host ".NET 4.7.1 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "460805") {
        Write-Host ".NET 4.7.0 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        DotNetFound = $True
    }
    If ($NETval.Release -eq "394806") {
        Write-Host ".NET 4.6.2 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "394271") {
        Write-Host ".NET 4.6.1 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "393297") {
        Write-Host ".NET 4.6.0  is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "379893") {
        Write-Host ".NET 4.5.2 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "378758") {
        Write-Host ".NET 4.5.1 is installed and is not Supported - " -NoNewLine
        Write-Host " Failed" -ForegroundColor Red
        $DotNetFound = $True
    }
    If ($NETval.Release -eq "378389") {
        Write-Host ".NET 4.5.0 is installed and is not Supported - " -NoNewLine
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

# Check Mailbox Role Prerequisites on Core OS
Function CheckCoreMailbox {

    CLS
    Write-Host '------------------------------------------------------------------------------------------' -ForegroundColor White
    Write-Host ' Checking all requirements for Exchange 2019 Mailbox Role on Windows 2019 /2022 (Core OS)' -ForegroundColor Magenta
    Write-Host '------------------------------------------------------------------------------------------' -ForegroundColor White
    Write-Host ' '
    Write-Host ' '

    # Formatting
    Write-Host ' '
    Write-Host ' '

    # .NET Check - 4.7.2 is default, greater and lower than that not supported as of 2019/06/13
    Check-DotNetVersion
    
    # Check TCP Keep Alive value
    TCPKeepAliveValue

    # C++ 2012 Check
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\7C9F8B73BF303523781852719CD9C700" -ErrorAction Silentlycontinue
	# If($val.DisplayVersion -ne $Null){
    If($val.Version -ge '184610406'){
		Write-Host "Microsoft Visual C++ 2012 x64 Runtime - 11.0.61030 is" -NoNewline -ForegroundColor White
        Write-Host "installed." -ForegroundColor Green
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

    # UCMA Verification
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
    If($val.DisplayVersion -ne "5.0.8308.0"){
		Write-Host "Microsoft Unified Communications Managed API 4.0 is now" -ForegroundColor White -NoNewLine
        Write-host " installed" -ForegroundColor Green
	} Else {
        Write-Host "Microsoft Unified Communications Managed API 4.0 is" -ForegroundColor White -NoNewLine
        Write-Host " not Installed" -ForegroundColor Yellow
    }

    # Check Windows Features
    # Microsoft - https://docs.microsoft.com/en-us/exchange/plan-and-deploy/prerequisites?view=exchserver-2019
    # $Values = @("Install-WindowsFeature AS-HTTP-Activation","Server-Media-Foundation","NET-Framework-45-Features","RPC-over-HTTP-proxy","RSAT-Clustering","RSAT-Clustering-CmdInterface","RSAT-Clustering-Mgmt","RSAT-Clustering-PowerShell","WAS-Process-Model","Web-Asp-Net45","Web-Basic-Auth","Web-Client-Auth","Web-Digest-Auth","Web-Dir-Browsing","Web-Dyn-Compression","Web-Http-Errors","Web-Http-Logging","Web-Http-Redirect","Web-Http-Tracing","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Metabase","Web-Mgmt-Service","Web-Net-Ext45","Web-Request-Monitor","Web-Server","Web-Stat-Compression","Web-Static-Content","Web-Windows-Auth","Web-WMI","Windows-Identity-Foundation","RSAT-ADDS")
    # Actual
    $Values = @("Web-Client-Auth","Web-Dir-Browsing","Web-Http-Errors","Web-Http-Logging","Web-Http-Redirect","Web-Metabase","Web-WMI","Web-Basic-Auth","Web-Digest-Auth","Web-Dyn-Compression","Web-Stat-Compression","Web-Windows-Auth","Web-ISAPI-Filter","NET-WCF-HTTP-Activation45","Web-Request-Monitor","RPC-over-HTTP-proxy","RSAT-Clustering","RSAT-Clustering-CmdInterface","RSAT-Clustering-PowerShell","Web-Static-Content","Web-Http-Tracing","Web-Asp-Net45","Web-ISAPI-Ext","Web-Mgmt-Service","Web-Net-Ext45","WAS-Process-Model","Web-Server","Server-Media-Foundation","RSAT-ADDS","NET-Framework-45-Features")
	Foreach ($Item in $Values){
	    $val = Get-WindowsFeature $Item
	    If ($Val.Installed -eq $True){
	        Write-Host "The Windows Feature"$item" is " -ForegroundColor White -NoNewLine 
	        Write-Host "installed." -ForegroundColor Green
	    } Else {
	        Write-Host "The Windows Feature"$item" is " -ForegroundColor White -NoNewLine 
	        Write-Host "not installed!" -ForegroundColor Red
	    }
	}

    # RAM Installed Check
    Try {
        $RamInGB = (Get-CIMInstance -computername $name -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
    } catch {
        Write-Host "Cannot acquire the amount of RAM in the server." -ForegroundColor Red
        $WMIQuery = $True
    }

    If ($WMIQuery) {
		Try {
            $RamInGb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
		} catch {
			Write-Host "Cannot acquire the amount of RAM in the server with CIM or WMI queries." -ForegroundColor Red
			$Stop = $True
		}
    }

    If ($RAMInGb -lt 128) {
        Write-Host 'RAM Test for Mailbox Role - ' -NoNewLine  -ForegroundColor White
        Write-Host 'FAILED' -ForegroundColor Red -NoNewline
        Write-Host " - $RAMinGB GB RAM Installed" -ForegroundColor White
    } Else {
        Write-Host 'RAM Test - Mailbox Role = ' -ForegroundColor White -NoNewLine
        Write-Host 'Passed' -ForegroundColor Green
        Write-Host " - $RAMinGB GB RAM Installed" -ForegroundColor White
    }

    # IIS URL Rewrite Check (New with CU11 - 10/27/21)
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\8112ACB9357FE1A4CB3FA528709269C5" -ErrorAction Silentlycontinue
    If($val.ProductName -like 'IIS URL Rewrite Module*'){
		Write-Host "IIS URL Rewrite module is" -NoNewline
        Write-Host " installed." -ForegroundColor Green
	} Else {
        Write-Host "IIS URL Rewrite module was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    # Formatting output and pause
    Write-host " "
    Write-host " "
    Write-host " "
    Start-Sleep 3
} # End Check for Mailbox Prerequisites (Core OS)

# Check Edge Transport Prerequisites
Function CheckEdgeTransport {
    CLS
    Write-Host '--------------------------------------------------------------------------------------' -ForegroundColor White
    Write-Host ' Checking all requirements for Exchange 2019 Edge Transport Role on Windows 2019/2022' -ForegroundColor Magenta
    Write-Host '--------------------------------------------------------------------------------------' -ForegroundColor White
    Write-Host ' '
    Write-Host ' '

    # Formatting
    Write-Host ' '
    Write-Host ' '
    
    # Check TCP Keep Alive value
    TCPKeepAliveValue

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

    # Check for Lightweight Active Directory Services
    $Values = @("ADLDS")
    Foreach ($Item in $Values){
	    $val = Get-WindowsFeature $Item
	    If ($Val.Installed -eq $True){
	        Write-Host "The Windows Feature"$item" is " -NoNewLine 
	        Write-Host "installed." -ForegroundColor Green
	    } Else {
	        Write-Host "The Windows Feature"$item" is " -NoNewLine 
	        Write-Host "not installed!" -ForegroundColor Yellow
	    }
	}

    # RAM Installed Check
    Try {
        $RamInGB = (Get-CIMInstance -computername $name -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
    } catch {
        Write-Host "Cannot acquire the amount of RAM in the server." -ForegroundColor Red
        $WMIQuery = $True
    }

    If ($WMIQuery) {
		Try {
            $RamInGb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
		} catch {
			Write-Host "Cannot acquire the amount of RAM in the server with CIM or WMI queries." -ForegroundColor Red
			$Stop = $True
		}
    }

    If ($RAMInGb -lt 128) {
        Write-Host 'RAM Test for Edge Transport Role - ' -NoNewLine  -ForegroundColor White
        Write-Host 'FAILED' -ForegroundColor Red -NoNewline
        Write-Host " - $RAMinGB GB RAM Installed" -ForegroundColor White
    } Else {
        Write-Host 'RAM Test - Edge Transport Role = ' -ForegroundColor White -NoNewLine
        Write-Host 'Passed' -ForegroundColor Green
        Write-Host " - $RAMinGB GB RAM Installed" -ForegroundColor White
    }
    
    TCPKeepAliveValue

    # Formatting output and pause
    Write-host " "
    Write-host " "
    Write-host " "
    Start-Sleep 3

} # End for Edge Transport Prerequisites

# Check for Mailbox Prerequisites on Full OS
Function CheckFullMailbox {
    CLS
    Write-Host '-----------------------------------------------------------------------------------------' -ForegroundColor White
    Write-Host ' Checking all requirements for Exchange 2019 Mailbox Role on Windows 2019/2022 (Full OS)' -ForegroundColor Magenta
    Write-Host '-----------------------------------------------------------------------------------------' -ForegroundColor White
    Write-Host ' '
    Write-Host ' '

    # Formatting
    Write-Host ' '
    Write-Host ' '

    # .NET Check - 4.7.2 is default, greater and lower than that not supported as of 2019/06/13
    Check-DotNetVersion
    
    # IIS URL Rewrite Check (New with CU11 - 10/27/21)
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\Installer\Products\8112ACB9357FE1A4CB3FA528709269C5" -ErrorAction Silentlycontinue
    If($val.ProductName -like 'IIS URL Rewrite Module*'){
		Write-Host "IIS URL Rewrite module is" -NoNewline
        Write-Host " installed." -ForegroundColor Green
	} Else {
        Write-Host "IIS URL Rewrite module was" -ForegroundColor White -NoNewline
        Write-Host " not detected! " -ForegroundColor Yellow -NoNewline
        Write-Host "A reboot may be needed." -ForegroundColor White
    }

    # Universal C Runtime in Windows (KB 2999226) Check (New with CU11 - 10/27/21)



    # Check TCP Keep Alive value
    TCPKeepAliveValue

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

    # UCMA Verification
    $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
    If($val.DisplayVersion -ne "5.0.8308.0"){
        Write-Host "Microsoft Unified Communications Managed API 4.0 is" -ForegroundColor White -NoNewLine
        Write-Host " not Installed" -ForegroundColor Yellow		
	} Else {
    Write-Host "Microsoft Unified Communications Managed API 4.0 is now " -ForegroundColor White -NoNewLine
    Write-Host "installed" -ForegroundColor Green

    }

    # Check Windows Features
	# $Values = @("Web-WebServer","Web-Common-Http","Web-Default-Doc","Web-Dir-Browsing","Web-Http-Errors","Web-Static-Content","Web-Http-Redirect","Web-Health","Web-Http-Logging","Web-Log-Libraries","Web-Request-Monitor","Web-Http-Tracing","Web-Performance","Web-Stat-Compression","Web-Dyn-Compression","Web-Security","Web-Filtering","Web-Basic-Auth","Web-Client-Auth","Web-Digest-Auth","Web-Windows-Auth","Web-App-Dev","Web-Net-Ext45","Web-Asp-Net45","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Mgmt-Tools","Web-Mgmt-Compat","Web-Metabase","Web-WMI","Web-Mgmt-Service","NET-Framework-45-ASPNET","NET-WCF-HTTP-Activation45","NET-WCF-MSMQ-Activation45","NET-WCF-Pipe-Activation45","NET-WCF-TCP-Activation45","Server-Media-Foundation","MSMQ-Services","MSMQ-Server","RSAT-Feature-Tools","RSAT-Clustering","RSAT-Clustering-PowerShell","RSAT-Clustering-CmdInterface","RPC-over-HTTP-Proxy","WAS-Process-Model","WAS-Config-APIs")
	$Values = @("Server-Media-Foundation","NET-Framework-45-Features","RPC-over-HTTP-proxy","RSAT-Clustering","RSAT-Clustering-CmdInterface","RSAT-Clustering-Mgmt","RSAT-Clustering-PowerShell","WAS-Process-Model","Web-Asp-Net45","Web-Basic-Auth","Web-Client-Auth","Web-Digest-Auth","Web-Dir-Browsing","Web-Dyn-Compression","Web-Http-Errors","Web-Http-Logging","Web-Http-Redirect","Web-Http-Tracing","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Lgcy-Mgmt-Console","Web-Metabase","Web-Mgmt-Console","Web-Mgmt-Service","Web-Net-Ext45","Web-Request-Monitor","Web-Server","Web-Stat-Compression","Web-Static-Content","Web-Windows-Auth","Web-WMI","Windows-Identity-Foundation","RSAT-ADDS")
    Foreach ($Item in $Values){
	    $val = Get-WindowsFeature $Item
	    If ($Val.Installed -eq $True){
	        Write-Host "The Windows Feature"$item" is " -NoNewLine -ForegroundColor White
	        Write-Host "installed." -ForegroundColor Green
	    } Else {
	        Write-Host "The Windows Feature"$item" is " -NoNewLine 
	        Write-Host "not installed!" -ForegroundColor Red
	    }
	}

    # RAM Installed Check
    Try {
        $RamInGB = (Get-CIMInstance -computername $name -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
    } catch {
        Write-Host "Cannot acquire the amount of RAM in the server." -ForegroundColor Red
        $WMIQuery = $True
    }

    If ($WMIQuery) {
		Try {
            $RamInGb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1GB
		} catch {
			Write-Host "Cannot acquire the amount of RAM in the server with CIM or WMI queries." -ForegroundColor Red
			$Stop = $True
		}
    }

    If ($RAMInGb -lt 128) {
        Write-Host 'RAM Test for Mailbox Role - ' -NoNewLine  -ForegroundColor White
        Write-Host 'FAILED' -ForegroundColor Red -NoNewline
        Write-Host " - $RAMinGB GB RAM Installed" -ForegroundColor White
    } Else {
        Write-Host 'RAM Test - Mailbox Role = ' -ForegroundColor White -NoNewLine
        Write-Host 'Passed' -ForegroundColor Green
        Write-Host " - $RAMinGB GB RAM Installed" -ForegroundColor White
    }

    # Formatting output and pause
    Write-host " "
    Write-host " "
    Write-host " "
    Start-Sleep 3
}# End Check for Mailbox Prerequisites (Full OS)

# Check Server Power Management
Function CheckPowerPlan {
	$HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
	$CurrPlan = $(powercfg -getactivescheme).split()[3]
	if ($CurrPlan -eq $HighPerf) {
		Write-Host " ";Write-Host "The power plan now is set to " -nonewline;Write-Host "High Performance." -foregroundcolor green;Write-Host " "
	}
} # End of Server Power Management Function

# Windows Defender Exclusions - Clear All
Function ClearWindowsDefenderExclusions {
    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '
    Write-Host 'Do you want to completely remove all exclusions for paths, processes and extentions?' -NoNewline
    Write-Host ' (y or n)  ' -ForegroundColor Green -NoNewline
    $DefenderAnswer = Read-Host
    If ($DefenderAnswer -eq 'y') {
        Write-Host 'Clearing all Windows Defender Paths, Processes and Extentions...' -ForegroundColor Yellow
        $Paths = (Get-MpPreference).exclusionpath
        Foreach($Path in $Paths){Remove-MpPreference -ExclusionPath $PAth}
        $Process = (Get-MpPreference).exclusionprocess
        Foreach($Process1 in $Process){Remove-MpPreference -ExclusionProcess $Process1}
        $Extensions = (Get-MpPreference).exclusionextension
        Foreach($Extension in $Extensions){Remove-MpPreference -ExclusionExtension $Extension}
    } Else {
        Write-Host 'All Windows Defender Paths, Processes and Extentions will be left as is...' -ForegroundColor Cyan
    }

    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '

} # End of Clear All Windows Defender Exclusions Function

# Configure PageFile for Exchange
Function ConfigurePageFile {
    $Stop = $False
    $WMIQuery = $False

    # Remove Existing PageFile
    try {
        Set-CimInstance -Query “Select * from win32_computersystem” -Property @{automaticmanagedpagefile=”False”}
    } catch {
        Write-Host "Cannot remove the existing pagefile." -ForegroundColor Red
        $WMIQuery = $True
    }
    # Remove PageFile with WMI if CIM fails
    If ($WMIQuery) {
		Try {
			$CurrentPageFile = Get-WmiObject -Class Win32_PageFileSetting
            $name = $CurrentPageFile.Name
            $CurrentPageFile.delete()
		} catch {
			Write-Host "The server $server cannot be reached via CIM or WMI." -ForegroundColor Red
			$Stop = $True
		}
    }

    Try {
        $RamInMb = (Get-CIMInstance -computername $name -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1MB
        $ExchangeRAM = $RAMinMb * 0.25
    } catch {
        Write-Host "Cannot acquire the amount of RAM in the server." -ForegroundColor Red
        $stop = $true
    }

    # Get RAM and set ideal PageFileSize - WMI Method
    If ($WMIQuery) {
		Try {
            $RamInMb = (Get-wmiobject -computername $server -Classname win32_physicalmemory -ErrorAction Stop | measure-object -property capacity -sum).sum/1MB
            $ExchangeRAM = $RAMinMb * 0.25
		} catch {
			Write-Host "Cannot acquire the amount of RAM in the server with CIM or WMI queries." -ForegroundColor Red
			$stop = $true
		}
    }

    # For possible addition at a later time
    # If ($ExchangeRAM -lt 32768) {
    #      $ExchangeRAM = 32768
    # }

    # Reset WMIQuery
    $WMIQuery = $False

    If ($Stop -Ne $True) {
        # Configure PageFile
        try {
            Set-CimInstance -Query “Select * from win32_PageFileSetting” -Property @{InitialSize=$ExchangeRAM;MaximumSize=$ExchangeRAM}
        } catch {
            Write-Host "Cannot configure the PageFile correctly." -ForegroundColor Red
        }
        If ($WMIQuery) {
		    Try {
                Set-WMIInstance -computername $server -class win32_PageFileSetting -arguments @{name ="$name";InitialSize=$ExchangeRAM;MaximumSize=$ExchangeRAM}
		    } catch {
			    Write-Host "Cannot configure the PageFile correctly." -ForegroundColor Red
                $stop = $true
		    }
        }
        if ($stop -ne $true) {
            $pagefile = Get-CimInstance win32_PageFileSetting -Property * | select-object Name,initialsize,maximumsize
            $name = $pagefile.name;$max = $pagefile.maximumsize;$min = $pagefile.initialsize
            Write-Host " "
            Write-Host "This server's pagefile, located at " -ForegroundColor white -NoNewline
            Write-Host "$name" -ForegroundColor green -NoNewline
            Write-Host ", is now configured for an initial size of " -ForegroundColor white -NoNewline
            Write-Host "$min MB " -ForegroundColor green -NoNewline
            Write-Host "and a maximum size of " -ForegroundColor white -NoNewline
            Write-Host "$max MB." -ForegroundColor Green
            Write-Host " "
        } else {
            Write-Host "The PageFile cannot be configured at this time." -ForegroundColor Red
        }
    } else {
        Write-Host "The PageFile cannot be configured at this time." -ForegroundColor Red
    }
} # End of Configure Pagefile Function

#Configure TCP Keep Alive value Function
Function ConfigureTCPKeepAlive {
    
    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '

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

    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '

} # End of Configure TCP Keep Alive value Function

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
    Write-Host " "
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
    [string]$expression = ".\2013-vcRedist_x64.exe /quiet /norestart /l* $targetfolder\2013-cPlusPlus.log"
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
    Write-Host " "

} # End of CPlusPlus Function

# Disable SSL 3.0
Function DisableSSL3 {
    Write-Host " "
    $TestPath1 = Get-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" -erroraction silentlycontinue
    $TestPath2 = Get-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -erroraction silentlycontinue
    $regisTrypath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
    $Name = "Enabled"
	$value = "0"
    $checkval1 = Get-Itemproperty -Path "$regisTrypath" -name $name -erroraction silentlycontinue

    # Check for SSL 3.0 Reg Key
	If ($TestPath1 -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols", $true)
		$key.CreateSubKey('SSL 3.0')
		$key.Close()
	} Else {
		Write-Host "The " -NoNewLine
        Write-Host "SSL 3.0" -ForegroundColor Green -NoNewLine
        Write-Host " RegisTry key already exists."
	}

    # Check for SSL 3.0\Server Reg Key
	If ($TestPath2 -eq $null) {
		$key = (get-item HKLM:\).OpenSubKey("System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0", $true)
		$key.CreateSubKey('Server')
		$key.Close()
	} Else {
		Write-Host "The " -NoNewLine
        Write-Host "SSL 3.0\Servers" -ForegroundColor Green -NoNewLine
        Write-Host " RegisTry key already exists."
	}

    # Add the enabled value to disable SSL 3.0 Support
	If ($checkval1.enabled -ne "0") {
		Try {
			New-ItemProperty -Path $regisTryPath -Name $name -Value $value -force -PropertyType DWord
            $ssl++
		} Catch {
			$SSL--
		} 
	} Else {
		Write-Host "The regisTry value " -NoNewLine
        Write-Host "Enabled" -ForegroundColor Green -NoNewLine
        Write-Host " exists under the SSL 3.0\Server RegisTry Key."
	}
} # End of Disable SSL 3.0 Function

# Enable RSS on all adapters
Function EnableRSS {

    Write-host 'This will close your RDP session!  Please reconnect after it is closed.' -ForegroundColor Yellow
    Start-Sleep 2
    $Names = (Get-NetAdapterRss).Name
    Foreach ($Name in $Names) {
        $RSS = (Get-NetAdapterRss -Name $Name).Enabled
        IF (!$RSS) {
            Try {
                Enable-NetAdapterRSS -Name $Name -ErrorAction STOP
                $Date = Get-Date
                $Output = "$Date : SUCCESS - Enabled RSS on the $Name Adapter." | Out-File  $LogDestination -Append
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enable RSS on the $Name Adapter." | Out-File  $LogDestination -Append
            }
        }
    }
} # End of Enable RSS function

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

# Configure the Server for the High Performance Power Plan
Function HighPerformance {
    Write-Host " "
	$HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
	$CurrPlan = $(powercfg -getactivescheme).split()[3]
	if ($CurrPlan -ne $HighPerf) {
		powercfg -setactive $HighPerf
		CheckPowerPlan
	} else {
		if ($CurrPlan -eq $HighPerf) {
			Write-Host " ";Write-Host "The power plan is already set to " -nonewline;Write-Host "High Performance." -foregroundcolor green;Write-Host " "
		}
	}
} # End of High Performance Power Plan Function

# IIS URL Rewrite
Function IISURLRewrite {

    FileDownload "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
    Set-Location $DownloadFolder
    Write-Host " "
    Write-Host "File: rewrite_amd64_en-US.msi installing..." -NoNewLine

    # New Code (Waits for completion)
    # .\rewrite_amd64_en-US.msi /quiet /norestart | Out-Null
    # Start-Process .\Install\rewrite_amd64_en-US.msi -Wait -NoNewWindow
    Start-Process 'rewrite_amd64_en-US.msi' -ArgumentList /quiet -Wait

    Write-Host "`nIIS URL Rewrite is now installed" -ForegroundColor Green
    Write-Host " "
} # End of the IISURLRewrite Function

# Function .NET 4.8
Function Install-NET48 {

    # VerIfy .NET 4.8 is not already installed
    Check-DotNetVersion
    $DotNetVersion = ($global:NetVersion).release
    If ($DotNetVersion -lt 528049) {

        Write-Host "  ***  .NET 4.8 is not installed.  Downloading now!!  ***" -ForegroundColor Yellow
        # Download .NET 4.8 installer
        # FileDownload "https://download.microsoft.com/download/6/E/4/6E48E8AB-DC00-419E-9704-06DD46E5F81D/NDP472-KB4054530-x86-x64-AllOS-ENU.exe"
        FileDownload "https://download.visualstudio.microsoft.com/download/pr/7afca223-55d2-470a-8edc-6a1739ae3252/abd170b4b0ec15ad0222a809b761a036/ndp48-x86-x64-allos-enu.exe"
	    Set-Location $DownloadFolder
        Write-Host " "
	    Write-Host "File: ndp48-x86-x64-allos-enu.exe installing..." -NoNewLine

        # New Code (Waits for completion)
        .\ndp48-x86-x64-allos-enu.exe /quiet /norestart | Out-Null
        
        Write-Host "`n.NET 4.8 is now installed" -ForegroundColor Green
        Write-Host " "
        $Reboot = $true

    } 
    start-sleep 2

} # End of Function .NET 4.8 Install

# Install Microsoft Unified Communications Managed API 4.0, Core Runtime 64-bit
Function Install-NewWinUniComm4{
	FileDownload "http://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe"
	Set-Location $DownloadFolder
    [string]$expression = ".\UcmaRuntimeSetup.exe /quiet /norestart /l* $targetfolder\WinUniComm4.log"
	Write-Host "File: UcmaRuntimeSetup.exe installing..." -NoNewLine
	Invoke-Expression $expression
	Start-Sleep -Seconds 20
	$val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
	if($val.DisplayVersion -ne "5.0.8308.0"){
		Write-Host "`nMicrosoft Unified Communications Managed API 4.0 is now installed" -ForegroundColor Green
	}
    Write-Host " "
} # End Install-NewWinUniComm4 Function

# Function - Microsoft Unified Communications Managed API 4.0, Core Runtime 64-bit
Function Install-WinUniComm4 {
    Write-Host " "
	$val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{41D635FE-4F9D-47F7-8230-9B29D6D42D31}" -Name "DisplayVersion" -erroraction silentlycontinue
	if($val.DisplayVersion -ne "5.0.8308.0"){
		if($val.DisplayVersion -ne "5.0.8132.0"){
			if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A41CBE7D-949C-41DD-9869-ABBD99D753DA}") -eq $false) {
				Write-Host "`nMicrosoft Unified Communications Managed API 4.0 is not installed.  Downloading and installing now." -foregroundcolor yellow
				Install-NewWinUniComm4
			} else {
    				Write-Host "`nAn old version of Microsoft Unified Communications Managed API 4.0 is installed."
				UnInstall-WinUniComm4
				Write-Host "`nMicrosoft Unified Communications Managed API 4.0 has been uninstalled.  Downloading and installing now."  -foregroundcolor green
				Install-NewWinUniComm4
			}
   		} else {
   			Write-Host "`nThe Preview version of Microsoft Unified Communications Managed API 4.0 is installed."
   			UnInstall-WinUniComm4
   			Write-Host "`nMicrosoft Unified Communications Managed API 4.0 has been uninstalled.  Downloading and installing now." -foregroundcolor green
   			Install-NewWinUniComm4
		}
	} else {
		Write-Host "The correct version of Microsoft Unified Communications Managed API 4.0, Core Runtime 64-bit is " -nonewline
		Write-Host "installed." -ForegroundColor green
	}
    Write-Host " "
} # End Install-WinUniComm4 Function

# Begin ModuleStatus Function
Function ModuleStatus {
        $module = Get-Module -name "ServerManager" -erroraction STOP

    if ($module -eq $null) {
        try {
            Import-Module -Name "ServerManager" -erroraction STOP
            # return $null
        } catch {
            Write-Host " ";Write-Host "Server Manager module could not be loaded." -ForegroundColor Red
        }
    } else {
        # Write-Host "Server Manager module is already imported." -ForegroundColor Cyan
        # return $null
    }
    Write-Host " "
} # End ModuleStatus Function

# Turn off NIC Power Management
Function PowerMgmt {
    Write-Host " "
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
            # Check to see if the value is 24 and if not, set it to 24
            If($PnPCapabilities -ne 24){Set-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 24 | Out-Null}
            # Verify the value is now set to or was set to 24
			If($PnPCapabilities -eq 24) {Write-Host " ";Write-Host "Power Management has already been " -NoNewline;Write-Host "disabled" -ForegroundColor Green;Write-Host " "}
   		 } 
 	 } 
 } # End of NIC Power Management Function
  
# Windows Defender Exclusions - Reporting

Function ReportWindowsDefenderExclusions {

    ########### REPORTING ###########################################

    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '

    # Get Windows Defender exclusions:
    $ExclusionExtension = (Get-MpPreference).ExclusionExtension
    $ExclusionPath = (Get-MpPreference).ExclusionPath
    $ExclusionProcess = (Get-MpPreference).ExclusionProcess

    # Display Current exclusions:
    Write-Host 'Current Windows Defender Exclusions:' -ForegroundColor Green
    Write-host 'Excluded Extensions' -ForegroundColor Yellow
    If ($Null -eq $ExclusionExtension) {Write-Host 'None'} Else {$ExclusionExtension}
    Write-Host 'Excluded Paths' -ForegroundColor Yellow
    If ($Null -eq $ExclusionPath) {Write-Host 'None'} Else {$ExclusionPath}
    Write-Host 'Excluded Processes' -ForegroundColor Yellow
    If ($Null -eq $ExclusionProcess) {Write-Host 'None'} Else {$ExclusionProcess}
    
    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '
    ########### End of REPORTING ####################################

} # End of Reporting on Windows Defender Exclusions Function

# SMBv1 and SMBv2 Function
Function SMBv1SMBv2 {

    # Check SMBv1 enabled
    $LogDestination = $Path+'\SMBlog.txt'
    $SMBV1Installed = $False
    $SMBv1 = (Get-WindowsFeature FS-SMB1).Installed
    Write-Host "SMBv1 Check:" -ForegroundColor White
    If ($SMBV1 -eq $True) {
        $Date = Get-Date
        $Output = "$Date - INFO - SMBv1 was found installed, attemting to remove." | Out-File  $LogDestination -Append
        Try {
            # Remove
            Remove-WindowsFeature FS-SMB1 -ErrorAction STOP
            $Date = Get-Date ; $Output = "$Date - SUCCESS - SMBv1 is now removed from the server." | Out-File  $LogDestination -Append
            Write-Host ' * SMBv1 is ' -ForegroundColor White -NoNewLine
            Write-Host 'not installed' -ForegroundColor Green
        } Catch {
            $Date = Get-Date ; $Output = "$Date - FAILED - Could not remove SMBv1 from the server." | Out-File  $LogDestination -Append
            $Output = "$Date - Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            Write-Host ' * SMBv1 is ' -ForegroundColor White -NoNewLine
            Write-Host 'installed' -ForegroundColor Red
        }
    } Else {
        Write-Host ' * SMBv1 is ' -ForegroundColor White -NoNewLine
        Write-Host 'not installed' -ForegroundColor Green
    }

    # Verify SMBv1 is not enabled
    $SMBv1ProtocolEnabled = $True
    $SMBv2ProtocolEnabled = $False
    $SMBv1Protocol = Get-SmbServerConfiguration | Select EnableSMB1Protocol
    $SMBv2Protocol = Get-SmbServerConfiguration | Select EnableSMB2Protocol
    If ($SMBv1Protocol -eq $True) {
        Try {
            Set-SmbServerConfiguration -EnableSMB2Protocol $False -Confirm:$False -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date - SUCCESS - Could not disable SMBv1 on the server." | Out-File  $LogDestination -Append
            Write-Host ' * SMBv1 is ' -ForegroundColor White -NoNewLine
            Write-Host 'disabled.' -ForegroundColor Green
            $SMBv1ProtocolEnabled = $False
        } Catch {
            $Date = Get-Date
            $Output = "$Date - FAILED - Could not disable SMBv1 on the server." | Out-File  $LogDestination -Append
            $Output = "$Date - Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            Write-Host ' * SMBv1 is ' -ForegroundColor White -NoNewLine
            Write-Host 'not disabled.' -ForegroundColor Red
        }
    } Else {
            $Date = Get-Date ; $Output = "$Date - SUCCESS - SMBv1 is disabled on the server." | Out-File  $LogDestination -Append
            Write-Host ' * SMBv1 is ' -ForegroundColor White -NoNewLine
            Write-Host 'disabled.' -ForegroundColor Green
            $SMBv1ProtocolEnabled = $False
    }
    If ($SMBv2Protocol -eq $True) {
        $Date = Get-Date
        $Output = "$Date - SUCCESS - SMBv2 is enabled on the server." | Out-File  $LogDestination -Append
        Write-Host ' * SMBv2 is ' -ForegroundColor White -NoNewLine
        Write-Host 'enabled.' -ForegroundColor Green
	    $SMBv2ProtocolEnabled = $True
    } Else {
        Try {
            Set-SmbServerConfiguration -EnableSMB2Protocol $True -Confirm:$False -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date - SUCCESS - SMBv2 is enabled on the server." | Out-File  $LogDestination -Append
            Write-Host ' * SMBv2 is ' -ForegroundColor White -NoNewLine
            Write-Host 'enabled.' -ForegroundColor Green
            $SMBv2ProtocolEnabled = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date - FAILED - Could not enable SMBv2 on the server." | Out-File  $LogDestination -Append
            $Output = "$Date - Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            Write-Host ' * SMBv2 is ' -ForegroundColor White -NoNewLine
            Write-Host 'not enabled.' -ForegroundColor Red
        }
    }
    # Return values back for the server:
    Return $SMBV1Installed,$SMBv1ProtocolEnabled,$SMBv2ProtocolEnabled
} # End Function to disable SMBv1

# Check the TCP Keep Alive Value
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

# Function for TLS 1.0, 1.1 and 1.2
Function TLS101112 {
    $LogDestination = $Path+'\TLSLog.txt'
    # TLS Disable 1.0 / TLS 1.1 / Enable TLS 1.2 (default)
    # Examples of setting an existing value creating a new value
    # $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$DeviceNumber"
    # Set-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 24 | Out-Null
    # New-ItemProperty -Path $TCPPath -Name "KeepAliveTime" -Value 1800000 -Force -PropertyType DWord
    # $TCPPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

  # TLS 1.0 - Server
    #Variables
    $TLS10ServerPathBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $TLS10ServerPathShort = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0'
    $TLS10ServerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
    $TLS10ServerEnabled = (Get-ItemProperty -Path $TLS10ServerPath -ErrorAction SilentlyContinue).Enabled
    $TLS10ServerDisabledByDefault = (Get-ItemProperty -Path $TLS10ServerPath -ErrorAction SilentlyContinue).DisabledByDefault
    #Create Keys
    If ((Get-Item -Path $TLS10ServerPathShort -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS10ServerPathBase -Name 'TLS 1.0' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.0 base reg key created." | Out-File  $LogDestination -Append
            $TLS10BasePath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.0 base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS10BasePath = $False
        }
    } else {
        $TLS10BasePath = $True
    }
    If ((Get-Item -Path $TLS10ServerPath -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS10ServerPathShort -Name 'Server' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.0 Server base reg key created." | Out-File  $LogDestination -Append
            $TLS10ShortPath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.0 Server base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS10ShortPath = $False
        }
    } Else {
        $TLS10ShortPath = $True
    }
    # Add Entries
    If (($TLS10BasePath) -and ($TLS10ShortPath)) {
        If ($Null -eq $TLS10ServerEnabled){
            # Set value in the path:
            Try {
                New-ItemProperty -Path $TLS10ServerPath -Name 'Enabled' -Value 0 -Force -PropertyType DWord -ErrorAction STOP
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.0 Server is now disabled." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.0 Server." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS10ServerEnabled -eq '1') {
            Try {
                Set-ItemProperty -Path $TLS10ServerPath -Name "Enabled" -Value 0 -ErrorAction STOP| Out-Null
                $Date = Get-Date ; $Output = "$Date : SUCCESS - TLS 1.0 Server is now disabled." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.0 Server." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            } 
        } Elseif ($TLS10ServerEnabled -eq '0') {
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.0 Server is disabled." | Out-File  $LogDestination -Append
        }
        If ($Null -eq $TLS10ServerDisabledByDefault) {
            Try {
                New-ItemProperty -Path $TLS10ServerPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.0 Server is now disabled by Default." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disabled TLS 1.0 Server by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        }  ElseIf ($TLS10ServerDisabledByDefault -eq '0') {
            Try {
                Set-ItemProperty -Path $TLS10ServerPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date ; $Output = "$Date : SUCCESS - TLS 1.0 Server is Disabled by Default." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.0 Server by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS10ServerDisabledByDefault -eq '1') {
            $Date = Get-Date
            $Output = "$Date : Success - TLS 1.0 Server is Disabled by Default." | Out-File  $LogDestination -Append
        }
    }
    # TLS 1.0 - Client
    #Variables
    $TLS10ClientPathBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $TLS10ClientPathShort = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0'
    $TLS10ClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
    $TLS10ClientEnabled = (Get-ItemProperty -Path $TLS10ClientPath -ErrorAction SilentlyContinue).Enabled
    $TLS10ClientDisabledByDefault = (Get-ItemProperty -Path $TLS10ClientPath -ErrorAction SilentlyContinue).DisabledByDefault
    #Create Keys
    If ((Get-Item -Path $TLS10ClientPathShort -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS10ClientPathBase -Name 'TLS 1.0' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.0 base reg key created." | Out-File  $LogDestination -Append
            $TLS10BasePath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.0 base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS10BasePath = $False
        }
    } else {
        $TLS10BasePath = $True
    }
    If ((Get-Item -Path $TLS10ClientPath -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS10ClientPathShort -Name 'Client' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.0 Client base reg key created." | Out-File  $LogDestination -Append
            $TLS10ShortPath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.0 Client base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS10ShortPath = $False
        }
    } Else {
        $TLS10ShortPath = $True
    }
    # Add Entries
    If (($TLS10BasePath) -and ($TLS10ShortPath)) {
        If ($Null -eq $TLS10ClientEnabled){
            # Set value in the path:
            Try {
                New-ItemProperty -Path $TLS10ClientPath -Name 'Enabled' -Value 0 -Force -PropertyType DWord -ErrorAction STOP
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.0 Client is now disabled." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.0 Client." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS10ClientEnabled -eq '1') {
            Try {
                Set-ItemProperty -Path $TLS10ClientPath -Name "Enabled" -Value 0 -ErrorAction STOP| Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.0 Client is now disabled." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date ; $Output = "$Date : FAILED - Could not disable TLS 1.0 Client." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            } 
        } Elseif ($TLS10ClientEnabled -eq '0') {
            $Date = Get-Date 
            $Output = "$Date : SUCCESS - TLS 1.0 Client is disabled." | Out-File $LogDestination -Append
        }
        If ($Null -eq $TLS10ClientDisabledByDefault) {
            Try {
                New-ItemProperty -Path $TLS10ClientPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.0 Client is now disabled by Default." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disabled TLS 1.0 Client by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        }  ElseIf ($TLS10ClientDisabledByDefault -eq '0') {
            Try {
                Set-ItemProperty -Path $TLS10ClientPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.0 Client is Disabled by Default." | Out-File  $LogDestination -Append
                $TLS10BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.0 Client by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS10ClientDisabledByDefault -eq '1') {
            $Date = Get-Date
            $Output = "$Date : Success - TLS 1.0 Client is Disabled by Default." | Out-File  $LogDestination -Append
        }
    }

    # TLS 1.1 - Server
    #Variables
    $TLS11ServerPathBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $TLS11ServerPathShort = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1'
    $TLS11ServerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
    $TLS11ServerEnabled = (Get-ItemProperty -Path $TLS11ServerPath -ErrorAction SilentlyContinue).Enabled
    $TLS11ServerDisabledByDefault = (Get-ItemProperty -Path $TLS11ServerPath -ErrorAction SilentlyContinue).DisabledByDefault
    #Create Keys
    If ((Get-Item -Path $TLS11ServerPathShort -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS11ServerPathBase -Name 'TLS 1.1' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.1 base reg key created." | Out-File  $LogDestination -Append
            $TLS11BasePath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.1 base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS11BasePath = $False
        }
    } else {
        $TLS11BasePath = $True
    }
    If ((Get-Item -Path $TLS11ServerPath -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS11ServerPathShort -Name 'Server' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.1 Server base reg key created." | Out-File  $LogDestination -Append
            $TLS11ShortPath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.1 Server base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS11ShortPath = $False
        }
    } Else {
        $TLS11ShortPath = $True
    }
    # Add Entries
    If (($TLS11BasePath) -and ($TLS11ShortPath)) {
        If ($Null -eq $TLS11ServerEnabled){
            # Set value in the path:
            Try {
                New-ItemProperty -Path $TLS11ServerPath -Name 'Enabled' -Value 0 -Force -PropertyType DWord -ErrorAction STOP
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.1 Server is now disabled." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.1 Server." | Out-File  $LogDestination -Append
                $Output= "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS11ServerEnabled -eq '1') {
            Try {
                Set-ItemProperty -Path $TLS11ServerPath -Name "Enabled" -Value 0 -ErrorAction STOP| Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.1 Server is now disabled." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.1 Server." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            } 
        } ElseIf ($TLS11ServerEnabled -eq '0') {
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.1 Server disabled." | Out-File $LogDestination -Append
        }
        If ($Null -eq $TLS11ServerDisabledByDefault) {
            Try {
                New-ItemProperty -Path $TLS11ServerPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.1 Server is now disabled by Default." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disabled TLS 1.1 Server by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        }  ElseIf ($TLS11ServerDisabledByDefault -eq '0') {
            Try {
                Set-ItemProperty -Path $TLS11ServerPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date 
                $Output = "$Date : SUCCESS - TLS 1.1 Server is Disabled by Default." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.1 Server by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS11ServerDisabledByDefault -eq '1') {
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.1 Server is Disabled by Default." | Out-File  $LogDestination -Append
        }
    }

    # TLS 1.1 - Client
    #Variables
    $TLS11ClientPathBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $TLS11ClientPathShort = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1'
    $TLS11ClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
    $TLS11ClientEnabled = (Get-ItemProperty -Path $TLS11ClientPath -ErrorAction SilentlyContinue).Enabled
    $TLS11ClientDisabledByDefault = (Get-ItemProperty -Path $TLS11ClientPath -ErrorAction SilentlyContinue).DisabledByDefault
    #Create Keys
    If ((Get-Item -Path $TLS11ClientPathShort -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS11ClientPathBase -Name 'TLS 1.1' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.1 base reg key created." | Out-File  $LogDestination -Append
            $TLS11BasePath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.1 base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS11BasePath = $False
        }
    } else {
        $TLS11BasePath = $True
    }
    If ((Get-Item -Path $TLS11ClientPath -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS11ClientPathShort -Name 'Client' -Force -ErrorAction STOP
            $Date = Get-Date ; $Output = "$Date : SUCCESS - TLS 1.1 Client base reg key created." | Out-File  $LogDestination -Append
            $TLS11ShortPath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.1 Client base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS11ShortPath = $False
        }
    } Else {
        $TLS11ShortPath = $True
    }
    # Add Entries
    If (($TLS11BasePath) -and ($TLS11ShortPath)) {
        If ($Null -eq $TLS11ClientEnabled){
            # Set value in the path:
            Try {
                New-ItemProperty -Path $TLS11ClientPath -Name 'Enabled' -Value 0 -Force -PropertyType DWord -ErrorAction STOP
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.1 is now disabled." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.1." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS11ClientEnabled -eq '1') {
            Try {
                Set-ItemProperty -Path $TLS11ClientPath -Name "Enabled" -Value 0 -ErrorAction STOP| Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.1 is now disabled." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.1." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            } 
        } Elseif ($TLS11ClientEnabled -eq '0') {
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.1 Client is disabled." | Out-File  $LogDestination -Appen
        }
        If ($Null -eq $TLS11ClientDisabledByDefault) {
            Try {
                New-ItemProperty -Path $TLS11ClientPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.1 Client is now disabled by Default." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disabled TLS 1.1 Client by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        }  ElseIf ($TLS11ClientDisabledByDefault -eq '0') {
            Try {
                Set-ItemProperty -Path $TLS11ClientPath -Name "DisabledByDefault" -Value 1 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.1 Client is Disabled by Default." | Out-File  $LogDestination -Append
                $TLS11BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not disable TLS 1.1 Client by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS11ClientDisabledByDefault -eq '1') {
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.1 Client is Disabled by Default." | Out-File  $LogDestination -Append
        }
    }

    # TLS 1.2 - Server
    #Variables
    $TLS12ServerPathBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $TLS12ServerPathShort = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
    $TLS12ServerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
    $TLS12ServerEnabled = (Get-ItemProperty -Path $TLS12ServerPath -ErrorAction SilentlyContinue).Enabled
    $TLS12ServerDisabledByDefault = (Get-ItemProperty -Path $TLS12ServerPath -ErrorAction SilentlyContinue).DisabledByDefault
    #Create Keys
    If ((Get-Item -Path $TLS12ServerPathShort -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS12ServerPathBase -Name 'TLS 1.2' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.2 base reg key created." | Out-File  $LogDestination -Append
            $TLS12BasePath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.2 base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS12BasePath = $False
        }
    } Else {
        $TLS12BasePath = $True
    }
    If ((Get-Item -Path $TLS12ServerPath -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS12ServerPathShort -Name 'Server' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.2 Server base reg key created." | Out-File  $LogDestination -Append
            $TLS12ShortPath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.2 Server base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS12ShortPath = $False
        }
    } Else {
        $TLS12ShortPath = $True
    }
    # Add Entries
    If (($TLS12BasePath) -and ($TLS12ShortPath)) {
        If ($Null -eq $TLS12ServerEnabled){
            # Set value in the path:
            Try {
                New-ItemProperty -Path $TLS12ServerPath -Name 'Enabled' -Value 1 -Force -PropertyType DWord -ErrorAction STOP
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.2 is now enabled." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enabled TLS 1.2." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS12ServerEnabled -eq '0') {
            Try {
                Set-ItemProperty -Path $TLS12ServerPath -Name "Enabled" -Value 1 -ErrorAction STOP| Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.2 is now enabled." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enabled TLS 1.2." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Appen
            } 
        } Elseif ($TLS12ServerEnabled -eq '1') {
            $Date = Get-Date 
            $Output = "$Date : SUCCESS - TLS 1.2 Server is enabled." | Out-File  $LogDestination -Append
        }
        If ($Null -eq $TLS12ServerDisabledByDefault) {
            Try {
                New-ItemProperty -Path $TLS12ServerPath -Name "DisabledByDefault" -Value 0 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.2 is not Disabled by Default." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enabled TLS 1.2 by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS12ServerDisabledByDefault -eq '1') {
            Try {
                Set-ItemProperty -Path $TLS12ServerPath -Name "DisabledByDefault" -Value 0 -ErrorAction STOP | Out-Null
                $Date = Get-Date ; $Output = "$Date : SUCCESS - TLS 1.2 is not Disabled by Default." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enabled TLS 1.2 by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } Else {
            $Date = Get-Date 
            $Output = "$Date : SUCCESS - TLS 1.2 Server is not Disabled by Default." | Out-File  $LogDestination -Append
        }
    }

    # TLS 1.2 - Client
    #Variables
    $TLS12ClientPathBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $TLS12ClientPathShort = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
    $TLS12ClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $TLS12ClientEnabled = (Get-ItemProperty -Path $TLS12ClientPath -ErrorAction SilentlyContinue).Enabled
    $TLS12ClientDisabledByDefault = (Get-ItemProperty -Path $TLS12ClientPath  -ErrorAction SilentlyContinue).DisabledByDefault
    #Create Keys
    If ((Get-Item -Path $TLS12ClientPathShort -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS12ClientPathBase -Name 'TLS 1.2' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.2 base reg key created." | Out-File  $LogDestination -Append
            $TLS12BasePath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.2 base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS12BasePath = $False
        }
    } else {
        $TLS12BasePath = $True
    }
    If ((Get-Item -Path $TLS12ClientPath -ErrorAction SilentlyContinue) -eq $Null) {
        Try {
            New-Item -Path $TLS12ClientPathShort -Name 'Client' -Force -ErrorAction STOP
            $Date = Get-Date
            $Output = "$Date : SUCCESS - TLS 1.2 Client base reg key created." | Out-File  $LogDestination -Append
            $TLS12ShortPath = $True
        } Catch {
            $Date = Get-Date
            $Output = "$Date : FAILED - Could not create TLS 1.2 Client base reg key." | Out-File  $LogDestination -Append
            $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            $TLS12ShortPath = $False
        }
    } Else {
        $TLS12ShortPath = $True
    }
    # Add Entries
    If (($TLS12BasePath) -and ($TLS12ShortPath)) {
        If ($Null -eq $TLS12ClientEnabled){
            # Set value in the path:
            Try {
                New-ItemProperty -Path $TLS12ClientPath -Name 'Enabled' -Value 1 -Force -PropertyType DWord -ErrorAction STOP
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.2 is now enabled." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enabled TLS 1.2." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS12ClientEnabled -eq '0') {
            Try {
                Set-ItemProperty -Path $TLS12ClientPath -Name "Enabled" -Value 1 -ErrorAction STOP| Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.2 is now enabled." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enabled TLS 1.2." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            } 
        } Elseif ($TLS12ClientEnabled -eq '1') {
            $Date = Get-Date 
            $Output = "$Date : SUCCESS - TLS 1.2 Client is enabled." | Out-File  $LogDestination -Append
        }
        If ($Null -eq $TLS12ClientDisabledByDefault) {
            Try {
                New-ItemProperty -Path $TLS12ClientPath -Name "DisabledByDefault" -Value 0 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.2 is not Disabled by Default." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - Could not enabled TLS 1.2 by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS12ClientDisabledByDefault -eq '1') {
            Try {
                Set-ItemProperty -Path $TLS12ClientPath -Name "DisabledByDefault" -Value 0 -ErrorAction STOP | Out-Null
                $Date = Get-Date
                $Output = "$Date : SUCCESS - TLS 1.2 is not Disabled by Default." | Out-File  $LogDestination -Append
                $TLS12BasePath = $True
            } Catch {
                $Date = Get-Date
                $Output = "$Date : FAILED - TLS 1.2 is Disabled by Default." | Out-File  $LogDestination -Append
                $Output = "$Date : Error message - $_.Exception.Message" | Out-File $LogDestination -Append
            }
        } ElseIf ($TLS12ClientDisabledByDefault -eq '0') {
            $Date = Get-Date 
            $Output = "$Date : SUCCESS - TLS 1.2 Client is not Disabled by Default." | Out-File  $LogDestination -Append
        }
    }
} # End of Function TLS101112

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
        Write-Host ' True' -ForegroundColor Red
        Write-Host 'Server Disabled by Default:' -NoNewline
        Write-Host ' False' -ForegroundColor Red
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
        Write-Host 'Client Enabled' -NoNewline
        Write-Host ' True' -ForegroundColor Red
        Write-Host 'Client Disabled by Default:' -NoNewline
        Write-Host ' False' -ForegroundColor Red
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
        Write-Host 'Server Enabled' -NoNewline
        Write-Host ' True' -ForegroundColor Red
        Write-Host 'Server Disabled by Default:' -NoNewline
        Write-Host ' False' -ForegroundColor Red
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
        Write-Host 'Client Enabled' -NoNewline
        Write-Host ' True' -ForegroundColor Red
        Write-Host 'Client Disabled by Default:' -NoNewline
        Write-Host ' False' -ForegroundColor Red
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
        Write-Host ' True' -ForegroundColor Green
        Write-Host 'Server Disabled by Default:' -NoNewline
        Write-Host ' False' -ForegroundColor Green
    }
    # TLS 1.2
    $TLS12ClientPath = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client"
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeClient)
    $RegKey= $Reg.OpenSubKey("$TLS12ClientPath")
    If ($Null -ne $RegKey) {
        $TLS12ClientEnableValue = $RegKey.GetValue("Enabled")
        $TLS12ClientDisabledValue = $RegKey.GetValue("DisabledByDefault")
        If ($TLS12ClientEnableValue -eq '1') {
            Write-Host 'Client Enabled:' -NoNewLine
            Write-host ' True' -ForegroundColor Green
        } Else {
            Write-Host 'Client Enabled:' -NoNewLine
            Write-host ' False' -ForegroundColor Red
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
        Write-Host ' True' -ForegroundColor Green
        Write-Host 'Client Disabled by DEfault:' -NoNewline
        Write-Host ' False' -ForegroundColor Green
    }
} # End of TLScheck function
 
# Universal C Runtime in Windows (KB 2999226)
Function UniversalCRuntime {

    FileDownload "https://download.microsoft.com/download/9/6/F/96FD0525-3DDF-423D-8845-5F92F4A6883E/Windows8.1-KB2999226-x64.msu"
    Set-Location $DownloadFolder
    Write-Host " "
    Write-Host "File: Windows8.1-KB2999226-x64.msu installing..." -NoNewLine

    # New Code (Waits for completion)
    Start-Process 'Windows8.1-KB2999226-x64.msu' -ArgumentList /quiet -Wait

    Write-Host "`nIIS URL Rewrite is now installed" -ForegroundColor Green
    Write-Host " "
} # End of the Universal C Runtime Function

# UCMA for Windows 2019/2022 CORE
Function UCMACore {
    # CLS
    Write-host " "
    Write-host "Please mount the Exchange Server 2019 ISO and enter the drive letter for the mounted ISO below:" -ForegroundColor Yellow
    Write-Host "Drive Letter: [D , E, etc]  " -NoNewLine -ForegroundColor White
    $ISO = Read-Host

    # New Code
    $Drive = "$ISO"+":\UCMARedist\"
    cd $DRive   
    Write-Host "File: Setup.exe installing..." -NoNewLine
    .\Setup.exe /quiet /norestart | Out-Null
    
    # Old Code
    # [string]$expression = "$Path /quiet /norestart"
    # Start-Process $Path -NoNewWindow -Wait
    # Invoke-Expression $expression
    # Start-Sleep -Seconds 20

    # Change back to Downloads directory
    cd $CurrentPath

    # Formatting
    Write-Host ' ';Write-Host ' ';Write-Host ' '
} # End of UCMACore Install function

#                                                                                   #
#####################################################################################


#####################################################################################
#              Main Script Section Functions                                        #

# Run code for Windows Server 2019 Full OS
Function Code2019Full {

    $Menu = {
        Write-Host "	*****************************************************" -ForegroundColor Cyan
        Write-Host "	 Exchange Server 2019 (Full OS) Prerequisites Script" -ForegroundColor Cyan
        Write-Host "	*****************************************************" -ForegroundColor Cyan
        Write-Host " "
        Write-Host "	*** .NET 4.8 ***" -ForegroundColor Yellow
        Write-Host " "
        Write-Host "	Install NEW Server" -ForegroundColor Cyan
        Write-Host "	------------------" -ForegroundColor Cyan
        Write-Host "	1) Install Mailbox Role Prerequisites" -ForegroundColor White
        Write-Host "	2) Install Edge Transport Prerequisites" -ForegroundColor White
        Write-Host " "
        Write-Host "	Prerequisite Checks" -ForegroundColor Cyan
        Write-Host "	------------------" -ForegroundColor Cyan
        Write-Host "	10) Check Prerequisites for Mailbox role" -ForegroundColor White
        Write-Host "	11) Check Prerequisites for Edge role" -ForegroundColor White
        Write-Host "	12) Additional Exchange Server checks" -ForegroundColor White
        Write-Host " "
        Write-Host "	One-Off Installations" -ForegroundColor Cyan
        Write-Host "	---------------------" -ForegroundColor Cyan
        Write-Host "	20) Install - One Off - Microsoft C++ 2013" -ForegroundColor White
        Write-Host "	21) Install - One Off - Microsoft C++ 2012 (Mailbox/Edge Transport)" -ForegroundColor White
        Write-Host "	22) Install - One Off - UCMA 4.0" -ForegroundColor White
        Write-Host "	23) Install - One-Off - .NET 4.8 - CU2+" -ForegroundColor White
        Write-Host "	24) Install - IIS URL Rewrite" -ForegroundColor White
        Write-Host "	25) Install - Universal C Runtime" -ForegroundColor White
        Write-Host " "
        Write-Host "	Additional Options" -ForegroundColor Cyan
        Write-Host "	-------------------" -ForegroundColor Cyan
        Write-Host "	30) Set Power Plan to High Performance" -ForegroundColor White
        Write-Host "	31) Disable Power Management for NICs." -ForegroundColor White
        Write-Host "	32) Disable SSL 3.0 Support" -ForegroundColor White
        Write-Host "	33) Configure PageFile to 25% of RAM" -foregroundcolor green
        Write-Host "	34) Configure Event Logs (App, Sys, Sec) to 100MB" -ForegroundColor White
        Write-Host "	35) Configure TCP Keep Alive Value (1800000)" -ForegroundColor White
        Write-Host "	36) Launch Windows Update" -ForegroundColor White
        Write-Host "	37) Disable TLS 1.0 & 1.1. Enabled TLS 1.2"
        Write-Host "	38) Enable RSS on all adapters."
        Write-Host "	39) Disable SMBv1"
        Write-Host "	"
        Write-Host "	Additional Configurations" -ForegroundColor Cyan
        Write-Host "	-------------------------" -ForegroundColor Cyan
        Write-Host "	40) Add Windows Defender Exclusions"
        Write-Host "	41) Clear Windows Defender Exclusions" -ForegroundColor White
        Write-Host "	42) Report Windows Defender Exclusions" -ForegroundColor White
        Write-Host "	"
        Write-Host "	Exit Script or Reboot" -ForegroundColor Cyan
        Write-Host "	-------------------------" -ForegroundColor Cyan
        Write-Host "	98) Restart the Server"  -ForegroundColor Red
        Write-Host "	99) Exit" -ForegroundColor Cyan
        Write-Host "	"
        Write-Host "	Select an option.. [1-99]? " -ForegroundColor White -nonewline
    }

    Do { 	
	    If ($Reboot -eq $true){Write-Host "`t`t`t`t`t`t`t`t`t`n`t`t`t`tREBOOT REQUIRED!`t`t`t`n`t`t`t`t`t`t`t`t`t`n`t`tDO NOT INSTALL EXCHANGE BEFORE REBOOTING!`t`t`n`t`t`t`t`t`t`t`t`t" -backgroundcolor red -foregroundcolor black}
	    If ($Choice -ne "None") {Write-Host "Last command: "$Choice -foregroundcolor Yellow}	
	    Invoke-Command -ScriptBlock $Menu
        $Choice = Read-Host

        Switch ($Choice)    {
            1 {# Prep Mailbox Role - Full OS
                If ($Core) {
                    CLS
                    Write-host "The operating system is " -Foregroundcolor White -NoNewline
                    Write-host "Windows 2019/2022 Server CORE " -Foregroundcolor red -NoNewline
                    Write-host "and cannot continue." -Foregroundcolor White
                    Write-host "Please choose another option." -Foregroundcolor Yellow
                    Write-host " "
                    Write-host " "
                    Start-Sleep 4
                } Else {
                    CLS
                    Write-Host "--------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-Host " Installing prerequisites for Exchange 2019 Mailbox Role on Windows Server 2019/2022!" -ForegroundColor Magenta
                    Write-Host "--------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-host ''
                    ModuleStatus -name ServerManager
                    Install-WindowsFeature RSAT-ADDS
                    Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, RSAT-ADDS
                    Install-NET48
                    Install-WinUniComm4
                    CPlusPlus
                    HighPerformance
                    PowerMgmt
                    ConfigureTCPKeepAlive
                    IISURLRewrite
                    UniversalCRuntime
                    $Reboot = $true
                }
            }
            2 { # Pre Edge Transport Role - Full OS
                    CLS
                    Write-Host "---------------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-Host " Installing prerequisites for Exchange 2019 Edge Transport Role on Windows Server 2019/2022!" -ForegroundColor Magenta
                    Write-Host "---------------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-host ''
                    Install-windowsfeature ADLDS
                    Install-NET48
                    CPlusPlus2012
                    HighPerformance
                    PowerMgmt
                    IISURLRewrite
                    $Reboot = $true
            }
            10 {
                CLS
                If ($Core) {
                    Write-host "This check is " -Foregroundcolor White -NoNewline
                    Write-host "NOT " -Foregroundcolor red -NoNewline
                    Write-host "for Windows 2019/2022 Server Core.  Cannot continue." -Foregroundcolor White
                    Write-host "Please choose another option." -Foregroundcolor Yellow
                    Write-host " "
                    Write-host " "
                    Start-Sleep 4

                } Else {
                    CheckFullMailbox
                }
            }
            11 {
                CheckEdgeTransport
            }
            12 { # Check - TLS, Hyperthreading, SSL and more
                AdditionalChecks
            }
            20 { # Install - One Off - C++ 2013
                CPlusPlus2013
            }
            21 {# Install - One Off - C++ 2012
                CPlusPlus2012
            }
            22 { # Install - One Off - UCMA 4.0
                If ($Core) {
                    CLS
                    Write-host "This UCMA install is " -Foregroundcolor White -NoNewline
                    Write-host "NOT " -Foregroundcolor red -NoNewline
                    Write-host "for Windows 2019/2022 Server Core. Cannot continue." -Foregroundcolor White
                    Write-host "Please choose another option." -Foregroundcolor Yellow
                    Write-host " "
                    Write-host " "
                    Start-Sleep 4
                } Else {
                    Install-WinUniComm4
                }
            }
            23 {#	Install -One-Off - .NET 4.8
                Install-NET48
            }
            24 { # Install IIS URL rewrite
                IISURLRewrite
            }
            25 { # Install Universal C Runtime (KB2999226)
                UniversalCRuntime
            }
            30 { # Set power plan to High Performance as per Microsoft
                HighPerformance
            }
            31 { # Disable Power Management for NICs
                PowerMgmt
            }
            32 { # Disable SSL 3.0 Support
                DisableSSL3
            }
            33 { # Configure Pagefile - 25% of RAMB
                ConfigurePageFile
            }
            34 { # Configure Event Logs to 100MB
                EventLogLimits
            }
            35 { # Configure TCP Keep Alive
                ConfigureTCPKeepAlive
            }
            36 {#	Windows Update
                start ms-settings:windowsupdate
                # Invoke-Expression "$env:windir\system32\wuapp.exe startmenu"
            }
            37 { # Disable TLS 1.0 & 1.1.  Enable TLS 1.2.  Registry work.
                TLS101112
            }
            38 { # Enable RSS on all adapters
                EnableRSS
            }
            39 { # Disable SMBv1 and makesure SMBv2 is enabled
                SMBv1SMBv2
            }
            40 { # Configure Windows Defender Exclusions
                AddWindowsDefenderExclusions
            }
            41 {
                ClearWindowsDefenderExclusions
            }
            42 {
                ReportWindowsDefenderExclusions
            }
            98 { # Exit and restart
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
            Stop-Transcript
            }   
        Default {Write-Host "You haven't selected any of the available options. "}
        }
    } While ($Choice -ne 99)
} # End of 2019 Full OS Install Function

# Run code for Windows Server 2019 Core OS
Function Code2019Core {

    $Menu = {
        Write-Host "	*****************************************************" -ForegroundColor Cyan
        Write-Host "	 Exchange Server 2019 (Core OS) Prerequisites Script" -ForegroundColor Cyan
        Write-Host "	*****************************************************" -ForegroundColor Cyan
        Write-Host " "
        Write-Host "	*** .NET 4.8 ***" -ForegroundColor Yellow
        Write-Host " "
        Write-Host "	Install NEW Server" -ForegroundColor Cyan
        Write-Host "	------------------" -ForegroundColor Cyan
        Write-Host "	1) Install Mailbox Role Prerequisites" -ForegroundColor White
        Write-Host "	2) Install Edge Transport Prerequisites" -ForegroundColor White
        Write-Host " "
        Write-Host "	Prerequisite Checks" -ForegroundColor Cyan
        Write-Host "	------------------" -ForegroundColor Cyan
        Write-Host "	10) Check Prerequisites for Mailbox role" -ForegroundColor White
        Write-Host "	11) Check Prerequisites for Edge role" -ForegroundColor White
        Write-Host "	12) Additional Exchange Server checks" -ForegroundColor White
        Write-Host " "
        Write-Host "	One-Off Installations" -ForegroundColor Cyan
        Write-Host "	---------------------" -ForegroundColor Cyan
        Write-Host "	20) Install - Microsoft C++ 2013" -ForegroundColor White
        Write-Host "	21) Install - Microsoft C++ 2012 (Mailbox/Edge Transport)" -ForegroundColor White
        Write-Host "	22) Install - UCMA 4.0" -ForegroundColor White
        Write-Host "	23) Install - .NET 4.8 - CU2+" -ForegroundColor White
        Write-Host "	24) Install - IIS URL Rewrite" -ForegroundColor White
        Write-Host " "
        Write-Host "	Additional Options" -ForegroundColor Cyan
        Write-Host "	-------------------" -ForegroundColor Cyan
        Write-Host "	30) Set Power Plan to High Performance" -ForegroundColor White
        Write-Host "	31) Disable Power Management for NICs." -ForegroundColor White
        Write-Host "	32) Configure PageFile to 25% of RAM" -foregroundcolor green
        Write-Host "	33) Configure Event Logs (App, Sys, Sec) to 100MB" -ForegroundColor White
        Write-Host "	34) Configure TCP Keep Alive Value (1800000)" -ForegroundColor White
        Write-Host "	35) Launch Windows Update" -ForegroundColor White
        Write-Host "	36) Disable TLS 1.0 & 1.1. Enabled TLS 1.2"
        Write-Host "	37) Enable RSS on all adapters."
        Write-Host "	38) Disable SMBv1"
        Write-Host "	"
        Write-Host "	Windows Defender Options" -ForegroundColor Cyan
        Write-Host "	-------------------------" -ForegroundColor Cyan
        Write-Host "	40) Add Windows Defender Exclusions"
        Write-Host "	41) Clear Windows Defender Exclusions" -ForegroundColor White
        Write-Host "	42) Report Windows Defender Exclusions" -ForegroundColor White
        Write-Host "	"
        Write-Host "	Exit Script or Reboot" -ForegroundColor Cyan
        Write-Host "	-------------------------" -ForegroundColor Cyan
        Write-Host "	98) Restart the Server"  -ForegroundColor Red
        Write-Host "	99) Exit" -ForegroundColor Cyan
        Write-Host "	"
        Write-Host "	Select an option.. [1-99]? " -ForegroundColor White -nonewline
    }

    
    Do { 	
	    If ($Reboot -eq $true){Write-Host "`t`t`t`t`t`t`t`t`t`n`t`t`t`tREBOOT REQUIRED!`t`t`t`n`t`t`t`t`t`t`t`t`t`n`t`tDO NOT INSTALL EXCHANGE BEFORE REBOOTING!`t`t`n`t`t`t`t`t`t`t`t`t" -backgroundcolor red -foregroundcolor black}
	    If ($Choice -ne "None") {Write-Host "Last command: "$Choice -foregroundcolor Yellow}	
	    Invoke-Command -ScriptBlock $Menu
        $Choice = Read-Host

        Switch ($Choice)    {

            1 {# Prep Mailbox Role - Core OS
                If ($Core) {
                    CLS
                    Write-Host "-------------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-Host " Installing prerequisites for Exchange 2019 Mailbox Role on Windows Server 2019/2022 Core!" -ForegroundColor Magenta
                    Write-Host "-------------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-host ''
                    ModuleStatus -name ServerManager
                    Install-WindowsFeature RSAT-ADDS
                    # Microsoft - https://docs.microsoft.com/en-us/exchange/plan-and-deploy/prerequisites?view=exchserver-2019
                    # Install-WindowsFeature AS-HTTP-Activation, Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, RSAT-ADDS
                    # Correct Features
                    Install-WindowsFeature Web-Client-Auth,Web-Dir-Browsing,Web-Http-Errors,Web-Http-Logging,Web-Http-Redirect,Web-Metabase,Web-WMI,Web-Basic-Auth,Web-Digest-Auth,Web-Dyn-Compression,Web-Stat-Compression,Web-Windows-Auth,Web-ISAPI-Filter,NET-WCF-HTTP-Activation45,Web-Request-Monitor,RPC-over-HTTP-proxy,RSAT-Clustering,RSAT-Clustering-CmdInterface,RSAT-Clustering-PowerShell,Web-Static-Content,Web-Http-Tracing,Web-Asp-Net45,Web-ISAPI-Ext,Web-Mgmt-Service,Web-Net-Ext45,WAS-Process-Model,Web-Server,Server-Media-Foundation,RSAT-ADDS,NET-Framework-45-Features
                    Install-NET48
                    UCMACore 
                    CPlusPlus
                    HighPerformance
                    PowerMgmt
                    ConfigureTCPKeepAlive
                    IISURLRewrite
                    $Reboot = $true
                } Else {
                    CLS
                    Write-host "The operating system is " -Foregroundcolor White -NoNewline
                    Write-host "NOT " -Foregroundcolor red -NoNewline
                    Write-host "Windows 2019/2022 Server Core.  Cannot continue." -Foregroundcolor White
                    Write-host "Please choose another option." -Foregroundcolor Yellow
                    Write-host " "
                    Write-host " "
                    Start-Sleep 4
                }
            }
            2 { # Pre Edge Transport Role - Core OS
                    CLS
                    Write-Host "--------------------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-Host " Installing prerequisites for Exchange 2019 Edge Transport Role on Windows Server 2019/2022 Core!" -ForegroundColor Magenta
                    Write-Host "--------------------------------------------------------------------------------------------------" -ForegroundColor White
                    Write-host ''
                    Install-windowsfeature ADLDS
                    CPlusPlus2012
                    HighPerformance
                    PowerMgmt
                    ConfigureTCPKeepAlive
                    $Reboot = $true
            }
            10 {
                CLS
                If ($Core) {
                    CheckCoreMailbox
                } Else {
                    Write-host "This check is " -Foregroundcolor White -NoNewline
                    Write-host "NOT " -Foregroundcolor red -NoNewline
                    Write-host "for Windows 2019 Server and needs to be run on Windows 2019/2022 Core.  Cannot continue." -Foregroundcolor White
                    Write-host "Please choose another option." -Foregroundcolor Yellow
                    Write-host " "
                    Write-host " "
                    Start-Sleep 4
                }
            }
            11 {
                CLS
                CheckEdgeTransport
            }
            12 { # Check - TLS, Hyperthreading, SSL and more
                AdditionalChecks
            }
            20 { # Install - One Off - C++ 2013
                CPlusPlus
            }
            21 { # Install - One Off - C++ 2013
                CPlusPlus2012
            }
            22 { # Install - One Off - UCMA 4.0 on Core OS
                If ($Core) {
                    UCMACore 
                } Else {
                    CLS
                    Write-host "The operating system is " -Foregroundcolor White -NoNewline
                    Write-host "NOT " -Foregroundcolor red -NoNewline
                    Write-host "Windows 2019/2022 Server Core. Cannot continue." -Foregroundcolor White
                    Write-host "Please choose another option." -Foregroundcolor Yellow
                    Write-host " "
                    Write-host " "
                    Start-Sleep 4
                }
            }
            23 {#	Install -One-Off - .NET 4.8
                Install-NET48
            }
            24 { # Install IIS URL rewrite
                IISURLRewrite
            }
            30 { # Set power plan to High Performance as per Microsoft
                HighPerformance
            }
            31 { # Disable Power Management for NICs
                PowerMgmt
            }
            32 { # Configure Pagefile - RAM + 10 MB
                ConfigurePageFile
            }
            33 { # Configure Event Logs
                EventLogLimits
            }
            34 { # Configure TCP Keep Alive
                ConfigureTCPKeepAlive
            }
            35 {#	Windows Update
                Start ms-settings:windowsupdate
                # Invoke-Expression "$env:windir\system32\wuapp.exe startmenu"
            }
            36 { # Disable TLS 1.0 & 1.1.  Enable TLS 1.2.  Registry work.
                TLS101112
            }
            37 { # Enable RSS on all adapters
                EnableRSS
            }
            38 { # Disable SMBv1 and makesure SMBv2 is enabled
                SMBv1SMBv2
            }
            40 { # Configure Windows Defender Exclusions
                AddWindowsDefenderExclusions
            }
            41 {
                ClearWindowsDefenderExclusions
            }
            42 {
                ReportWindowsDefenderExclusions
            }
            98 { # Exit and restart
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
            Stop-Transcript
        }
        Default {Write-Host "You haven't selected any of the available options. "}
        }
    } While ($Choice -ne 99)
} # End of 2019/2022 Core OS Install Function

#              End Main Functions                                                   #
#####################################################################################


#####################################################################################
#               MAIN SCRIPT BODY                                                    #

# Check for Windows Server 2019/2022
If ($Ver -ge '10.0.17763') {
    $OSCheck = $True

    # Now load the menu for Windows 2019/2022 Core or Full OS
    If ($Core) {
        Code2019Core
    } Else {
        Code2019Full
    }
}

# If OS older than Windows Server 2019 found, exit with error
If ($OSCheck -ne $True) {
    write-host " "
    write-host "The server is not running Windows Server 2019/2022.  Exiting the script."  -ForegroundColor Red
    write-host " "
    Exit
}

#                End Main Script Body                                               #
#####################################################################################