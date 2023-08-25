####################################################################################################################################################################
#  SCRIPT DETAILS                                                                                                                                                  #
#    Analyzes Public DNS records [ MX, PTR, SPF, DMARC and DKIM ] to determine the current state for Exchange Online                                               #
#        downloading latest Update Roll-up, etc.                                                                                                                   #
#																																								   #
# SCRIPT VERSION HISTORY	                                                                                                                                       #
#    Current Version	: 1.02                                                                                                                                     #
#                       : 1.02 - Some alterations for blog article
#                       : 1.01 - First version with revisions and testing                                                                                          #
#                                                                                                                                                                  #
# DATE RELEASED         : 8/10/23                                	 																                               #
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
#  .\Get-DNSRecordAnalysis-v1.01.ps1                                                                                                                               #
#                                                                                                                                                                  #
# COMING SOON!                                                                                                                                                     #
#   Certificate Based Authentication, ARC DNS Check and more                                                                                                       #
#																																								   #
####################################################################################################################################################################

# Introduction to DNS Record Analysis and Reporting
# 
# Modules and manual settings are great, but how can we create a report that 
# can be read and understood quickly. Well, we need colors, consolidated useful 
# feedback and overall ratings to assist in determining what needs to be worked on. 
# Utilizing lessons learned from building other health check scripts, using health 
# check scripts and so on we will attempt to construct a useful script that provides 
# quick and relevant analysis of your Microsoft 365 SMTP domains.

# Potential Output
# Overall,Domain,MX,PTR,SPF,DMARC,DKIM,SPF-A,DKIM-A,DMARC-A
# $Overall,$Domain,$MX,$PTR,$SPF,$DMARC,$DKIM,$SPF.SpfAdvisory,$DMARC.DmarcAdvisory,$DKIM.DkimAdvisory

# Rate each domain based on records present
# Color code

# Prerequisited
# Require Admin rights (installation)
# Download module
# Import Module
# Check for ExO module (require?)
# Import module

############################################################
# Module Checks

# Set variables to True
$DHC_Module = $True
$EOM_Module = $True

# Try to import modules
Try { Import-Module DomainHealthChecker } Catch { $DHC_Module = $False }
Try { Import-Module ExchangeOnlineManagement } Catch { $EOM_Module = $False }

# Exchange Online Management Correct Version?
If ($EOM_Module) {$Ver = (Get-InstalledModule ExchangeOnlineManagement).Version ; If ($Ver.split('.')[0] -eq 3) { $EOM_Module = $True} }

# Install missing modules
If (!$EOM_Module) {Try {Install-Module ExchangeOnlineManagement -ErrorAction STOP ; Write-Host 'Successfully installed missing module - Exchange Online Management.' -ForegroundColor Green} Catch { Write-Host 'Cannot Install missing module - Exchange Online Management.  Exiting' -ForegroundColor Red ; Exit} }
If (!$DHC_Module) {Try {Install-Module DomainHealthChecker -ErrorAction STOP ; Write-Host 'Successfully installed missing module - Domain Health Checker.' -ForegroundColor Green} Catch { Write-Host 'Cannot Install missing module - Domain Health Checker.  Exiting' -ForegroundColor Red ; Exit}}

# Load modules
Try { Import-Module DomainHealthChecker -ErrorAction STOP } catch { Write-Host "Domain Health Checker module could not be loaded. Exiting!" -ForegroundColor Red ; Exit }
Try { Import-Module ExchangeOnlineManagement -ErrorAction STOP } catch { Write-Host "Exchange Online Management module could not be loaded. Exiting!" -ForegroundColor Red ; Exit }
############################################################

############################################################
# Starting Tasks

# Admin Rights
#Requires -RunAsAdministrator

# File Definitions
$Date = get-date -Format "MM.dd.yyyy-hh.mm-tt"
$CurrentPath = (Get-Item -Path ".\" -Verbose).FullName
$DNSAnalysisReportFile = "$Date-DNS-Record-Analysis.HTML"
$TranscriptFileName = "$Date-DNS-Record-Analysis-TRANSCRIPT.csv"

# Transcript
Start-Transcript -path "$CurrentPath\$date-Get-DNSRecords.txt" | Out-Null

# Clear Screen
CLS

# Reset Error Variable
$Error.clear()

############################################################

############################################################
# Exchange Online
Connect-ExchangeOnline

# Gather data
Try {
    $AcceptedDomains = (Get-AcceptedDomain -ErrorAction STOP).Name
} Catch {
        $Line = "Either no Accepted Domains were found or the Get-AcceptedDomains cmdlet failed to run." | Out-File $Destination -Append
}
$DNSServer = '8.8.8.8'

$LongestDomainName = ($AcceptedDomains | Measure-Object -Maximum -Property Length).maximum

############################################################

############################################################
# HTML File Header

# Colors
$Green = "#00b200"
$Red = "#E3242B"
$Yellow = "#FFF700"
$Blue = "#1338BE"

# Calculate some columns and other widths
$DomainNameColumnWidth = $LongestDomainName*5
$DomainNameColumnPt = "$DomainNameColumnWidth"+"pt"

# Individual Columns (for customizations)
$OverallColumnWidth = 40
$OverallColumnWidthDisplay = "35pt"
$DNSRecordColumnWidth = 30
$DNSRecordColumnWidthDisplay = "28pt"
$DkimDNSRecordColumnWidth = 50
$DkimDNSRecordColumnDisplay = "45pt"
$SpecialDNSRecordColumnWidth = 60
$SpecialDNSRecordColumnDisplay = "55pt"
$SpfAdvisoryColumnWidth = 325
$SpfAdvisoryColumnWidthDisplay = "320pt"
$DmarcAdvisoryColumnWidth = 500
$DmarcAdvisoryColumnWidthDisplay = "495pt"
$DkimAdvisoryColumnWidth = 300
$DkimAdvisoryColumnWidthDisplay = "295pt"

# $DomainNameColumnPt = "$LongestDomainName"+"pt"
$TableWidthValue = $OverallColumnWidth+$DomainNameColumnWidth+(3*$DNSRecordColumnWidth)+(2*$SpecialDNSRecordColumnWidth)+$SpfAdvisoryColumnWidth+$DmarcAdvisoryColumnWidth+$DkimAdvisoryColumnWidth
$TableWidth = "$TableWidthValue"+"pt"

# HTML file header
"<html xmlns:v='urn:schemas-microsoft-com:vml'" | Out-File -FilePath $DNSAnalysisReportFile
"xmlns:o='urn:schemas-microsoft-com:office:office'" | Out-File -FilePath $DNSAnalysisReportFile -Append
"xmlns:x='urn:schemas-microsoft-com:office:excel'" | Out-File -FilePath $DNSAnalysisReportFile -Append
"xmlns='http://www.w3.org/TR/REC-html40'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
""
"<head>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<meta http-equiv=Content-Type content='text/html; charset=windows-1252'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<!--table" | Out-File -FilePath $DNSAnalysisReportFile -Append
	"{mso-displayed-decimal-separator:'\.';" | Out-File -FilePath $DNSAnalysisReportFile -Append
	"mso-displayed-thousand-separator:'\,'';} "| Out-File -FilePath $DNSAnalysisReportFile -Append
"@page" | Out-File -FilePath $DNSAnalysisReportFile -Append
	"{margin:.75in .7in .75in .7in;" | Out-File -FilePath $DNSAnalysisReportFile -Append
	"mso-header-margin:.3in;" | Out-File -FilePath $DNSAnalysisReportFile -Append
	"mso-footer-margin:.3in;}" | Out-File -FilePath $DNSAnalysisReportFile -Append
"-->" | Out-File -FilePath $DNSAnalysisReportFile -Append
"</HEAD>" | Out-File -FilePath $DNSAnalysisReportFile -Append

"<table border=0 cellpadding=0 cellspacing=0 width=192 style='border-collapse:" | Out-File -FilePath $DNSAnalysisReportFile -Append
 "collapse;table-layout:fixed;width:$TableWidth'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
 # "<col width=64 span=10 style='width:48pt'>" | Out-File -FilePath $DNSAnalysisReportFile -Append

"<tr height=19 style='height:12pt'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 bgcolor='$Blue' width=$OverallColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;height:14.4pt;width:$OverallColumnWidthDisplay;text-align:center;'>Overall</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$DomainNameColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$DomainNameColumnPt;text-align:center;'>AcceptedDomain</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$DNSRecordColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$DNSRecordColumnWidthDisplay;text-align:center;'>MX</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$DNSRecordColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$DNSRecordColumnWidthDisplay;text-align:center;'>SPF</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$SpecialDNSRecordColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$SpecialDNSRecordColumnWidthDisplay;text-align:center;'>DMARC</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$DkimDNSRecordColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$DkimDNSRecordColumnWidthDisplay;text-align:center;'>DKIM</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$SpecialDNSRecordColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$SpecialDNSRecordColumnWidthDisplay;text-align:center;'>DNSSEC</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$SpfAdvisoryColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$SpfAdvisoryColumnWidthDisplay;text-align:center;'>SPF Notes</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$DmarcAdvisoryColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$DmarcAdvisoryColumnWidthDisplay;text-align:center;'>Dmarc Notes</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td bgcolor='$Blue' width=$DkimAdvisoryColumnWidth style='color:White;border-left:none;border:solid black 1.0pt;width:$DkimAdvisoryColumnWidthDisplay;text-align:center;'>Dkim Notes</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"</tr>" | Out-File -FilePath $DNSAnalysisReportFile -Append
############################################################

############################################################
# Main Script Body

Foreach ($AcceptedDomain in $AcceptedDomains) {

	$SpfRecord = Get-SPFRecord $AcceptedDomain
	$DmarcRecord = Get-DMARCRecord $AcceptedDomain
	$DkimRecord = Get-DKIMRecord $AcceptedDomain
    $DnsSec = Get-DNSSec $AcceptedDomain

    ############################################################
    #SPF RECORD
    $SPFRecordLength = [int32]$SpfRecord.SPFRecordLenght
        #SPF Length Analysis
        If ($SPFRecordLength -eq 0) { 
            $SpfRecordLengthResult = 2 # Red / Risk
            $SpfRecordExists = $False
        }
        If (($SPFRecordLength -gt 0) -and ($SPFRecordLength -lt 150)) {
            $SpfRecordLengthResult = 0 # Green / No Risk
            $SpfRecordExists = $True
        }
        If ($SPFRecordLength -gt 200) {
            $SpfRecordExists = $True
            If ($SPFRecordLength -lt 250) {
                $SpfRecordLengthResult = 1 # Yellow / Low Risk
            } Else {
                $SpfRecordLengthResult = 2 # Red / Risk / Too large
            }
        }

        If ($SpfRecordExists) {
            # SPF Advisory Analysis
            If ($SPFRecord.SPFAdvisory -like '*not sufficiently*') {
                $SPFAdvisoryLevel = 1 # Yellow / Low Risk
            } Else {
                $SPFAdvisoryLevel = 0 # Green / No Risk
            }
            If ($SPFRecord.SPFAdvisory -eq 'Domain does not have an SPF record. To prevent abuse of this domain, please add an SPF record to it.') { 
                $SPFAdvisoryLevel = 2 # Red / Risk
            }
        }

        If ($SpfRecordExists) {
            $SPF = 'X'
            $SpfOverallResults = $SpfRecordLengthResult + $SPFAdvisoryLevel
            # If ($SpfOverallResults -eq 0) { $SPFColor = "$Green" }
            If ($SpfOverallResults -eq 4) { $SPFColor = "$Red" }
            If (($SpfOverallResults -gt 0) -and ($SpfOverallResults -lt 4)) { $SPFColor = "$Yellow" }
        }
        # Advisory
        $SpfAdvisory = $SpfRecord.SpfAdvisory
    ############################################################

    ############################################################
    # DKIM RECORD
        
        # Dkim Existence
        If ([string]::IsNullOrWhiteSpace($DkimRecord.DkimRecord) ) {
            $Dkim = ''
            $DkimRecordResult = 2
            $DKIMColor = "$Red"
            
        } Else {
            $DkimRecordResult = 0
            $Dkim = 'X'
            $DkimAdvisory = $DkimRecord.DkimAdvisory
            # $DKIMColor = "$Green"
        }

    # Advisory
    $DkimAdvisory = $DkimRecord.DkimAdvisory
    ############################################################

    ############################################################
    # DMARC RECORD

        # DMARC Existence
        If ([string]::IsNullOrWhiteSpace($DmarcRecord.DmarcRecord) ) {
            $DmarcRecordExists = $False
            $DmarcColor = "$Red"
        } Else {
            $DmarcRecordExists = $True		
            $DmarcExistResult = 0
        }

        If ($DmarcRecordExists) {
            # DMARC Record setting check / rating
            If ($DmarcRecord.DmarcRecord -like '*p=none*') { $DMARCAdvisoryLevel = 2 }
            If ($DmarcRecord.DmarcRecord -like '*p=quarantine*') { $DMARCAdvisoryLevel = 1 }
            If ($DmarcRecord.DmarcRecord -like '*p=reject*') { $DMARCAdvisoryLevel = 0 }
            # Prep for chart
            $Dmarc = 'X'
            $DmarcOverallResults = $DMARCExistResult + $DMARCAdvisoryLevel
            $DMARCAdvisoryLevel  = Switch ($DmarcRecord.DmarcRecord) {
                { $_ -like "*p=none*"} {"2"}
                { $_ -like "*p=quarantine*"} {"1"}
                { $_ -like "*p=reject*"} {"0"}
            }
        }
        
        # Advisory
        $DmarcAdvisory = $DmarcRecord.DmarcAdvisory
    ############################################################

    ############################################################
    # MX Record Check
        Try {
            $MXRecord = Resolve-DnsName $AcceptedDomain -Server $DNSServer -Type MX -ErrorAction STOP
            $MX = 'X'
            $MXRecordResult = 0
        } Catch {
            $MXRecordResult = 2
        }
    ############################################################

    ###########################################################
    # DNS Sec Check
        If ($DnsSec -like '*DNSSEC is enabled on your domain.') {
            $DnsSec = 'X'
            $DNSSecResult = 0
        } Else {
            $DNSSecResult = 2
            $DnsSec = ''
        }
    ###########################################################

    ###########################################################
    # Overall Rating
    $DNSRating = $MXRecordResult+$PTRRecordResult+$DNSSecResult+$DmarcOverallResults+$SpfOverallResults+$DkimRecordResult

    If ($DNSRating -lt 2) { $DNSRatingColor = "$Green" }
    If ($DNSRating -gt 4) { $DNSRatingColor = "$Red" }
    If (($DNSRating -ge 2) -and (($DNSRating -le 4))) { $DNSRatingColor = "$Yellow" }
    ###########################################################

    ############################################################
    # Create HTML Report

    "<tr height=19 style='height:12pt'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td height=19 width=$OverallColumnWidth bgcolor='$DNSRatingColor' style='border-left:none;border:solid black 1.0pt;height:14.4pt;width:$OverallColumnWidthDisplay;text-align:center;' >$DNSRating</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$DomainNameColumnWidth style='border-left:none;border:solid black 1.0pt;width:$DomainNameColumnPt;text-align:center;'>$AcceptedDomain</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$DNSRecordColumnWidth style='border-left:none;border:solid black 1.0pt;width:$DNSRecordColumnWidthDisplay;text-align:center;'>$MX</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$DNSRecordColumnWidth style='border-left:none;border:solid black 1.0pt;width:$DNSRecordColumnWidthDisplay;text-align:center;'>$SPF</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$SpecialDNSRecordColumnWidth style='border-left:none;border:solid black 1.0pt;width:$SpecialDNSRecordColumnWidthDisplay;text-align:center;'>$DMARC</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$DkimDNSRecordColumnWidth style='border-left:none;border:solid black 1.0pt;width:$DkimDNSRecordColumnWidthDisplay;text-align:center;'>$DKIM</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$SpecialDNSRecordColumnWidth style='border-left:none;border:solid black 1.0pt;width:$SpecialDNSRecordColumnWidthDisplay;text-align:center;'>$DNSSEC</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$SpfAdvisoryColumnWidth bgcolor='$SPFColor' style='border-left:none;border:solid black 1.0pt;width:$SpfAdvisoryColumnWidthDisplay;text-align:center;'>$SPFAdvisory</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$DmarcAdvisoryColumnWidth bgcolor='$DmarcColor' style='border-left:none;border:solid black 1.0pt;width:$DmarcAdvisoryColumnWidthDisplay;text-align:center;'>$DmarcAdvisory</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "<td width=$DkimAdvisoryColumnWidth bgcolor='$DkimColor' style='border-left:none;border:solid black 1.0pt;width:$DkimAdvisoryColumnWidthDisplay;text-align:center;'>$DkimAdvisory</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
    "</tr>" | Out-File -FilePath $DNSAnalysisReportFile -Append

    ############################################################

    # Clear Variables
    $SpfAdvisory = $Null
    $DkimcAdvisory = $Null
    $DmarcAdvisory = $Null

} # Close loop for this domain

############################################################
# Finish HTML File
"</table>" | Out-File -FilePath $DNSAnalysisReportFile -Append

"<table border=0 cellpadding=0 cellspacing=0 width=150 style='border-collapse:" | Out-File -FilePath $DNSAnalysisReportFile -Append
 "collapse;table-layout:fixed;width:400'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<BR>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<tr height=19 style='height:12pt'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50 style='border-left:none;height:14.4pt;width:45pt;text-align:center;' ></td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50 style='border-left:none;height:14.4pt;width:45pt;text-align:center;' >Color Key</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=100 style='border-left:none;height:14.4pt;width:95pt;text-align:left;' ></td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"</tr>" | Out-File -FilePath $DNSAnalysisReportFile -Append

"<tr height=19 style='height:12pt'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50 style='border-left:none;height:14.4pt;width:45pt;text-align:center;' ></td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50  bgcolor='$Green' style='border-left:none;height:14.4pt;width:45pt;text-align:center;' >0 - 1</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=100 style='border-left:none;height:14.4pt;width:95pt;text-align:left;' >Good</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"</tr>" | Out-File -FilePath $DNSAnalysisReportFile -Append

"<tr height=19 style='height:12pt'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50 style='border-left:none;height:14.4pt;width:45pt;text-align:left;' ></td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50  bgcolor='$Yellow' style='border-left:none;height:14.4pt;width:45pt;text-align:center;' >2 - 3</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=100 style='border-left:none;height:14.4pt;width:95pt;text-align:left;' >Some Risk - See Notes</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"</tr>" | Out-File -FilePath $DNSAnalysisReportFile -Append

"<tr height=19 style='height:12pt'>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50 style='border-left:none;height:14.4pt;width:45pt;text-align:left;' ></td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=50  bgcolor='$Red' style='border-left:none;height:14.4pt;width:45pt;text-align:center;' >4+</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"<td height=19 width=100 style='border-left:none;height:14.4pt;width:95pt;text-align:left;' >High Risk - See Notes</td>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"</tr>" | Out-File -FilePath $DNSAnalysisReportFile -Append

"</table>" | Out-File -FilePath $DNSAnalysisReportFile -Append
# "</body>" | Out-File -FilePath $DNSAnalysisReportFile -Append
"</html>" | Out-File -FilePath $DNSAnalysisReportFile -Append
############################################################

############################################################
# Final Tasks

# Disconnect-ExchangeOnline -Confirm:$False

Write-Host "DNS Analysis report is located here: $DNSAnalysisReportFile"
Write-Host "Transcript of this script is located here: $TranscriptFileName"
Write-Host ''
Write-Host 'Please send feedback to ' -ForegroundColor White -NoNewLine
Write-Host 'ScriptFeedback@PracticalPowerShell.Com' -ForegroundColor Green

############################################################
