#    Simple .NET Check Script for Exchange Server 2013 / 2016 / 2019
#    Version 1.1
#    by Damian Scoles
#    Blog:  https://www.powershellgeek.com/
#

$found = $false

# Check for .NET Version
write-host "Checking the version of .NET installed on this server....." -foregroundcolor Yellow
write-host " "
start-sleep 2

# Check .Net version:
$val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release"

# Display which version this is:
if ($val.Release -lt "379893") {
	write-host "Less than .NET 4.5.2 is " -nonewline 
	write-host "installed!" -ForegroundColor red -nonewline
	$Found = $True
}
if ($val.Release -eq "379893") {
    write-host ".NET 4.5.2 is " -nonewline -foregroundcolor white
	write-host "installed." -ForegroundColor green -NoNewline
	$Found = $True
}
if ($val.Release -eq "394271") {
    write-host ".NET 4.6.1 is " -nonewline -foregroundcolor white
	write-host "installed." -ForegroundColor green -
	$Found = $True
}
if ($val.Release -eq "394806") {
    write-host ".NET 4.6.2 is " -nonewline -foregroundcolor white
	write-host "installed." -ForegroundColor green -nonewline
	$Found = $True
}
if ($val.Release -eq "460805") {
   	write-host ".NET 4.7 is " -nonewline -foregroundcolor white
	write-host "installed." -ForegroundColor green -nonewline
	$Found = $True
}
if ($val.Release -eq "461310") {
   	write-host ".NET 4.7.1 is " -nonewline -foregroundcolor white
	write-host "installed." -ForegroundColor green -nonewline
	$Found = $True
}
if ($val.Release -eq "461814") {
    write-host ".NET 4.7.2 is " -nonewline -foregroundcolor white
	write-host "installed." -ForegroundColor green -nonewline
	$Found = $True
}
if ($val.Release -eq "528209") {
    write-host ".NET 4.8.0 is " -nonewline -foregroundcolor white
	write-host "installed." -ForegroundColor green -nonewline
	$Found = $True
}



# Display error if version not found.
if ($found -eq $false) {
    write-host "ERROR: Could not find the proper version of .NET installed on your server" -ForegroundColor Red
}