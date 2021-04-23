# Clear the screen:
CLS

#Transcript
$Date = get-date -UFormat %m.%d.%y-%H.%M%p
Start-Transcript OneDriveCleanup-$Date.txt

# Inmport the SharePoint PnP Module:
Import-Module SharePointPnPPowerShellOnline

# Script Version
# 1.06
# Author: Damian Scoles
# Purpose: Remove files from OneDrive based on Compliance Search in Security and Compliance Center

# Begin the script
Write-Host ' '
Write-Host '--------------------------------------' -ForegroundColor white
Write-Host ' BEGIN - OneDrive File Removal Script' -ForegroundColor Magenta
Write-Host '--------------------------------------' -ForegroundColor White
Write-Host ' '

# Variables to populate:
$SharePointURL = 'https://scoles-admin.sharepoint.com'
# $SharePointURL = 'https://<tenant domain>-admin.sharepoint.com'

# $Credentials = Get-Credential
$GAUPN = Read-Host "Please enter your Global Admin account UPN"
$Password = Read-Host -assecurestring "Please password for Global Admin account specified above"
$Credentials = New-Object -typeName System.Management.Automation.PSCredential -argumentlist $GAUPN, $Password
Write-Host ' '

# Connect to SPO
Write-Host "`nConnecting to SharePoint Online ..." -ForegroundColor Green
Connect-SPOService -Url $SharePointURL -Credential $Credentials

# Get CSV File.  Two options -->  (1) As for the file with Read-Host or (2) Use a default name always:
$CSVName = Read-Host "Please specify a CSV file to import [i.e. Results.csv]"
# $CSVName = 'Results.csv'

# Import the CSV file:
 $CSV = Import-Csv $CSVName

# Sort Results file, pulling out User Location and File Name
$Table = Foreach ($Line in $CSV) {

    $User = $Line.Location
    $FullFilePath = $Line."Original Path"
    $Type = $Line.Type
    $File = $FullFilePath.Split('/')[-1]

    New-Object -TypeName PSCustomObject -Property @{
        User = $User
        File = $File
    }
} 

# Sort the Table variable by User to keep OneDrive connections simple:
$SortedResults = $Table | Sort-Object User,File

# Removal Part of the Script:
$Counter = 0
$RemovalList = @()
$LastOneDrive = $null
$Loop = 1
$TotalLoops = ($SortedResults).Count
$Date = get-date -UFormat %m.%d.%y-%H.%M%p
$DeletedFileReport = "FilesRemovedByScript-$Date.TXT"
$NotDeletedFileReport = "FilesNotRemovedByScript-$Date.TXT"

# File HEaders
$Line = "ID,User,File" | Out-File $DeletedFileReport
$Line = "ID,User,File" | Out-File $NotDeletedFileReport

Foreach ($Line in $SortedResults) {
    
    # Variables For Loop
    $UserOneDrive = [string]$Line.User
    $File = $Line.File

    # File Processing Function
    Function FileProcessing ($counter) {

        Write-Host "These files found in OneDrive at this URL - $UserOneDrive. Please selct which ones to remove." -ForegroundColor White
        Write-Host " **## CAUTION ##**" -ForegroundColor Red -NoNewline
        Write-Host " - Files seleected will be " -ForegroundColor White -NoNewline
        Write-host " - DELETED - " -ForegroundColor Red -NoNewline
        Write-host "proceed carefully!" -ForegroundColor Yellow
        Start-Sleep 5

        # Output file list to remove
        $FilesToRemove = $RemovalList | Out-GridView -PassThru

        # List Files:
        Write-Host "Files Selected to be removed are:"

        Foreach ($FileToRemove in $FilesToRemove) {

            $ID = [string]$FileToRemove.ID
            $File = $FileToRemove.File
            $User = $FileToRemove.User

            # Multiple ID Check
            If ($ID -like "* *")  {
                $MultipleID = $ID.Split(' ;')
                Foreach ($SubID in $MultipleID) {
                    # Write-Host "ID = $ID , User = $User and File = $File"
                    Write-Host " "
                    Write-Host "Removing" -NoNewLine
                    Write-Host " $File " -ForegroundColor Yellow -NoNewLine
                    Write-Host "from " -NoNewLine
                    Write-Host "$User" -ForegroundColor Yellow -NoNewLine
                    Write-Host " with ID of " -NoNewLine
                    Write-Host "$SubID ..." -ForegroundColor Yellow
                    $ConfirmRemoval = Read-Host " Confirm file removal [y or n] "
                    If ($ConfirmRemoval -eq 'y') {
                        # What If Mode:
                        Write-Host "Remove-PnPListItem -List Documents -Identity $SubID" -ForegroundColor Red

                        # Real deletion, no warning, no what it.  G-O-N-E:
                        # Remove-PnPListItem -List Documents -Identity $SubID

                        # Export results to a file:
                        $Line = "$SubID,$User,$File" | Out-File $DeletedFileReport -Append 
                    } Else {
                        Write-Host " *** FILE WAS NOT DELETED **" -ForegroundColor Yellow

                        # Export results to a file:
                        $Line = "$SubID,$User,$File" | Out-File $NotDeletedFileReport -Append 
                    }
                }

            } Else {
                
                # Single ID
                # Write-Host "ID = $ID , User = $User and File = $File"
                Write-Host " "
                Write-Host "Removing" -NoNewLine
                Write-Host " $File " -ForegroundColor Yellow -NoNewLine
                Write-Host "from " -NoNewLine
                Write-Host "$User" -ForegroundColor Yellow -NoNewLine
                Write-Host " with ID of " -NoNewLine
                Write-Host "$ID ..." -ForegroundColor Yellow
                $ConfirmRemoval = Read-Host " Confirm file removal [y or n] "
                If ($ConfirmRemoval -eq 'y') {
                    # What If Mode:
                    Write-Host "Remove-PnPListItem -List Documents -Identity $ID" -ForegroundColor Red

                    # Real deletion, no warning, no what it.  G-O-N-E:
                    # Remove-PnPListItem -List Documents -Identity $ID

                    # Export results to a file:
                    $Line = "$ID,$User,$File" | Out-File $DeletedFileReport -Append 
                } Else {
                    Write-Host " *** FILE WAS NOT DELETED **" -ForegroundColor Yellow

                    # Export results to a file:
                    $Line = "$ID,$User,$File" | Out-File $NotDeletedFileReport -Append 
                }
            }

        }

    }

    # Check if new user One Drive, if so, call processing function and then connect
    If (($LastOneDrive -ne $UserOneDrive) -and ($Counter -gt 0)) {

        FileProcessing

        # Clear Variables
        $RemovalList = $null
        $RemovalList = @()
        $FilesToRemove = $null

        # Reset Counter
        $Counter = 0
       
    } 
  
    # Grant Permissions for connecting - First loop for User One Drive Only
    If ($Counter -eq 0) {
        Try {
            Set-SPOUser -Site $UserOneDrive -LoginName $GAUPN -IsSiteCollectionAdmin $True -ErrorAction Stop
        } Catch {
            Write-Verbose 'Error adding permisisons to SPO drive'
        }
    }

    # Connect to new OneDrive:
    If ($Counter -eq 0) {
        Write-Host ''
        Write-Host 'Connecting to SharePoint PnP service ...' -ForegroundColor Cyan
        $Connect = $True
        Try {
            Connect-PnPOnline -Url $UserOneDrive -Credentials $Credentials -ErrorAction Stop
        } Catch {
            Write-Host "Failed to connect to $UserOneDrive"
            $Connect = $False
        }
    }

    # Get a list of files for this new OneDrive:
    $RemovalList += If ($Connect) {
        $ID = ((Get-PnPListItem -List Documents -Fields 'ID').FieldValues | Where {$_.FileRef -like "*$File"}).ID

        # Create List of files:
        New-Object -TypeName PSCustomObject -Property @{
            User = $UserOneDrive
            File = $File
            ID = $ID
        }
    }

    # End of the loop tasks
    $Counter ++
    $LastOneDrive = $UserOneDrive

    If ($Loop -eq $TotalLoops){

        FileProcessing $Counter
    }

    $Loop++
}

# Stopping Transcript
Stop-Transcript

# Output files:
Write-Host ''
Write-Host ''
Write-Host 'Output files generated:' -ForegroundColor Green
Write-Host '-------------------------------------------------------------' -ForegroundColor White
Write-Host " * Files removed by the script     -->" -ForegroundColor White -NoNewline
Write-Host " $DeletedFileReport." -ForegroundColor Yellow
Write-Host " * Files NOT Removed by the script -->" -ForegroundColor White -NoNewline
Write-Host " $NotDeletedFileReport." -ForegroundColor Yellow
Write-Host ''
Start-Sleep 5

# Closeout:
Write-Host ' '
Write-Host '------------------------------------' -ForegroundColor white
Write-Host ' END - OneDrive File Removal Script' -ForegroundColor Magenta
Write-Host '------------------------------------' -ForegroundColor White
Write-Host ' '