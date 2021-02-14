#-------------------------------------------------------------------------------------------#
#                                       Change Log                                          #
#-------------------------------------------------------------------------------------------#
# V2 changes
# - Fixed ShowUser function
# - Fixed optionsmenu prompt loop
# - Prompt user for credentials only if they want IPDexport


# V3 changes
# - Implement WOL
# - Fix Selected Room condition
# - Fix RebootUnused (although it still doesn't work ¯\_(ツ)_/¯)
# - Add ListMachines function and option

# V4 changes
# - Replace RebootUnused with workflow. Works in parallel.
# - Minor changes to prompts for credentials. Checks for file etc.
# - Split code into methods

# V5 changes
# - Add option to change selected machines in menu
# - Implement message logged in users

# V6 changes
# - Add filtering of machines including dual boot Macs
# - [6.1] Added comments, code cleanup, and msg to run tool from ICTtools for WOL 

# V7 changes
# - Integrate generate system info code from HeathTools (output to grid-view only)

#-------------------------------------------------------------------------------------------#
#                                          To-Do                                            #
#-------------------------------------------------------------------------------------------#
# - Use workflow to run in parallel
# - Output to CSV and HTML
# - Cleanup code for systeminfo
# - Break code into separate files
# - Query for software deployments
# - Deploy software from SCCM
# - Deploy printers to logged-in users
# - Custom message [low priority]

#-------------------------------------------------------------------------------------------#

<#
    Print the hostnames of each computer in list.
#>
function ListMachines
{
    write-host `n"Listing selected machine/s"
    foreach ($_ in $List) {
        write-host "- $($_.'dns')"
    }
}

<#
    Show currently logged in users on each computer in list.
    Iterates through each computer, and retrieving the currently logged in user.
#>
function ShowUser
{
    foreach($computer in $List.dns)
    {
        ## If machine is offline, skip it
        if (!(Test-Connection -ComputerName $computer -Quiet -Count 1)){
            write-host "Machine $computer offline"
            continue
        }

        try {
            $loggedinuser = $(Get-WMIObject -ComputerName "$computer" -Class Win32_ComputerSystem | select username).username
            Write-Host "$computer - $loggedinuser"
        } catch {
            ## only time ive seen it throw an error is when the host machine is same as $computer
            ## leaving catch in there for further testing. if its the only case can exclude using if statement 
            ## this shouldn't matter since script *should* be run from icttools for WOL
            Write-Host "$computer - error (possible local machine)?"
        }
    }
}


<#
    Reboots computers in list that are online but don't have users logged in.
    Uses a workflow rather than function so that reboots can be done in parallel.
    Note that output won't be in sequence because of multithreading.
#>
workflow RebootUnused {
    Param
    (
        [parameter(mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $ComputerList,

        [int]
        $Throttle = 5,

        [int]
        $Delay = 5
    )

    foreach -parallel -ThrottleLimit $Throttle ($computer in $ComputerList) {
        ## only proceed if computer is online.
        if ((test-connection -ComputerName $computer -quiet -count 1)) {
            ## run following sequence in parallel.
            Sequence {
                InlineScript{
                    try {
                        ## check if here is someone currently logged in. only proceed with reboot if $null
                        $userstatus = $(Get-WMIObject -ComputerName "$using:computer" -Class Win32_ComputerSystem | select username).username
                        if ($userstatus -eq $null) {
                            Write-Host "$using:computer - Rebooting"
                            ## void tells script to not wait for response from Restart-Computer cmdlet
                            [void](Restart-Computer -ComputerName $using:computer -Force)
                        }
                        Start-Sleep -Seconds $using:Delay
                    } catch {
                        ## this should only run if running off own computer in theory.
                        Write-Host "$using:computer - error (possible local machine)?"                    
                    }
	            }
            }
        }
    }
}

<#
    Send WOL packets to offline machines.
    This usually only works from ICTtools. Calls WOLcmd.exe with arguments based on computer IPD setup and sends packet.
#>
function WakeOnLAN
{
    ## if tool isn't being run from ICTtools, throw warning that WOL may not work (even if wolcmd.exe is present).
    if ((Get-WMIObject -ComputerName localhost -Class Win32_ComputerSystem).name -ne "ICTTOOLS2016"){
        Write-Warning "Please run this tool in ICTtools for best results with WakeOnLan"
    }
    ## loop through each computer
    foreach ($_ in $List) {
        ## if it is online, skip it
        if (Test-Connection -ComputerName $_.dns -Quiet -Count 1){
            write-host "Machine $($_.'dns') already online"
        } else {
            ## otherwise run wolcmd.exe by passing MAC and IP address for this computer from IPDexport
            write-host "Machine $($_.'dns') offline. Running WOLcmd.exe"
            ## note that MAC has to be reformated to omit ":"
            ## subnet mask is always 255.255.255.0 and port is always 7
            $wolOutput = & C:\wolcmd\WolCmd.exe ($_.MACAddress -replace ':') $_.IPAddress 255.255.255.0 7
            write-host $wolOutput
        }
    }
}

function GetSystemInfo
{
    Write-Host `n"Generating SystemInfo Report. This may take a few minutes."
    
    ## container to store systeminfo for selected machines
    $systeminfo = @()

    ## if user hasn't already provided credentials, prompt for webadmin credentials and store.
    ## this is used for webscraping
    if ($global:credential -eq $null){
        $global:credential = CredentialPrompt
    }

    foreach ($_ in $List){
        ## create new object to contain system info for this particular computer
        $o = new-object  psobject

        ## add hostname to object
        $o | add-member -membertype noteproperty -name Computer -value $_.dns
        
        ## check if computer is responding then run checks
        if (test-connection -computername $_.dns -quiet -count 1)
        { 
            try {
                ## if WMI isn't working, kill the script. throws exception and skips to catch block.
                gwmi win32_computersystem -ComputerName $_.dns -ErrorAction Stop | out-null
            
                ## set status to on and add to object
                $o | add-member -membertype noteproperty -name Status -value "ON"

                ## get serialnumber through wmi and add to object
                $o | add-member -membertype noteproperty -name Serial -value (gwmi win32_bios -computername $_.dns).SerialNumber
  
                ## get uptime for computer
                $getuptime = (get-date) - (Get-WmiObject -Computername $_.dns  win32_operatingsystem | select @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).LastBootUpTime

                ## format uptime
                if ($getuptime.days-as [int] -gt 1){
                    $uptime = $getuptime.Days.ToString() + " Days"
                }
                elseif($getuptime.days-as [int] -eq 1){
                    $uptime = $getuptime.Days.Tostring() + " Day"
                }
                elseif($getuptime.hours-as [int] -eq 1){
                    $uptime = $getuptime.hours.Tostring() + " Hour"
                }
                else{
                    $uptime = $getuptime.hours.Tostring() + " Hours"
                }
                
                ## add uptime to object o
                $o | add-member -membertype noteproperty -name Uptime -value $uptime          

                ## get iver and add to object
                $o | add-member -membertype noteproperty -name Iver -value  (gwmi -computername $_.dns -query "select * from Win32_environment where username='<system>' and name='iver'").VariableValue

                ## get reimage date (osinstall date) and add to object
                $o | add-member -membertype noteproperty -name ReimageDate -value ([WMI]'').ConvertToDateTime((Get-WmiObject Win32_Registry -ComputerName $_.dns).InstallDate).tostring("dd-MMM-yyyy")
  
                ## get total disk size (capacity) and add to object
                $o | add-member -membertype noteproperty -name DiskSize -value ((gwmi Win32_LogicalDisk -computername $_.dns -Filter "DeviceID='C:'").size/1GB -as [int])
  
                ## get free disk space and add to object
                $o | add-member -membertype noteproperty -name FreeSpace -value ((gwmi Win32_LogicalDisk -computername $_.dns -Filter "DeviceID='C:'").FreeSpace/1GB -as [int])

                ## get percentage of free space and add to object
                $o | add-member -membertype noteproperty -name PercentFree -value (100 - ([math]::Round((1- (((gwmi Win32_LogicalDisk -computername $_.dns -Filter "DeviceID='C:'").FreeSpace/1GB -as [int]) / ((gwmi Win32_LogicalDisk -computername $_.dns -Filter "DeviceID='C:'").size/1GB -as [int]))) * 100)))

                ## set laschecked to current date and add to object
                $o | add-member -membertype noteproperty -name LastChecked -value (Get-Date -UFormat "%c")
                
                ## check equitrac installation and add to object
                if (Get-WmiObject -computer $_.dns -Class Win32_Service -Filter "Name='EQSharedEngine'" -ErrorAction SilentlyContinue) {
                    $o | add-member -membertype noteproperty -name Equitrac -value "Installed"
                } else {
                    $o | add-member -membertype noteproperty -name Equitrac -value "Not Installed"
                }

                ## check MyPC installation and add to object
                if (Get-WmiObject -computer $_.dns -Class Win32_Service -Filter "Name='MyPCClientNetworkSvc'" -ErrorAction SilentlyContinue) {
                    $o | add-member -membertype noteproperty -name MYPC -value "Installed"
                } else {
                    $o | add-member -membertype noteproperty -name MYPC -value "Not Installed"
                }

                ## check nvivo installation and add to object
                if (test-path "\\$($_.'dns')\C$\Program Files\QSR\NVivo 12\nvivo.exe") {
                    $NvivoVers = Get-Item "\\$($_.'dns')\C$\Program Files\QSR\NVivo 12\nvivo.exe"
                    $NvivoVers = ($NvivoVers.VersionInfo).Fileversion                
                    $o | add-member -membertype noteproperty -name NVIVO -value "$NvivoVers"
                } else {
                    $o | add-member -membertype noteproperty -name NVIVO -value "Not Installed" 
                }

                ## check rstudio installation and add to object
                if (test-path "\\$($_.'dns')\C$\Program Files\RStudio\bin\rstudio.exe") {                    
                    $RstudioVers = Get-Item "\\$($_.'dns')\C$\Program Files\RStudio\bin\rstudio.exe"
                    $RstudioVers = ($RstudioVers.VersionInfo).Fileversion                
                    $o | add-member -membertype noteproperty -name RStudio -value "$RstudioVers"
                } else {
                    $o | add-member -membertype noteproperty -name RStudio -value "Not Installed" 
                }

                ## check office installation and add to object
                if (test-path "\\$($_.'dns')\C$\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE") {                    
                    $WordVers = Get-Item "\\$($_.'dns')\C$\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE"
                    $WordVers = ($WordVers.VersionInfo).Fileversion                
                    $o | add-member -membertype noteproperty -name Office -value "$WordVers"
                } else {
                    $o | add-member -membertype noteproperty -name Office -value "Not Installed" 
                }
                    
                ## check endnote installation and add to object
                if (test-path "\\$($_.'dns')\C$\Program Files (x86)\EndNote X9\EndNote.exe") {                    
                    $EndNoteVers = Get-Item "\\$($_.'dns')\C$\Program Files (x86)\EndNote X9\EndNote.exe"
                    $EndNoteVers = ($EndNoteVers.VersionInfo).Fileversion                
                    $o | add-member -membertype noteproperty -name Endnote -value "$EndNoteVers"
                } elseif(test-path "\\$($_.'dns')\C$\Program Files (x86)\EndNote X8\EndNote.exe"){
                    $EndNoteVers = Get-Item "\\$($_.'dns')\C$\Program Files (x86)\EndNote X8\EndNote.exe"
                    $EndNoteVers = ($EndNoteVers.VersionInfo).Fileversion
                    $o | add-member -membertype noteproperty -name Endnote -value "$EndNoteVers"
                } else {
                    $o | add-member -membertype noteproperty -name Endnote -value "Not Installed" 
                }

                ## check photoshop installation and add to object
                if (test-path "\\$($_.'dns')\C$\Program Files\Adobe\Adobe Photoshop 2020\Photoshop.exe") {                    
                    $PhotoShopVers = Get-Item "\\$($_.'dns')\C$\Program Files\Adobe\Adobe Photoshop 2020\Photoshop.exe"
                    $PhotoShopVers = ($PhotoShopVers.VersionInfo).Fileversion                
                    $o | add-member -membertype noteproperty -name PhotoShop -value "$PhotoShopVers"
                } elseif(test-path "\\$($_.'dns')\C$\Program Files\Adobe\Adobe Photoshop CC 2019\Photoshop.exe") {
                    $PhotoShopVers = Get-Item "\\$($_.'dns')\C$\Program Files\Adobe\Adobe Photoshop CC 2019\Photoshop.exe"
                    $PhotoShopVers = ($PhotoShopVers.VersionInfo).Fileversion
                    $o | add-member -membertype noteproperty -name PhotoShop -value "$PhotoShopVers"
                } else {
                    $o | add-member -membertype noteproperty -name PhotoShop -value "Not Installed" 
                }

                ## check currently logged in user and add to object
                if ((gwmi win32_computersystem -computername $_.dns).username){
                    $o | add-member -membertype noteproperty -name CurrentUser -value (Get-WmiObject Win32_ComputerSystem -computername $_.dns | Select-Object -ExpandProperty UserName).Split('\')[1]
                } else {
                    $o | add-member -membertype noteproperty -name CurrentUser -value ""
                }

                ## get lease end date by webscraping IPD
                ## proceed if existing report csv exists
                If (test-path ".\csv\$global:ZoneName.csv") {
                    ## if so, import
                    $SysteminfoOld = Import-Csv .\csv\$global:ZoneName.csv
   
                    ## replacing contents of machines that are OFF  
                    ## iterate through each computer in old systeminfo csv
                    foreach ($_off in $SysteminfoOld) {
                        ## if current computer doesn't match iteration in csv, skip.
                        if (!($_off.computer -like $_.dns)){
                            continue;
                        }


                        ## if leaseexpiry isn't empty compare current date and lease expiry date and proceed.
                        if ( $_off.LeaseExpiry -ne '' ) {
                            ## convert off date string to date
                            $offdate = $_off.LeaseExpiry.Substring(0,7)
                            $offdate = ([datetime]::parseexact($offdate, 'yyyy-MM', $null))

                            ## convert current date string to date
                            $getdate = get-date
                            $_date = $getdate.ToString("yyyy-MM-dd")
                            $_date = $_date.Substring(0,7)
                            $_date = ([datetime]::parseexact($_date, 'yyyy-MM', $null))

                            ## if todays date is less then the expiry date in sheet, add it to object
                            if ($_date -lt $offdate){
                                $o | add-member -membertype noteproperty -name LeaseExpiry -value $_off.LeaseExpiry
                                break;
                            } 
                        }
                        ## otherwise scrape IP
                        ## HREF is pulling the associated IPD address from the object record 
                        $web = Invoke-WebRequest -Credential ($credential) $_.HREF 
                        if ($web.Content -match "The lease expires on (?<content>.*)</font></b>") {
                            $o | add-member -membertype noteproperty -name LeaseExpiry -value $matches['content']
                        } elseif ($web.content -match "The lease expires on (?<content>.*)&nbsp") {
                            $o | add-member -membertype noteproperty -name LeaseExpiry -value $matches['content']
                        }
                        break;
                    }
                } else {
                    ## if there is no existing report just pull from IPD.
                    ## HREF is pulling the associated IPD address from the object record 
                    $web = Invoke-WebRequest -Credential ($credential) $_.HREF 
                    if ($web.Content -match "The lease expires on (?<content>.*)</font></b>") {
                        $o | add-member -membertype noteproperty -name LeaseExpiry -value $matches['content']
                    }
                    elseif ($web.content -match "The lease expires on (?<content>.*)&nbsp") {
                        $o | add-member -membertype noteproperty -name LeaseExpiry -value $matches['content']
                    }
                }
            } Catch [Exception] {
                if ($_.Exception.GetType().Name -eq "COMException") {
                    $o | add-member -membertype noteproperty -name Status -value "WMI ERROR"
                }
            }
        } else {
            ## code below only executes if machine is offline.
            $o | add-member -membertype noteproperty -name Status -value "OFF"
        }

        if ($o.Status -ne "ON") {
            $o | add-member -membertype noteproperty -name CurrentUser -value ""
            $o | add-member -membertype noteproperty -name Iver -value ""
            $o | add-member -membertype noteproperty -name ReimageDate -value ""
            $o | add-member -membertype noteproperty -name Serial -value ""
            $o | add-member -membertype noteproperty -name Office -value ""
            $o | add-member -membertype noteproperty -name PhotoShop -value ""
            $o | add-member -membertype noteproperty -name Equitrac -value ""
            $o | add-member -membertype noteproperty -name MYPC -value ""
            $o | add-member -membertype noteproperty -name NVIVO -value ""
            $o | add-member -membertype noteproperty -name RStudio -value ""
            $o | add-member -membertype noteproperty -name Endnote -value ""
            $o | add-member -membertype noteproperty -name DiskSize -value ""
            $o | add-member -membertype noteproperty -name FreeSpace -value ""
            $o | add-member -membertype noteproperty -name PercentFree -value ""
            $o | add-member -membertype noteproperty -name LastChecked -value ""
            $o | add-member -membertype noteproperty -name LeaseExpiry -value ""
        }
        ## append object o to systeminfo
        $systeminfo += $o
    }

    $systeminfo | select Computer,Status,CurrentUser,Iver,ReimageDate,Serial,Office,PhotoShop,Equitrac,MYPC,NVIVO,RStudio,EndNote,DiskSize,FreeSpace,PercentFree,LastChecked,LeaseExpiry | Out-GridView
}

<#
    Display a popup message on each computer
    Currently only has preset options
    Can add custom message in future if need be.
#>
function MessageLoggedInUsers
{
    ## do while loop to repeat until a valid message is selected to broadcast
    $message = $null;
    do {
        $option1 = "The lab will be closing in 15 minutes."
        $option2 = "Please maintain social distancing in this lab."
        $option3 = "Please maintain considerate levels of noise in the lab."
        Write-Host `n"What message would you like to send?"
        Write-Host "1: `"$option1`""
        Write-Host "2: `"$option2`""
        Write-Host "3: `"$option3`""
        Write-Host "C: Cancel."
        $sel = Read-Host "Please make a selection"
        switch ($sel)
        {
            "1"{$message = $option1}
            "2"{$message = $option2}
            "3"{$message = $option3}
            "c"{
                Write-Host `n"Cancelled Messaging. Returning to menu."
                return
            }
            default {
                Write-Host `n"$Sel IS NOT A VALID OPTION"
                pause
            }
        }
    } while ($message -eq $null)

    ## loop through each computer in list and broadcast message if machine is online and there is someone logged in.
    foreach($computer in $List.dns)
    {
        if ((test-connection -ComputerName $computer -quiet -count 1)) {
            try {
                $userstatus = $(Get-WMIObject -ComputerName "$computer" -Class Win32_ComputerSystem | select username).username                    
                if($userstatus -ne $null){
                    Write-Host "Sent Message: `"$message`" to $computer"
                    [void](Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList "msg * $message" -ComputerName $computer)
                }
            } catch {
                Write-Host "$using:computer - error (possible local machine)?"
            }
	    }
    }
}

<# 
    Get IPDExport file needed to run this tool.
    Checks if file already exists, asks user if they want to update if so, and sends web request to retrieve the export.
#>
function GetIPDExport
{
    $IPDDownload = "x"
    while ($IPDDownload -ne "Y"-and $IPDDownload -ne "N")
    {
        cls
        Write-host "              <##### LAB ADMIN TOOL #####>"`n

        ## check if file already exists in folder
        if (Test-Path -Path ".\ipd.csv" -PathType leaf){
            ## if so get last modified date to display and prompt user to ask if they want to update the file.
            $lastModifiedDate = (Get-Item ".\ipd.csv").LastWriteTime
            Write-Host "IPD file last modified on $lastModifiedDate"
            $IPDDownload = [string](Read-Host -Prompt 'Download latest IPD list? Note you will be prompted for webadmin credentials. Type "Y" for Yes, or "N" for No ')
        } else {
            ## if not, it is necessary to download the file so set variable to Y. this will auto prompt for webadmin credentials in next block of code.
            Write-Host "No IPD file found!"
            $IPDDownload = "Y"
        }

        ## only runs if user wants to download a new copy or if no ipd file exists at all
        if($IPDDownload -eq "Y")
        {    
            $global:credential = CredentialPrompt
            try {
                ## create webrequest for IPD export and download
                $output = Invoke-WebRequest -Uri "https://webadmin.aut.ac.nz/admin/db/ipd/ServiceNowExport.cgi?view=ipd" -OutFile ".\ipd.csv" -credential $credential
            }
            catch {
                Write-Host "`nError! Unable to retrieve file. Please check your credentials."
                $IPDDownload = "x";
                pause;
            }
        }
    }
}

<#
    Prompt user for network credentials.
    Used to query IPD (for export and scraping).
    Returns credentials.
#>
function CredentialPrompt {
    ## get webadmin credentials to be used for IPD enquiry
    $message = "Please enter your network credentials"
    ## code below retrieves currently logged in user and modifies string to pass to credential prompt (so user only has to input password).
    ## note this only works if tool is NOT running in ICTtools.
    $username = (Get-WMIObject -ComputerName localhost -Class Win32_ComputerSystem | select username).username
    $username = $username -replace 'AUTUNI\\', ""
    ## display prompt for credentials
    return (get-credential -Message $message -UserName $username)
}

<#
    Prompts user to set criteria of machines they want to select
    This will be a sequence of characters (e.g. "ma202-")
    That will then get all machines matching that hostname from ipd.csv and populate a list.
    After that, the list is filtered through to remove invalid machines (printers, kiosks, iMacs, etc.).
#>
function SelectMachines {
    $List = $null
    ## Query user valid input until something is found in IPD list
    do 
    {
        cls
        Write-host "              <##### LAB ADMIN TOOL #####>"`n
        Write-Host "Enter room name or computer name to check then press 'ENTER'"`n
        Write-Host "(Be specific with your search criteria ie. 'wa414b-' )"`n

        $Query = [string](Read-Host -Prompt 'Please enter search criteria ')
        $global:ZoneName = $Query
        write-host `n"Searching IPD list for $Query ...."
        
        $IPDlist = Import-Csv .\ipd.csv
        ## grabs the dns, ip, mac, and hosttype for each machine that has a dns that begins with the pattern the user enters
        $List = $IPDList | Where-Object {$_.dns -like "$Query*"} | select dns, IPAddress, MACAddress, HostType, HREF | sort dns
        
        ## initialise a separate list as an array. this will be used to populate the machines that pass through the filtered criteria.
        $FilteredList = @()
        
        foreach ($_ in $List)
        {
            ## check if device is an access point, kiosk, printer, staff machine, laptop, etc.
            if ($_.dns -like "*mfd*" -or $_.dns -like "*avctl*" -or $_.dns -like "*book*" -or $_.dns -like "*kiosk*" -or $_.dns -like "*lt-*" -or $_.dns -like "*p455*" -or $_.dns -like "*ws" -or $_.dns -like "*ls" <#-or $_[$i].dns -like "*wc" some machines have this in name#>) 
            {
                ## if so, skip adding it to the filteredlist and skip to the next machine in list. 
                continue;
            } 

            ## check if device is a mac machine
            if ($_.HostType -like "*mac*"){
                ## can't exclude straight away because machine could be dual boot in windows
                ## ping machine to check if online.
                if ((test-connection -ComputerName $_.dns -quiet -count 1) -eq $false) {
                    ## if unreachable, cant check wmi so skip this machine.
                    Write-Warning "MAC: $($_.dns) not reachable. Excluded from list."
                    continue
                }
                try {
                    ## query wmi object. generic query just to see if pc is in windows.
                    ## if it fails, will skip to catch block and skip machine. else add to list.
                    Get-WMIObject -ComputerName "$($_.dns)" -Class Win32_ComputerSystem -ErrorAction Stop
                }
                catch {
                    Write-Warning "MAC: $($_.dns) WMI exception. Excluded from list."
                    continue;
                }
            }

            ## if the computer passes the criteria, it is appended to the filteredlist
            $FilteredList += $_
        }

        ## replace query list with filtered computer list.
        $List = $FilteredList

        ## if the list is now empty, user will need to re-enter search criteria.
        ## else can exit loop and proceed.
        if ($List.Length -eq 0) 
        {
            Write-Host "No machines matching criteria `"$Query`" found. Please try again"`n
            $List = $null;
            pause
        }
    } while ($List -eq $null)

    return $List
}

<#
    Prints options to user.
    Used in menu once 1 or more valid devices have been selected.
#>
function Show-OptionsMenu
{
    param ([string]$Title = 'LAB ADMIN TOOL')
    cls
    if ($List.count -gt 1)
    {
        Write-host "Selected Room: $($global:ZoneName)"`n
    } else {
        Write-host "Selected machine: $($global:ZoneName)"`n
    }
     Write-Host "================ $Title ================"
     Write-Host "1: List machines"
     Write-Host "2: Check logged in users"
     Write-Host "3: Reboot machines with no users logged in"
     Write-Host "4: Wake on Lan"
     Write-Host "5: Message logged in users"
     Write-Host "6: Get System Info"
     Write-Host "C: Change selected machines"
     Write-Host "Q: Press 'Q' to quit."
}


<#
    Main method for this tool.
    Calls the different functions to initialise this tool and handle user input.
    Continues looping until the user decides to quit the tool.
#>
function Main {
    GetIPDExport
    $List = SelectMachines
    $sel= $null
    do
    {
        Show-OptionsMenu
        $sel = Read-Host "Please make a selection"
        switch ($sel)
        {
            "1"{ListMachines}
            "2"{ShowUser}
            "3"{RebootUnused -ComputerList $List.dns}
            "4"{WakeOnLAN}
            "5"{MessageLoggedInUsers}
            "6"{GetSystemInfo}
            "c"{$List = SelectMachines}
            "q"{
                Write-Host `n"Exiting Program"
                exit
            }
            default {
                Write-Host `n"$Sel IS NOT A VALID OPTION"
            }
        }
        pause
    } while($true)
}

## call Main to run tool
Main