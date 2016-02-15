<#
.SYNOPSIS

Host Discovery
version 1.0
Author: Rob Vance (http://www.ngosecurity.com)

	The MIT License
	-----------------------------------------------------------------------
	Copyright (c) 2015 NGO Security Solutions
	Permission is hereby granted, free of charge, to any person obtaining a 
	copy of this software and associated documentation files (the `"Software`"), 
	to deal in the Software without restriction, including without limitation 
	the rights to use, copy, modify, merge, publish, distribute, sublicense, 
	and/or sell copies of the Software, and to permit persons to whom the 
	Software is furnished to do so, subject to the following conditions:
	The above copyright notice and this permission notice shall be included 
	in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED `"AS IS`", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
	DEALINGS IN THE SOFTWARE.

.DESCRIPTION

Completes a validation assessment by:
    1.	Verifying the SSL Certificate; expiration date; susceptibility to SSL vulnerabilities 
        such as FREAK, POODLE, Heartbleed; renegotiation; key size; allowed protocols; supported 
        cryptography; CRL status and enabled mitigating controls
    2.	Identifying Open TCP Ports
    3.  Identifying Started and stopped Services 
    4.  Grabbing the Banner of listening ports
    5.  Configuration of the Web Server; dangerous HTTP methods; XML
    6.  Searches through the Security Event Logs for Event IDs of interest
    7.  Gathering Host Details; computer details; patches; user accounts; shares (SMB)
    8.  Identify if Tanium and/or Splunk is installed
    9.  Identify if antivirus is installed
    10. Test if anonymous access to the registry is permitted
    11. Test if commands can be executed as anonymous user
    12. Test if files can be uploaded by anonymous user

To see how to use run the help

PS H:\> .\$scriptname -h | -help

.NOTES

Prerequisites:

    Windows versions of -
        SSLScan
        OpenSSL
        Curl

Might need to run:
Set-ExecutionPolicy Unrestricted

Without admin access
powershell.exe -ExecutionPolicy Unrestricted

Look at:

https://pscx.codeplex.com/releases/view/133199
http://www.hanselman.com/blog/ScottHanselmans2014UltimateDeveloperAndPowerUsersToolListForWindows.aspx
Chocolatey
@powershell -NoProfile -ExecutionPolicy unrestricted -Command "iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))" && SET PATH=%PATH%;%systemdrive%\chocolatey\bin

.TODO

Additional functionality - Allow user to use a different domains.txt and ports.txt
                           files
                           Insert data into SQL Server
#>
[cmdletbinding()]
param(
    [switch]$v,
    [switch]$vv,
    [switch]$vvv,
    [switch]$q,
    [array]$hosts,
    [array]$ports,
    [string]$datafile,
    [switch]$updatedata,
    [string]$listname,
    [string]$portTHLD,
    [switch]$testall,
    [switch]$journal,
    [switch]$bitset,
    [switch]$tsttree,
    [switch]$tstdmp,
    [switch]$getver,
    [switch]$chkprocess,
    [switch]$banner,
    [switch]$h,
    [switch]$help,
    [switch]$setup
)
if($v -eq $true -or $vv -eq $true) {  Write-Host "Hello! Starting the script, but first need to do some house keeping..." }
#Before Starting Remove all previous set variables
if($v -eq $true -or $vv -eq $true) {  Write-Host "Clearing any lingering varialbes" }
$excludelst = "v,vv,vvv,q,hosts,ports,datafile,listname,portTHLD,testall,journal,tstdmp,getver,chckprocess,h,help,setup"
Get-Variable -Exclude $excludelst | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue }
#
####> Init Functions
#
# Check what version of Powershell is running
$global:psvers = $PSVersionTable.PSVersion.Major
# For use in the USAGE function
$global:scriptname = $MyInvocation.MyCommand.Name
#
function wiseguy() { 
    [string[]]$quoteList =
    "I changed my password everywhere to `'incorrect.`' That way when I forget it, it always reminds me, `'Your password is incorrect.`'","Don`'t worry if plan A fails, there are 25 more letters in the alphabet.", "To err is human... to really foul up requires the root password.","If at first you don't succeed; call it version 1.0","My software never has bugs. It just develops random features.","The only problem with troubleshooting is that sometimes trouble shoots back.","If brute force doesn't solve your problems, then you aren't using enough.", "Microsoft: You've got questions. We've got dancing paperclips.","I'm not anti-social; I'm just not user friendly",
    "After Perl everything else is just assembly language.","Difference between a virus and windows ? Viruses rarely fail.","1f u c4n r34d th1s u r34lly n33d t0 g3t a l!fe.",“Don’t worry if it doesn’t work right. If everything did, you’d be out of a job.”,“Fine, Java MIGHT be a good example of what a programming language should be like. But Java applications are good examples of what applications SHOULDN’T be like.”,"Always code as if the guy who ends up maintaining your code will be a violent psychopath who knows where you live." 
    #Choosing One Randonm Quote     
    $randomQuote = $quoteList | Get-Random -Count 1 
    # Writing Quote 
    Write-host $randomQuote -ForegroundColor black 
}
function usage() { 
$helpfile = "
.SYNOPSIS

Host Discovery
version 1.0
Author: Rob Vance (http://www.ngosecurity.com)

	The MIT License
	-----------------------------------------------------------------------
	Copyright (c) 2015 NGO Security Solutions
	Permission is hereby granted, free of charge, to any person obtaining a 
	copy of this software and associated documentation files (the `"Software`"), 
	to deal in the Software without restriction, including without limitation 
	the rights to use, copy, modify, merge, publish, distribute, sublicense, 
	and/or sell copies of the Software, and to permit persons to whom the 
	Software is furnished to do so, subject to the following conditions:
	The above copyright notice and this permission notice shall be included 
	in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED `"AS IS`", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
	DEALINGS IN THE SOFTWARE.

.DESCRIPTION

Completes a validation assessment by:
    1.	Verifying the SSL Certificate; expiration date; susceptibility to SSL vulnerabilities 
        such as FREAK, POODLE, Heartbleed; renegotiation; key size; allowed protocols; supported 
        cryptography; CRL status and enabled mitigating controls
    2.	Identifying Open TCP Ports
    3.  Identifying Started and stopped Services 
    4.  Grabbing the Banner of listening ports
    5.  Configuration of the Web Server; dangerous HTTP methods; XML
    6.  Searches through the Security Event Logs for Event IDs of interest
    7.  Gathering Host Details; computer details; patches; user accounts; shares (SMB)
    8.  Identify if Tanium and/or Splunk is installed
    9.  Identify if antivirus is installed
    10. Test if anonymous access to the registry is permitted
    11. Test if commands can be executed as anonymous user
    12. Test if files can be uploaded by anonymous user

.PARAMETER v

Be verbose and display all kinds of useful information. Use more than once (-vv) for greater verbosity, and heck with it display all -vvv

.PARAMETER q

Display nothing to the terminal

.PARAMETER hosts

To assess one or more hosts

.PARAMETER ports

Using specified port or ports

.PARAMETER capsmb

Enumerate everything SMB has to offer

.PARAMETER vulnchk

Run vulnerability assessment checks

.PARAMETER ssl

Output the X509 info into a csv formatted file

.PARAMETER dpath

Copy the final report to the following designation

.PARAMETER debugger

Various Test points and time elasped check

.EXAMPLE

To run the scan using the hosts and ports defined in the domains.txt and ports.txt file 
found in the <drive>:\data\ directory

PS H:\> .\$scriptname

To Verbosely display everything to the terminal

PS H:\> .\$scriptname -v | -vv

To scan a single host, but use all of the ports defined in the ports.txt file

PS H:\> .\$scriptname -hosts hostname

To scan a single port, but use all of the hosts defined in the domains.txt file

PS H:\> .\$scriptname -ports 80

To scan a single host, and a single port

PS H:\> .\$scriptname -hosts hostname -ports 80

To scan multiple hosts and ports and ignore the domains.txt and ports.txt files

PS H:\> .\$scriptname -hosts host,host2,host3 -ports 80,443,8080

To verbosely display and scan multiple host and ports

PS H:\> .\$scriptname -v -hosts host,host2,host3 -ports 80,443,8080

To verbosely display and test for the potential vunerability

To run the vulnerability checks

PS H:\> .\$scriptname -vulnchk

To scan with any combination of parameters witout displaying it to the terminal

PS H:\> .\$scriptname <options> -q

To verbosely display and scan multiple host, ports and output X509 info into a CSV file

PS H:\> .\$scriptname -v -hosts host,host2,host3 -ports 80,443,8080 -ssl

To copy the file to another destination, (other than locally)

PS H:\> .\$scriptname -v -hosts host,host2,host3 -ports 80,443,8080 -ssl -dpath \\fileserver\folder
"
Write-Host $helpfile
exit
}
if($v -eq $true -and $vv -eq $true) { wiseguy; Write-Host "`nWhat went wrong: Incorrect usage of Verbose switches, just need one"; exit }
if($v -eq $true -and $q -eq $true) { wiseguy; Write-Host "`nWhat went wrong: Incorrect usage of Verbose and Quiet switches"; exit }
if($vv -eq $true -and $q -eq $true) { wiseguy; Write-Host "`nWhat went wrong: Incorrect usage of Verbose and Quiet switches"; exit }
if($q -eq $true) {
    $v = $false
    $vv = $false
    Write-Host "`nQuiet Mode"
}
#
if($h -eq $true -or $help -eq $true) { usage }
#
function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value;
    if($Invocation.PSScriptRoot) {
        return $Invocation.PSScriptRoot;
    } elseif($Invocation.MyCommand.Path) {
        return Split-Path $Invocation.MyCommand.Path
    } else {
        return $Invocation.InvocationName.Substring(0,$Invocation.InvocationName.LastIndexOf("\"));
    }
}
#
####> Preset Defaults
#
# Paths
$pwd = Get-ScriptDirectory
if($pwd.Split("\").count -eq 2) { $pwd = $pwd -replace "\\","\" }
#
$rawfile = $pwd + "\rawdata"
if($rawfile.Split("\").count -eq 2) { $rawfile = $rawfile -replace "\\","\" }
$rptfile = $pwd + "\report"
if($rptfile.Split("\").count -eq 2) { $rptfile = $rptfile -replace "\\","\" }
# Set default data path
if($datafile -ne $true) { $datafile = $pwd + "\data" }
if($datafile.Split("\").count -eq 2) { $datafile = $datafile -replace "\\","\" }
# Files
$domsname = "domains.txt"
$portname = "ports.txt"
#
####> Network Share
#
#$nwROOT = "\\$netpath\tts\Rptcde"
#$nwDATA = "\\$netpath\tts\Rptcde\data"
#$nwRAWDATA = "\\$netpath\tts\Rptcde\rawdata"
#$nwREPORT = "\\$netpath\tts\Rptcde\report"
#> Prep
#if($v -eq $true -or $vv -eq $true) {  Write-Host "Grabing the today's list of systems to assess..." }
#$domfile = "$datafile\$domsname"
#if(Test-Path $domfile) { Remove-Item -Force $domfile }
#$fd = Get-Date -Format 'Mdyyyy'
#if((Test-Path (Get-ChildItem -Path $nwData\domains* -Filter "*_$fd`_*").FullName) -eq $true) { gc $nwData\domains_$fd`_T*.txt | Out-File $domfile -Append }
# Port scanning limiter
if($portTHLD-ne $true) { $portTHLD= 20 }

#
#>>>>>>>>>>>>>>>>>>>>>>>>>      Required executables (i.e., tools)      <<<<<<<<<<<<<<<<<<<<<<<<#
#
Function Get-MyModule($name){
# Checks for Module Dependencies 
    if(-not(Get-Module -Name $name)) { 
        if(Get-Module -ListAvailable | Where-Object { $_.name -eq $name }) { 
            Import-Module -Name $name 
            $true 
        } else { $false }
    } else { $true } 
} 

function unzip($file, $destination) {
    $shell = new-object -com shell.application
    $zip = $shell.NameSpace($file)
    foreach($item in $zip.items()) {
        $shell.Namespace($destination).copyhere($item)
    }
}

#
#>>>>>>>>>>>>>>>> No changes to any parameters are necessary beyond this point <<<<<<<<<<<<<<<<<#
#
$getdomslstfrom = "$nwDATA\$domsname"
$getportlstfrom = "$nwDATA\$portname"
if($updatedata -eq $true) {
    Write-Host "Updating domains.txt and ports.txt in the $datafile directory from the $nwDATA"
    if(!(Test-Path -Path $nwDATA)) {
        Write-Warning "Okay, this is embrassing, but for some reason (possibly related to access rights), can't seem to access $nwDATA"
        Write-Host "Checking to see if there are local copies of the necessary files..."
        if(!(Test-Path -Path "$datafile\$domsname")) { 
            Write-Host "Could not find a local copy of the $datafile\$domsname as well."
            $localdoms = $false
        } else {
            Write-Host "A local copy of $datafile\$domsname is avilable. Either continue or exit out of this script to make the necessary manual corrections."
            $localdoms = $true
        }
        if($hosts -eq $false -and $localdoms -eq $false) {
            Write-Host "Or consider using the -hosts host1,...,hostn switch. See Usage for more information about the -hosts switch."
            exit
        }
        if(!(Test-Path -Path "$datafile\$portname")) { 
            Write-Host "Could not find a local copy of the $datafile\$portname as well."
            $localport = $false
        } else {
            Write-Host "A local copy of $datafile\$portname is avilable. Either continue or exit out of this script to make the necessary manual corrections."
            $localport = $true
        }
        if($ports -eq $false -and $localport -eq $false) {
            Write-Host "Or consider using the -ports port1,...,portn switch. See Usage for more information about the -ports switch."
            exit
        }
    } else {
        Copy-Item -Path $getdomslstfrom -Destination $datafile -Force -ErrorAction SilentlyContinue
        Copy-Item -Path $getportlstfrom -Destination $datafile -Force -ErrorAction SilentlyContinue
        Write-Host "Both domains.txt and ports.txt have been update.  Please run the script as needed."
        if($((gwmi win32_computersystem).Name) -eq "H3K5FV1") {
            Copy-Item -Path H:\backup\domains.txt -Destination H:\data -Force -ErrorAction SilentlyContinue
            Write-Host "By your Command the lab's domains.txt has been restored."
        }
    }
    exit
}
#
if($setup -eq $true) {       
    Write-Host "You only need to run this switch once when running the script for first time "
    Write-Host "on $((gwmi win32_computersystem).Name), or when running in a directory that has not been previously configured."
    Write-Host "Give me a minute or two to setup and copy the necessary files and executables."

    # Check if paths exists, if not create it
    if(!(Test-Path -Path $rawfile)){ New-Item -ItemType directory -Path $rawfile -ErrorAction SilentlyContinue }
    if(!(Test-Path -Path $datafile)){ New-Item -ItemType directory -Path $datafile -ErrorAction SilentlyContinue }
    if(!(Test-Path -Path $rptfile)){ New-Item -ItemType directory -Path $rptfile -ErrorAction SilentlyContinue }

    if(!(Test-Path -Path "$pwd\sslscan\")){ 
        Write-Output "Creating SSLScan directory..." 
        New-Item -ItemType directory -Path "$pwd\sslscan\" -ErrorAction SilentlyContinue
        Write-Output "Making a copy of the SSLScan executables..."
        Copy-Item -Path "$nwROOT\sslscan\*" -Destination "$pwd\sslscan\" -Force -ErrorAction SilentlyContinue
    }

    if(!(Test-Path -Path "$pwd\openssl\")){ 
        Write-Output "Creating OpenSSL directory..."
        New-Item -ItemType directory -Path "$pwd\openssl\" -ErrorAction SilentlyContinue
        Write-Output "Making a copy of the OpenSSL executables..."
        Copy-Item -Path "$nwROOT\openssl\*" -Destination "$pwd\openssl\" -Force -ErrorAction SilentlyContinue
    }
    if(!(Test-Path -Path "$pwd\curl\")){ 
        Write-Output "Creating Curl directory..."
        New-Item -ItemType directory -Path "$pwd\curl\" -ErrorAction SilentlyContinue
        Write-Output "Making a copy of the Curl executables..."
        Copy-Item -Path "$nwROOT\curl\*" -Destination "$pwd\curl\" -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`nFinished creating the necessary directories"
    
    $source = "http://indy.fulgan.com/SSL/openssl-1.0.2e-x64_86-win64.zip"
    $Filename = [System.IO.Path]::GetFileName($source)
    $dstname = $pwd + "\" + $Filename
    $dstfin = "$pwd\openssl"

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($source, $dstname)

    unzip -File $dstname -Destination $dstfin
    
    remove-item -Path $dstname -Force -Recurse -ErrorAction SilentlyContinue

    $source = "http://sslscan-win.googlecode.com/files/SSLScan-1.8.2-win-r7.zip"
    $Filename = [System.IO.Path]::GetFileName($source)
    $dstname = $pwd + "\" + $Filename
    $dstfin = "$pwd\sslscan"

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($source, $dstname)

    unzip -File $dstname -Destination $dstfin
    
    remove-item -Path $dstname -Force -Recurse -ErrorAction SilentlyContinue

    $source = "http://curl.askapache.com/download/curl-7.33.0-win64-ssl-sspi.zip"
    $Filename = [System.IO.Path]::GetFileName($source)
    $dstname = $pwd + "\" + $Filename
    $dstfin = "$pwd\curl"

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($source, $dstname)

    unzip -File $dstname -Destination $dstfin
    
    remove-item -Path $dstname -Force -Recurse -ErrorAction SilentlyContinue    

    Write-Host "`nFinished downloading and extracting the necessary files"

    #Copy-Item -Path $getdomslstfrom -Destination $datafile -Force -ErrorAction SilentlyContinue
    #Copy-Item -Path $getportlstfrom -Destination $datafile -Force -ErrorAction SilentlyContinue

    # Default files if not locally available
    #Write-Host "`nA copy of the $domsname and $portname from $nwDATA is now in the $datafile folder."
    Write-Host "`nYou are now set to execute this script with the desired switches, for example:"
    Write-Host "`n $pwd\$scriptname -v -hosts host,host2,host3 -ports 80,443,8080 -testall"
    Write-Host "`nSee Usage for more information about the available switches."
    exit
}
####> openssl
if(Test-Path -Path  "$pwd\openssl\openssl.exe"){
    $openSSL = "$pwd\openssl\openssl.exe"
} elseif(Test-Path -Path "C:\OpenSSL-Win64\bin\openssl.exe") {
    $openSSL = "C:\OpenSSL-Win64\bin\openssl.exe"
} else {
    Write-Warning "openssl.exe is missing!"
    Write-Host "Please download the lastest version of openssl for Windows from: "
    Write-Host "`n http://indy.fulgan.com/SSL"
    Write-Host "`nDecompress and rename directory to:"
    Write-Host "`n <drive:\><path to openssl>\openssl"
    exit
}
####> SSLScan
if(Test-Path -Path "$pwd\sslscan\SSLScan.exe"){
    $SSLScan = "$pwd\sslscan\SSLScan.exe"
} elseif (Test-Path -Path "C:\Users\Seal\Downloads\SSLScan\SSLScan.exe" ) { 
    $SSLScan = "C:\Users\Seal\Downloads\SSLScan\SSLScan.exe"
} else {
    Write-Warning "SSLScan.exe is missing!"
    Write-Host "Please download the lastest version of SSLScan from: "
    Write-Host "`n http://code.google.com/p/sslscan-win/"
    Write-Host "`nDecompress and rename directory to:"
    Write-Host "`n <drive:\><path to sslscan>\sslscan"
    exit
}
####> curl
if(Test-Path -Path "$pwd\curl\curl.exe"){
    $curl = "$pwd\curl\curl.exe"
} elseif(Test-Path -Path "C:\Program Files\cURL\bin\curl.exe") {
    $curl = "C:\Program Files\cURL\bin\curl.exe"
}else {
    Write-Warning "curl.exe is missing!"
    Write-Host "Please download the lastest version of Curl from: "
    Write-Host "`n http://curl.haxx.se/latest.cgi?curl=win64-ssl-sspi"
    Write-Host "`nDecompress and rename directory to:"
    Write-Host "`n <drive:\><path to curl>\curl"
    exit
}
<#% FUTURE Feature
# posh-ssh-open-source-ssh-powershell-module
# http://www.powershellmagazine.com/2014/07/03/posh-ssh-open-source-ssh-powershell-module/
If(Get-MyModule –name “posh-ssh” -eq $true) { 
    Write-debugger “posh-ssh module is installed on this system."
} else { 
    Write-Warning "Missing Dependency"
    Write-Host "Downloading and installing Posh-SSH onto your system"
    #iex (New-Object Net.WebClient).DownloadString("https://gist.github.com/darkoperator/6152630/raw/c67de4f7cd780ba367cccbc2593f38d18ce6df89/instposhsshdev")
    #or Invoke-WebRequest https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1 -OutFile H:\Invoke-Mimikatz.ps1
    exit
}
%#>
#

if($hosts) {
    # if hostnames are provide via CLI
    $WebsiteURLs = @()
    foreach($hname in $hosts) {
        $tsthost = Test-Connection -ComputerName $hname -Quiet -Count 1 
        if($tsthost -eq $true) {
            $WebsiteURLs += [System.Net.DNS]::GetHostByName($hname).HostName
        }
    }
} else {
    # or default to using the domains.txt file
    if($listname) {
        $domainList = $datafile + "\" + $listname
    } else {
        $domainList = $datafile + "\" + $domsname
    }
    if(Test-Path -Path $domainList) {
        $WebsiteURLs = Get-Content -Path $domainList | ?{$_ -notmatch "^#"}
    } else {
        Write-Warning "domains.txt is missing!"
        Write-Host "Unless specified by switches at the command prompt, a file named domains.txt must "
        Write-Host "exists in the $domainList, with each hostname listed per line."
        Write-Host "`nThere is an option to use the -hosts switch to specify the hosts to assess."
    exit
    }
}
if($ports) {
    # if hostnames are provide via CLI
    $portList = $ports
    $portList = $portList | Sort -Unique
    $portTHLD= $portList.Count
} else {
    # or default to using the ports.txt file
    $plist = $datafile + "\" + $portname
    if(Test-Path $plist) {
        $portList = Get-Content -Path $plist | ?{$_ -notmatch "^#"}
    } else {
        Write-Warning "ports.txt is missing!"
        Write-Host "Unless specified by switches at the command prompt, a file named ports.txt must "
        Write-Host "exists in the x:\data\ directory, with each port listed per line."
        Write-Host "`nThere is an option to use the -ports switch to specify the ports to scan for."
    exit
    }
}
# This is in prep for multithreading
$stuff = [pscustomobject] @{
    q = $q
    v = $v
    vv = $vv
    vvv = $vvv
    rawfile = $rawfile
    datafile = $datafile
    rptfile = $rptfile
    testall = $testall
    journal = $journal
    tstdmp = $tstdmp
    getver = $getver
    chkprocess = $chkprocess
    portlist = $portList
    portTHLD= $portTHLD
    datetime = Get-Date -f MMddyyyyHHmmss
}
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Functions needed inside the loop <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
function Get-WmiObjectCustom([string]$ComputerName,[string]$NameSpace = "root\cimv2",[int]$TimeoutInseconds = 60,[string]$Class) {
# This just adds a timeout to WMI queries
# 
# e,g,, Get-WMIObjectCustom -Class Win32_ComputerSystem -ComputerName PC1 -TimeoutInSeconds 20                        
    try {            
        $ConnectionOptions = new-object System.Management.ConnectionOptions            
        $EnumerationOptions = new-object System.Management.EnumerationOptions            
        $timeoutseconds = new-timespan -seconds $timeoutInSeconds            
        $EnumerationOptions.set_timeout($timeoutseconds)            
        $assembledpath = "\\{0}\{1}" -f $ComputerName, $NameSpace            
        $Scope = new-object System.Management.ManagementScope $assembledpath, $ConnectionOptions            
        $Scope.Connect()            
        $querystring = "SELECT * FROM {0}" -f $class            
        $query = new-object System.Management.ObjectQuery $querystring            
        $searcher = new-object System.Management.ManagementObjectSearcher            
        $searcher.set_options($EnumerationOptions)            
        $searcher.Query = $querystring            
        $searcher.Scope = $Scope            
        $result = $searcher.get()            
    } catch {            
        Throw $_            
    }            
return $result            
}
function checkWMI ([string]$srv){  
# This checks to see if the register accepts WMI request in order to prevent the script from hanging
    $checkwmi = $null  
    $timeout = new-timespan -seconds 15  
    $Scope = new-object System.Management.ManagementScope "\\$srv\root\cimv2", $options -ErrorAction Continue
    try {
        $Scope.Connect()  
        $query = new-object System.Management.ObjectQuery "SELECT * FROM Win32_OperatingSystem"  
        $searcher = new-object System.Management.ManagementObjectSearcher $Scope,$query  
        $SearchOption = $searcher.get_options()  
        $SearchOption.set_timeout($timeout)  
        $searcher.set_options($SearchOption)  
        $checkwmi = $searcher.get()  
        $lastBoot = $checkwmi | %{$_.lastbootuptime}  
        
        if($lastBoot){  
            return $true  
        } else {  
            return $false  
        }
    } catch {
        continue
    }
} 
function testport($fqdn,$port) {
    # TCP Port Scanner that timesout after 50 seconds
    $Test = New-Object Net.Sockets.TcpClient
    $Test.BeginConnect( $fqdn, $port, $Null, $Null ) | Out-Null
    #  Calculate the end of the timeout period
    $Timeout = ( Get-Date ).AddMilliseconds( 1000 )
    #  Loop in 50 second increments until connected or timed out
    While( -not $Test.Connected -and ( Get-Date ) -lt $Timeout ){ Sleep -Milliseconds 50 }
    $results = $Test.Connected
    if($results -eq $true) { return $results }
    # Cleanup
    $Test.Close()
}
function Get-LHSAntiVirusProduct($Computer) {
    $OSVersion = (Get-WMIObjectCustom -Class Win32_OperatingSystem -ComputerName $WebsiteURL -TimeoutInSeconds 60).Version
    #$OSVersion = (Get-WmiObject win32_operatingsystem -computername $Computer).version
    $OS = $OSVersion.split(".")
    Write-Debug "`$OS[0]: $($OS[0])"

    if ($OS[0] -eq "5") {
        Write-Debug "Windows 2000, 2003, XP" 
        Try {
            $AntiVirusProduct = Get-WMIObjectCustom -Class AntiVirusProduct -ComputerName $WebsiteURL -Namespace root\SecurityCenter -TimeoutInSeconds 60
            #$AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop
        } Catch {
            Write-Error "$Computer : WMI Error"
            Write-Error $_
            Continue
        }    
        # Output PSCustom Object
        $AV = $Null
        $AV = New-Object PSObject -Property @{
            ComputerName = $AntiVirusProduct.__Server;
            Name = $AntiVirusProduct.displayName;
            versionNumber = $AntiVirusProduct.versionNumber;
            onAccessScanningEnabled = $AntiVirusProduct.onAccessScanningEnabled;
            productUptoDate = $AntiVirusProduct.productUptoDate;
                
        } | Select-Object ComputerName,Name,versionNumber,onAccessScanningEnabled,productUptoDate 
    } elseif ($OS[0] -eq "6") {
        Write-Debug "Windows Vista, 7, 2008, 2008R2"
        Try {
            $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop
        } Catch {
            Write-Error "$Computer : WMI Error"
            Write-Error $_
        }                
        # Switch to determine the status of antivirus definitions and real-time protection.
        # The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
        switch ($AntiVirusProduct.productState) {
            "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
        }            
        # Output PSCustom Object
        $AV = $Null
        $AV = New-Object -TypeName PSobject -Property @{         
            ComputerName = $AntiVirusProduct.__Server;
            Name = $AntiVirusProduct.displayName;
            ProductExecutable = $AntiVirusProduct.pathToSignedProductExe;
            DefinitionStatus = $defstatus;
            RealTimeProtectionStatus = $rtstatus
        } | Select-Object ComputerName,Name,ProductExecutable,DefinitionStatus,RealTimeProtectionStatus  
    } else {
        Write-Error "\\$Computer : Unknown OS Version"
    }        
    return $AV
}
function BannerGrabber($remoteHost,$portstr,$outBanner) {
    ## Open the socket, and connect to the computer on the specified port 
    $socket = new-object System.Net.Sockets.TcpClient($remoteHost, $portstr) 
    $Timeout = ( Get-Date ).AddMilliseconds( 10000 )
    while( -not $socket.Connected -and ( Get-Date ) -lt $Timeout ){ Sleep -Milliseconds 50 }
    if($socket -eq $null) { return; } 
    $stream = $socket.GetStream() 
    $writer = new-object System.IO.StreamWriter($stream) 
    $buffer = new-object System.Byte[] 1024 
    $encoding = new-object System.Text.AsciiEncoding 
    do { 
       ## Allow data to buffer for a bit 
       Sleep -Milliseconds 500 
       ## Read all the data available from the stream
       while($stream.DataAvailable) {  
          $read = $stream.Read($buffer, 0, 1024)    
          fmtOUT "$remoteHost : $portstr" ($encoding.GetString($buffer, 0, $read))
          ($encoding.GetString($buffer, 0, $read)) | Out-File $outBanner -Append
       } 
    } while(( Get-Date ) -lt $Timeout)
    ## Close the streams
    $portstr = $null
    $stream.Close()
}
function Get-ScheduledTask($WebsiteURL) {
    #region Functions
    function Get-AllTaskSubFolders {
        [cmdletbinding()]
        param (
            # Set to use $Schedule as default parameter so it automatically list all files
            # For current schedule object if it exists.
            $FolderRef = $Schedule.getfolder("\")
        )
        if ($FolderRef.Path -eq '\') {
            $FolderRef
        }
        if (-not $RootFolder) {
            $ArrFolders = @()
            if(($folders = $folderRef.getfolders(1))) {
                $folders | ForEach-Object {
                    $ArrFolders += $_
                    if($_.getfolders(1)) {
                        Get-AllTaskSubFolders -FolderRef $_
                    }
                }
            }
            $ArrFolders
        }
    }
    #endregion Functions
    try {
	    $schedule = new-object -com("Schedule.Service") 
    } catch {
	    Write-Warning "Schedule.Service COM Object not found, this script requires this object"
	    return
    }
    $Schedule.connect($WebsiteURL) 
    $AllFolders = Get-AllTaskSubFolders
    foreach ($Folder in $AllFolders) {
        if (($Tasks = $Folder.GetTasks(1))) {
            $Tasks | Foreach-Object {
	            New-Object -TypeName PSCustomObject -Property @{
	                'Name' = $_.name
                    'Path' = $_.path
                    'State' = switch ($_.State) {
                        0 {'Unknown'}
                        1 {'Disabled'}
                        2 {'Queued'}
                        3 {'Ready'}
                        4 {'Running'}
                        Default {'Unknown'}
                    }
                    'Enabled' = $_.enabled
                    'LastRunTime' = $_.lastruntime
                    'LastTaskResult' = $_.lasttaskresult
                    'NumberOfMissedRuns' = $_.numberofmissedruns
                    'NextRunTime' = $_.nextruntime
                    'Author' =  ([xml]$_.xml).Task.RegistrationInfo.Author
                    'UserId' = ([xml]$_.xml).Task.Principals.Principal.UserID
                    'Description' = ([xml]$_.xml).Task.RegistrationInfo.Description
                }
            }
        }
    }
}
function Get-HWInfo($WebsiteURL) {
# If SMB is accessible grab all of the hardware info
$writeArray =@()
$compList =@()
$excludeArray=@()
$tempArray =@()
# Branch of the Registry  
$Branch="LocalMachine"
# Main Sub Branch you need to open  
$SubBranch="SYSTEM\\CurrentControlSet\\Enum"  
    #Traverse the registry sub-keys and find device names
    Function traverseSubKeys($newregistrykey) {
	    $newsubkeys=$newregistrykey.GetSubKeyNames()
	    foreach ($newsub in $newsubkeys) {
		    $currentnewkey=$newregistrykey.OpenSubKey($newsub)  
		    $descvalue=$currentnewkey.GetValue("DeviceDesc")
		    $friendlyvalue=$currentnewkey.GetValue("FriendlyName")
		    if (($descvalue -eq $null) -and ($friendlyvalue -eq $null)) {
			    traverseSubKeys($currentnewkey)
		    } else {
		        #If friendly name exists, add that to the list of device names. Of not, use the device desc. Include the registry key if the option was specified
			    if ($friendlyvalue -ne $null) {
				    if ($includekey) {
					    $tempArray += $friendlyvalue + "      ||    " + $currentnewkey
				    } else {
					    $tempArray += $friendlyvalue
				    }
			    } else {
				    if ($includekey) {
					    $tempArray += $descvalue + "      ||    " + $currentnewkey
				    } else {
					    $tempArray += $descvalue
				    }
			    }
		    }
	    }
    }
    #Attempt to open the HKLM branch. Return from the current query if this fails
	try {
		$registry=[microsoft.win32.registrykey]::OpenRemoteBaseKey($Branch,$WebsiteURL)
	} catch {
		return
	}
    #Get the names of the registry sub-branches which contain installed hardware
	$registrykey=$registry.OpenSubKey($Subbranch)  
	$SubKeys=$registrykey.GetSubKeyNames()  
    #Traverse the sub-branches and find installed hardware
	Foreach ($key in $subkeys) {
		$NewSubKey=$SubBranch+"\\"+$key  
		$newregistrykey=$registry.OpenSubKey($NewSubKey)  
		traverseSubKeys $newregistrykey
	}
return $tempArray
}
####> HTML
function getrobot($WebsiteURL) {
    $Source = "http://" + $WebsiteURL + "/robots.txt"
    $Destination = $outRAW + "\" + $WebsiteURL + "_ROBOTS.txt"
    Invoke-WebRequest -URI $Source -OutFile $Destination
    $tc = linecount $Source
    if($tc -gt 1) { Copy-Item -Path $Source -Destination $destraw }
    Unblock-File $Destination
}
function chkhttp($url) {
    #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $xHTTP = new-object -com msxml2.xmlhttp
    $xHTTP.open("GET",$url,$false)
    $xHTTP.send()
    return $xHTTP
}
####> Helper Functions
function killprocess ($execname,$AllArgs,$patternSTR,$outFN) { 
# Prevent executables from exceeding 1 min run time (60000 ms = 60 sec...)
    $wfeto = 60000
    $psi=new-object System.Diagnostics.ProcessStartInfo
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.filename = $execname
    $psi.arguments = $AllArgs
    $p = [Diagnostics.Process]::Start($psi)
    $p.WaitForExit($wfeto) | Out-Null
    $p.Kill()
    if($outFN) { 
        $p.StandardOutput.ReadToEnd() | Out-File $outFN -Append
        return (gc $outFN | Select-String -Pattern $patternSTR | %{$_.Matches} | %{$_.Value})
    }
}
function stripcomma([string]$tempstring) {
# Strip out the commas
    return $tempstring.replace(',',';') 
}
function grep($f,$s) {
# Use gc to grep file $f and return matching line
    gc $f | % { if($_ -match $s){ return $_ } } 
}
function boolgrep($f,$s) {
# Use gc to grep file $f and return boolean
    gc $f | % { if($_ -match $s){ return $true } else { return $false } } 
}
function boollike($f,$s) {
# Use gc to grep file $f and return boolean
    gc $f | % { if($_ -like $s){ return $true } else { return $false } }  
}
####> Clear Variables
function freshstart($excludeList) {
    Get-Variable -Exclude $excludeList | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue }
}
####> Manage Logs
function fmtOUT($padtxt,$answer) {
# Keep the formatting consistent
    $padtext = $padtxt.PadRight(30,' ')
    Write-Host "$padtext : " -NoNewLine -ForegroundColor Green
    Write-Host "$answer" -ForegroundColor black
    $padtext = $ull
    $answer = $null
}
function logOUT($padtxt,$answer,$logfile) {
# Keep the formatting consistent
    $padtext = $padtxt.PadRight(21,' ')
    Write-Output "$padtext : $answer" | Out-File $logfile -Append
}
function logOUTPUT($padtext,$logfile) {
    Write-Output $padtext | Out-File $logfile -Append
}
function lnCNT($cntme) {
# Count the number of lines in the file
    $tc = 0
    if(Test-Path $cntme) { $tc = (gc -Path $cntme | select-string .).Count }
    return $tc
} 
function delLOG($delme) {
# If exists remove file and has content
    $tcnt = lnCNT $delme
    if($tcnt -ge 1){ Remove-Item -Force $delme }
    if(Test-Path $delme) { Remove-Item -Force $delme }
}
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>     LOOP STARTS HERE     <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
if($v -eq $true -or $vv -eq $true) { 
    Write-Host "Prep completed. " -ForegroundColor Gray 
    if($testall -eq $true) { Write-Warning "Go grab a refreshment, this might take a while, unless you like to see things scroll by on the screen." }
}
$elapsed = [System.Diagnostics.Stopwatch]::StartNew()
foreach($WebsiteURL in $WebsiteURLs) {
    #
    ####> Format WebsiteURL String
    #
    $WebsiteURL = $WebsiteURL.Trim()
    # Test if $WebsiteURL is an URI, if yes, strip and return the FQDN
    if($WebsiteURL -match "(/|htt(p|ps)://)") {
        $httpurl = "http://$WebsiteURL"
        $WebsiteURL = ([System.Uri]"$httpurl").Host
    }
    #
    ####> Assign the $stuff to variables
    #
    foreach ($parameter in $stuff) {
        $q = $parameter.q
        $v = $parameter.v
        $vv = $parameter.vv
        $vvv = $parameter.vvv
        $oRAW  = $parameter.rawfile
        $oData = $parameter.datafile
        $oRPT  = $parameter.rptfile
        $DateTime = $parameter.datetime
        # What to test
        $testall = $parameter.testall
        $journal = $parameter.journal
        $tstdmp = $parameter.tstdmp
        $getver = $parameter.getver
        $chkprocess = $parameter.chkprocess
        $portList = $parameter.portList
        $portTHLD= $parameter.portTHLD
    }
    # Set default filename and path
    $outRAW = $oRAW + "\" + $WebsiteURL
    # Set name of output files
    $outCSV = $oRAW + "\" + $WebsiteURL + ".csv"
    delLOG $outCSV
    $outFWR = $oRAW + "\" + $WebsiteURL + "_FWRDUMP.csv"
    delLOG $outFWR
    # Setup and Delete previous files
    $outHTTP = $outRAW + "_HTMLDUMP.txt"
    delLOG $outHTTP
    $outXML = $outRAW + "_XMLDUMP.txt"
    delLOG $outXML
    $outFTP = $outRAW + "_FTPDUMP.txt"
    delLOG $outFTP
    $outDNS = $outRAW + "_DISPLAYDNS.txt"
    delLOG $outDNS
    $outDMP = $outRAW + "_CRASHDUMP.txt"
    delLOG $outDMP
    $outHOST = $outRAW + "_HOSTINFO.txt"
    delLOG $outHOST
    $outHTTP = $outRAW + "_HTTPINFO.txt"
    delLOG $outHTTP
    $outPORT = $outRAW + "_PORT.txt"
    delLOG $outPORT
    $outBanner = $outRAW + "_BANNERDUMP.txt"
    delLOG $outBanner
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>     Basic Information    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($v -eq $true -or $vv -eq $true) { 
        Write-Host "Assessing " -NoNewLine
        Write-Host "$WebsiteURL $(Get-Date -f HH:mm:ss)" -ForegroundColor black
    }

    if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $WebsiteURL -Quiet) {
        fmtOUT "$WebsiteURL is" "Up"
    } else {
        fmtOUT "$WebsiteURL is" "Down/Filtered"
    }
    $outOBJ = New-Object -TypeName PSobject 
     # Test if $WebsiteURL is actaully an IP Address, if yes, return the FQDN
    $IsValid = ($WebsiteURL -As [IPAddress]) -As [Bool]
    if($IsValid -eq $true) { 
        $WebsiteURL = [System.Net.Dns]::GetHostbyAddress($WebsiteURL).HostName
        $outOBJ | Add-Member -MemberType NoteProperty -Name TargetHostName -Value $WebsiteURL
    } else {
        if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $WebsiteURL -Quiet -ErrorAction SilentlyContinue) {
            $outOBJ | Add-Member -MemberType NoteProperty -Name TargetHostName -Value $WebsiteURL
        }
    }   
    try {           
        $IPAddress = [System.Net.DNS]::GetHostEntry($WebsiteURL).AddressList[0].IPAddressToString   
        $outOBJ | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
    } catch {
        continue
    }

    # Port
    if($v -eq $true -or $vv -eq $true) { Write-Host "Looking for open TCP Ports..." }
    $ErrorActionPreference = "SilentlyContinue"
    $i = 0
    $csvport = @()
    do {
        $tstport = testport $WebsiteURL $([string]$portList[$i])
        if($tstport -eq $true) {
            if($vv -eq $true) { fmtOUT $([string]$portList[$i]) "Open" }
            Write-Output $portList[$i] | Out-File $outPORT -Append
            $csvport += $([string]$portList[$i])
        }
        $i++
    } until ($i -eq $portTHLD)
    $csvout = [string]$csvport -replace " ", ";"
    $outOBJ | Add-Member -MemberType NoteProperty -Name openTCPports -Value $csvout
    # Prep param
    switch ([array]$csvport) {
        { $_ -contains 21 } { $ftpstat = $true }
        { $_ -contains 22 } { $sshstat = $true }
        { $_ -match "(143(3|4))" } { $sqlstat = $true }
        { $_ -contains 445 -or $_ -contains 139 } { $wmistat = (checkWMI $WebsiteURL) }
        { $_ -match "(80|801(0|1|2|5))" } { 
            $Port = $_
            $httpstat = $true
            $url = "http://$WebsiteURL`:$Port"
            $sslhttp = "UNK"
        }
        { $_ -match "(8089)" } { 
            $xmlstat = $true
            $Port = $_
            $sslstat = $true
            $httpstat = $true
            #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            $url = "https://$WebsiteURL`:$Port"
        }
        { $_ -match "(443)" } {
            $Port=$_
            $httpstat=$true
            $sslstat=$true
            #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            $url = "https://$WebsiteURL`:$Port"
            $HTTPs = chkhttp $url
            if($v -eq $true -or $vv -eq $true) { Write-Host "`nChecking if $WebsiteURL will respond to HTTP/S request over port $Port" -ForegroundColor Gray }
            if($($HTTPs.status) -notmatch "((2|4)(\d){2})") {
                Write-Host "Good-to-Go"
                fmtOUT "URL" $url
                $sslhttp = "Ok"          
            } else { 
                Write-Host "Okay, port $Port appears to be open, but doesn't appear to accept HTTPS request"
                $url = "http://$WebsiteURL" 
                Write-Host "All further HTTP checks will now be done using:"
                fmtOUT "URL" $url
                $sslhttp = "No"
            }
        }
    }
    if($v -eq $true -or $vv -eq $true) {
        Write-Host "What I found out so far..."
        fmtOUT "FQDN" $WebsiteURL
        fmtOUT "IP Address" $IPAddress
        fmtOUT "Ports" $csvout
        fmtOUT "URL" $url
    }
    Write-Host "Checking what Services are running the the discovered ports" -ForegroundColor Gray
    if($vv -eq $true) {
        fmtOUT "FTP Status" $ftpstat
        fmtOUT "SSH Status" $sshstat
        fmtOUT "SQL Status" $sqlstat
        fmtOUT "WMI Status" $wmistat
        fmtOUT "SSL Status" $sslstat
        fmtOUT "XML Status" $xmlstat
        fmtOUT "HTTP Status" $httpstat
        fmtOUT "var Port" $Port
    }
    if($ftpstat -eq $true) {
        if($v -eq $true -or $vv -eq $true) { Write-Host "`nChecking if $WebsiteURL will respond to FTP request over port 21" -ForegroundColor Gray }
        if([bool](killprocess ftp $WebsiteURL "200" $outFTP)) {
            $outOBJ | Add-Member -MemberType NoteProperty -Name FTP -Value "Enabled"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name FTP -Value "UNK"
        }
    } else {
        $outOBJ | Add-Member -MemberType NoteProperty -Name FTP -Value "NA"
    }
    if($xmlstat -eq $true) {
        if($v -eq $true -or $vv -eq $true) { Write-Host "`nChecking if retrieving the XML $WebsiteURL is possible " -ForegroundColor Gray }
        ##[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $xmlOUT = (New-Object System.Net.WebClient).DownloadString($url)
        $xmlOUT | Out-File $outXML -Append
        if([bool]$xmlOUT -eq $true) {
            fmtOUT "XML Enabled" "Yes"
            $outOBJ | Add-Member -MemberType NoteProperty -Name XML -Value "Enabled"
        } else {
            fmtOUT "XML Enabled" "No"
            $outOBJ | Add-Member -MemberType NoteProperty -Name XML -Value "No"
        }            
    } else {
        $outOBJ | Add-Member -MemberType NoteProperty -Name XML -Value "NA"
    }
    <#% Test SSH - FUTURE Feature
    if($sshstat -eq $true) {
        $secpasswd = ConvertTo-SecureString "root" -AsPlainText -Force
        $creds = New-Object System.Management.Automation.PSCredential ("toor", $secpasswd)
        try {
            New-SSHSession -ComputerName $WebsiteURL -Credential $creds -AcceptKey
        } catch {
            switch ($error[0]) {
                { $_ -match "denied" } { $outOBJ | Add-Member -MemberType NoteProperty -Name SSH -Value "Enabled" }
                default { $outOBJ | Add-Member -MemberType NoteProperty -Name SSH -Value "UNK" }
            }
        }
    } else {
        $outOBJ | Add-Member -MemberType NoteProperty -Name SSH -Value "UNK"
    }
    %#>
    if($httpstat -eq $true) {

        # Web service; Information Leakage
        fmtOUT "URL" $url
        $sHTTP = new-object -com msxml2.xmlhttp
        $sHTTP.open("OPTIONS",$url,$false)
        $sHTTP.send()
        switch($sHTTP.status) {
        200 {
                fmtOUT "Status Code" $sHTTP.status    
                if($Port -eq 443) {
                    fmtOUT "HTTP Request on TCP Port $Port" $sslhttp
                } else {
                    fmtOUT "HTTP Request on TCP Port $Port" "Allowed"
                }
                $outOBJ | Add-Member -MemberType NoteProperty -Name HTTP -Value $sHTTP.status
                $outOBJ | Add-Member -MemberType NoteProperty -Name PORT -Value $Port
                $outOBJ | Add-Member -MemberType NoteProperty -Name SSL -Value $sslhttp
            }
        403 {
                fmtOUT "Status Code" $sHTTP.status
                fmtOUT "HTTP Request on TCP Port $Port" "Not Allowed"
                $outOBJ | Add-Member -MemberType NoteProperty -Name HTTP -Value $sHTTP.status
                $outOBJ | Add-Member -MemberType NoteProperty -Name PORT -Value $Port
                $outOBJ | Add-Member -MemberType NoteProperty -Name SSL -Value $sslhttp
            }
        default {
                    fmtOUT "Status Code" $sHTTP.status
                    fmtOUT "HTTP Request on TCP Port $Port" "Refused"
                    $outOBJ | Add-Member -MemberType NoteProperty -Name HTTP -Value $sHTTP.status
                    $outOBJ | Add-Member -MemberType NoteProperty -Name PORT -Value $Port
                    $outOBJ | Add-Member -MemberType NoteProperty -Name SSL -Value $sslhttp
                }
        }
        Write-Output $sHTTP.getAllResponseHeaders() | Out-File $outHTTP -Append
        #
        #####> System.Net.WebClient
        #
        $web = New-Object System.Net.WebClient
        $web.Encoding = [System.Text.Encoding]::Default
        $response = $web.DownloadString($url)
        # restores normal validation
        $pagesize = "{0}" -f ($web.DownloadString("$url")).length
        if($pagesize -gt 0) {
            Write-Output $response | Out-File $outHTTP -Append            
            $responseheader = $web.ResponseHeaders.GetEnumerator() | %{ "$_ : $($web.ResponseHeaders.Get($_))" } 
            if($responseheader) {
                Write-Output $responseheader | Out-File $outHTTP -Append
            }
            #
            #####> System.Net.WebClient
            #
            $webrequest = Invoke-WebRequest -URI $url -SessionVariable websession 
            Write-Output $websession.Cookies.GetCookies($url) | Out-File $outHTTP -Append
            Write-Output $webrequest.Links | Out-File $outHTTP -Append
            Write-Output $webrequest.Headers | Out-File $outHTTP -Append
            Write-Output $webrequest | Out-File $outHTTP -Append
        } 
        $Source = "http://" + $WebsiteURL + "/robots.txt"
        $Destination = $outRAW + "\" + $WebsiteURL + "_ROBOTS.txt"
        Invoke-WebRequest -URI $Source -OutFile $Destination
        $tc = linecount $Source
        if($tc -gt 1) { Copy-Item -Path $Source -Destination $nwRAWDATA }
        Unblock-File $Destination
        Copy-Item -Path $outHTTP -Destination $nwRAWDATA -Force -ErrorAction SilentlyContinue     
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$null}
    } else {
        $outOBJ | Add-Member -MemberType NoteProperty -Name HTTP -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name PORT -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SSL -Value "NA"
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>           Banner Grab            <<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($banner -eq $true -or $testall -eq $true) {
        # Grab banner from listening ports
        Write-Host "Looking through all of the open TCP Ports for what infomation is leaked..."
        foreach($openport in (gc -Path $outPORT)) {
            BannerGrabber $WebsiteURL $openport $outBanner
            if($vv -eq $true) { fmtOUT $WebsiteURL $openport }
        }
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>     X.509 Certificate Check      <<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($sslstat -eq $true) {
        if($v -eq $true -or $vv -eq $true) { Write-Host "`nChecking X.509 Information for $WebsiteURL on port $Port" -ForegroundColor Gray }
        try{
            $client = New-Object System.Net.Sockets.TcpClient -ErrorAction SilentlyContinue 
            $client.Connect($WebsiteURL, $Port)
            $sslStream = New-Object System.Net.Security.SslStream($client.GetStream()) -ErrorAction SilentlyContinue 
            $sslStream.AuthenticateAsClient($WebsiteURL)
            $Cert = $sslStream.Get_RemoteCertificate()
            $Cert2 = New-Object system.security.cryptography.x509certificates.x509certificate2($Cert) -ErrorAction SilentlyContinue 
            $ValidTo = [datetime]::Parse($Cert.GetExpirationDatestring())
            $Validfrom = [datetime]::Parse($Cert.GetEffectiveDatestring())
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain -ErrorAction SilentlyContinue 
            $RevocationFlag = $chain.ChainPolicy.RevocationFlag
            $RevocationMode = $chain.ChainPolicy.RevocationMode
            $VerificationFlags = $chain.ChainPolicy.VerificationFlags
        } Catch [System.Management.Automation.ActionPreferenceStopException] {
            continue
        }
        $Client.Close()
        if($v -eq $true -or $vv -eq $true) { Write-Host "`nCertificate Information" -ForegroundColor Gray }
        if([string]::IsNullOrEmpty($RevocationFlag) -or [string]::IsNullOrWhiteSpace($RevocationFlag)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name RevocationFlag -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name RevocationFlag -Value $RevocationFlag
        }
        if([string]::IsNullOrEmpty($RevocationMode) -or [string]::IsNullOrWhiteSpace($RevocationMode)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name RevocationMode -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name RevocationMode -Value $RevocationMode
        }
        if([string]::IsNullOrEmpty($VerificationFlags) -or [string]::IsNullOrWhiteSpace($VerificationFlags)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name VerificationFlags -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name VerificationFlags -Value $VerificationFlags
        }
        if($vv -eq $true) {
            fmtOUT "RevocationFlag" "$RevocationFlag"
            fmtOUT "RevocationMode" "$RevocationMode"
            fmtOUT "VerificationFlags " "$VerificationFlags "
        }
        foreach ($objItem in $sslStream) {
            $SslProtocol               = $objItem.SslProtocol
            $CheckCertRevocationStatus = $objItem.CheckCertRevocationStatus
            $CipherAlgorithm           = $objItem.CipherAlgorithm
            $CipherStrength            = $objItem.CipherStrength 
            $HashAlgorithm             = $objItem.HashAlgorithm
            $HashStrength              = $objItem.HashStrength
            $KeyExchangeAlgorithm      = $objItem.KeyExchangeAlgorithm
            $KeyExchangeStrength       = $objItem.KeyExchangeStrength
        }
        if([string]::IsNullOrEmpty($SslProtocol) -or [string]::IsNullOrWhiteSpace($SslProtocol)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name SslProtocol -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name SslProtocol -Value $SslProtocol
        }
        if([string]::IsNullOrEmpty($CheckCertRevocationStatus) -or [string]::IsNullOrWhiteSpace($CheckCertRevocationStatus)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name CheckCertRevocationStatus -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CheckCertRevocationStatus -Value $CheckCertRevocationStatus
        }
        if([string]::IsNullOrEmpty($CipherAlgorithm) -or [string]::IsNullOrWhiteSpace($CipherAlgorithm)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name CipherAlgorithm -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CipherAlgorithm -Value $CipherAlgorithm
        }
        if([string]::IsNullOrEmpty($CipherStrength) -or [string]::IsNullOrWhiteSpace($CipherStrength)) { 
            $CipherStrength ="NA"
            $outOBJ | Add-Member -MemberType NoteProperty -Name CipherStrength -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CipherStrength -Value $CipherStrength
        }
        if([string]::IsNullOrEmpty($HashAlgorithm) -or [string]::IsNullOrWhiteSpace($HashAlgorithm)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name HashAlgorithm -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name HashAlgorithm -Value $HashAlgorithm
        }
        if([string]::IsNullOrEmpty($HashStrength) -or [string]::IsNullOrWhiteSpace($HashStrength)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name HashStrength -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name HashStrength -Value $HashStrength
        }
        if([string]::IsNullOrEmpty($KeyExchangeAlgorithm) -or [string]::IsNullOrWhiteSpace($KeyExchangeAlgorithm)) {  
            $outOBJ | Add-Member -MemberType NoteProperty -Name KeyExchangeAlgorithm -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name KeyExchangeAlgorithm -Value $KeyExchangeAlgorithm
        }
        if([string]::IsNullOrEmpty($KeyExchangeStrength) -or [string]::IsNullOrWhiteSpace($KeyExchangeStrength)) {  
            $outOBJ | Add-Member -MemberType NoteProperty -Name KeyExchangeStrength -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name KeyExchangeStrength -Value $KeyExchangeStrength
        }
        if($v -eq $true -or $vv -eq $true) { 
            fmtOUT "SslProtocol" "$SslProtocol"
            fmtOUT "CheckCertRevocationStatus " "$CheckCertRevocationStatus "
            fmtOUT "CipherAlgorithm" "$CipherAlgorithm"
            fmtOUT "CipherStrength" "$CipherStrength"
            fmtOUT "HashAlgorithm " "$HashAlgorithm"
            fmtOUT "HashStrength" "$HashStrength"
            fmtOUT "KeyExchangeAlgorithm" "$KeyExchangeAlgorithm"
            fmtOUT "KeyExchangeStrength " "$KeyExchangeStrength"
        }
        if([string]::IsNullOrEmpty($ValidTo) -or [string]::IsNullOrWhiteSpace($ValidTo)) { $ValidTo = [datetime]::Parse($Cert.GetExpirationDatestring()) }
        if([string]::IsNullOrEmpty($Validfrom) -or [string]::IsNullOrWhiteSpace($Validfrom)) { $Validfrom = [datetime]::Parse($Cert.GetEffectiveDatestring()) }
        $CertFormat                = $cert.getformat()
        $CertExpiration            = $Validto
        $CertIssueDate             = $Validfrom
        $CertIssuer                = stripcomma $cert.get_issuer()
        $SerialNumber              = $cert.getserialnumberstring()
        $CertSubject               = stripcomma $cert.get_subject()
        $CertSubject               = $CertSubject.Replace("`" "," ")
        $CertType                  = convertoid $cert.getkeyalgorithm()
        $CertKeySize               = $cert2.PublicKey.key.KeySize
        if([string]::IsNullOrEmpty($CertFormat) -or [string]::IsNullOrWhiteSpace($CertFormat)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertFormat -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertFormat -Value $CertFormat
        }
        if([string]::IsNullOrEmpty($CertExpirationl) -or [string]::IsNullOrWhiteSpace($CertExpiration)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertExpiration -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertExpiration -Value $CertExpiration
        }
        if([string]::IsNullOrEmpty($CertIssueDate) -or [string]::IsNullOrWhiteSpace($CertIssueDate)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertIssueDate -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertIssueDate -Value $CertIssueDate
        }
        if([string]::IsNullOrEmpty($CertIssuer) -or [string]::IsNullOrWhiteSpace($CertIssuer)) {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertIssuer -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertIssuer -Value $CertIssuer
        }
        if([string]::IsNullOrEmpty($SerialNumber) -or [string]::IsNullOrWhiteSpace($SerialNumber)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name SerialNumber -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber
        }
        if([string]::IsNullOrEmpty($CertSubject) -or [string]::IsNullOrWhiteSpace($CertSubject)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertSubject -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertSubject -Value $CertSubject
        }
        if([string]::IsNullOrEmpty($CertType) -or [string]::IsNullOrWhiteSpace($CertType)) { 
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertType -Value "NA"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertType -Value $CertType
        }
        if([string]::IsNullOrEmpty($CertKeySize) -or [string]::IsNullOrWhiteSpace($CertKeySize)) {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertKeySize -Value "NA"        
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name CertKeySize -Value $CertKeySize 
        }
        if($vv -eq $true) { 
            fmtOUT "CertFormat  " "$CertFormat"
            fmtOUT "CertExpiration" "$CertExpiration"
            fmtOUT "CertIssueDate " "$CertIssueDate"
            fmtOUT "CertIssuer  " "$CertIssuer"
            fmtOUT "SerialNumber" "$SerialNumber"
            fmtOUT "CertSubject " "$CertSubject"
            fmtOUT "CertType " "$CertType"
            fmtOUT "CertKeySize " "$CertKeySize"
        }
        $ValidDays = $($ValidTo - [datetime]::Now).Days
        if($ValidDays -lt 0) { $ValidDays = 0 }
        if ($ValidDays -lt $warningThreshold) {   
            if($vv -eq $true) { fmtOUT "Not due to expired for another" "$ValidDays days" }
        } else {
            if($vv -eq $true) { fmtOUT "Cert is due to expire in" "$ValidDays days" }
        }
        $outOBJ | Add-Member -MemberType NoteProperty -Name ValidDays -Value $ValidDays
        if($v -eq $true -or $vv -eq $true) { 
            Write-Host "`nPermitted SSL/TLS protocols" -ForegroundColor Gray
            Write-Host "Timing how long it takes to execute each test..." 
        }
 
        if($vv -eq $true) { $sw = [Diagnostics.Stopwatch]::StartNew() }
       
        $outssl = $outRAW +"_SSLv1.txt"
        delLOG $outssl
        $AllArgs ="--no-failed $WebsiteURL`:$Port"
        $tlsstat = killprocess $SSLScan $AllArgs "Accepted" $outssl
        $t0 = [bool](Select-String -Path $outssl -Pattern "Accepted" -AllMatches | %{$_.Matches} | %{$_.Value})
        if($t0 -eq $true) {
            if($vv -eq $true) { fmtOUT "SSLv1" "Permitted" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv1 -Value "Yes"
        } else {
            if($vv -eq $true) { fmtOUT "SSLv1" "Not Permitted" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv1 -Value "No"
        }
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $t0 = $null

        if($vv -eq $true) { 
            $sw.Stop()
            $ms = $sw.Elapsed.Milliseconds
            $sec = $sw.Elapsed.Seconds
            $min = $sw.Elapsed.Minutes
            $hrs = $sw.Elapsed.Hours
            $to = "$hrs`:$min`:$sec`:$ms"
            fmtOUT "Elasped Time to complete" $to
        }
        
        $ProtocolNames = [System.Security.Authentication.SslProtocols] | gm -static -MemberType Property | ?{$_.Name -notcontains @("Default","None")} | %{$_.Name}
        $ProtocolStatus = [Ordered]@{}
        $ProtocolStatus.Add("ComputerName", $WebsiteURL)
        $ProtocolStatus.Add("Port", $Port)
        $ProtocolStatus.Add("KeyLength", $null)
        $ProtocolStatus.Add("SignatureAlgorithm", $null)
        $ProtocolNames | %{
        $ProtocolName = $_
        $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
        $Socket.Connect($WebsiteURL, $Port)
            try {
                $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
                $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
                $SslStream.AuthenticateAsClient($WebsiteURL, $null, $ProtocolName, $false )
                $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
                $ProtocolStatus["KeyLength"] = $RemoteCertificate.PublicKey.Key.KeySize
                $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.PublicKey.Key.SignatureAlgorithm.Split("#")[1]
                $ProtocolStatus.Add($ProtocolName, $true)
            } catch  {
                $ProtocolStatus.Add($ProtocolName, $false)
            } finally {
                $SslStream.Close()
            }
        }
        #[PSCustomObject]$ProtocolStatus
        $ssl2 = [PSCustomObject]$ProtocolStatus[4]
        $ssl3 = [PSCustomObject]$ProtocolStatus[5]
        $tls10 = [PSCustomObject]$ProtocolStatus[6]
        $tls11 = [PSCustomObject]$ProtocolStatus[7]
        $tls12 = [PSCustomObject]$ProtocolStatus[8]
        $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv2 -Value $ssl2
        $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv3 -Value $ssl3
        $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv1 -Value $tls10
        $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv11 -Value $tls11
        $outOBJ | Add-Member -MemberType NoteProperty -Name TLSV12 -Value $tls12

        function tstssl($sslv,$WebsiteURL,$Port) {
            $sw = $null
            if($vv -eq $true) { $sw = [Diagnostics.Stopwatch]::StartNew() }
            $outssl = $outRAW +"_"+$sslv+".txt"
            delLOG $outssl
            if($Port=8089){ 
                $patternSTR = "CN=SplunkServerDefaultCert" 
            } else { 
                $patternSTR = "CN=" + $WebsiteURL
            }
            switch($sslv) {
                "SSLv2" { $AllArgs ="s_client -ssl2 -connect $WebsiteURL`:$Port" }
                "SSLv3" { $AllArgs ="s_client -ssl3 -connect $WebsiteURL`:$Port" }
                "TLSv1" { $AllArgs ="s_client -tls1 -connect $WebsiteURL`:$Port" }
                "TLSv11" { $AllArgs ="s_client -tls1_1 -connect $WebsiteURL`:$Port" }
                "TLSv12" { $AllArgs ="s_client -tls1_2 -connect $WebsiteURL`:$Port" }
            default { $AllArgs ="s_client -tls1_2 -connect $WebsiteURL`:$Port" }
            }
            $tlsstat = killprocess $openssl $AllArgs $patternSTR $outssl
            $t0 = Select-String -Path $outssl -Pattern $patternSTR -AllMatches | %{$_.Matches} | %{$_.Value}
            if ($t0 -eq $patternSTR) {
                if($vv -eq $true) { fmtOUT $sslv "Permitted" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name $sslv -Value "Yes"
            } else {
                if($vv -eq $true) { fmtOUT $sslv "Not Permitted" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name $sslv -Value "No"
            }

            if($vv -eq $true) { 
                $sw.Stop()
                $ms = $sw.Elapsed.Milliseconds
                $sec = $sw.Elapsed.Seconds
                $min = $sw.Elapsed.Minutes
                $hrs = $sw.Elapsed.Hours
                $to = "$hrs`:$min`:$sec`:$ms"
                fmtOUT "Elasped Time to complete" $to
            }
            $outssl = $null
            $AllArgs = $null
            $patternSTR = $null
            $t0 = $null
            $tlsstat = $null
        }
        if($ssl2 -eq $false) { tstssl SSLv2 $WebsiteURL $Port }
        if($ssl2 -eq $true) {
            if($vv -eq $true) { fmtOUT "SSLv2" "Permitted" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv2 -Value "Yes"
        }
        if($ssl3 -eq $false) { tstssl SSLv3 $WebsiteURL $Port }
        if($ssl3 -eq $true) {
            if($vv -eq $true) { fmtOUT "SSLv3" "Permitted" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv3 -Value "Yes"
        }
        if($tls10 -eq $false) { tstssl TLSv1 $WebsiteURL $Port }
        if($tls10 -eq $true) {
            if($vv -eq $true) { fmtOUT "TLSv1" "Permitted" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv1 -Value "Yes"
        }
        if($tls11 -eq $false) { tstssl TLSv11 $WebsiteURL $Port }
        if($tls11 -eq $true) {
            if($vv -eq $true) { fmtOUT "TLSv1.1" "Permitted" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv11 -Value "Yes"
        }
        if($tls12 -eq $false) { tstssl TLSv12 $WebsiteURL $Port }
        if($tls12 -eq $true) {
            if($vv -eq $true) { fmtOUT "TLSv1.2" "Permitted" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv12 -Value "Yes"
        }
        if($v -eq $true -or $vv -eq $true) { Write-Host"`nCiphers Accepted" -ForegroundColor Gray }
        # Check what Ciphers are accepted
        $outssl = $outRAW +"_SSLv1.txt"
        $getCiphers = @()
        $getCiphers = (gc $outssl | Select-String -Pattern "Accepted*" -AllMatches | %{$_ -replace "[\s]*Accepted[\s]*",""}).Trim()
        if($getCiphers) {
            $cipher = $getCiphers| &{$OFS=";";[string]$getCiphers}
            if($vv -eq $true) { fmtOUT "Ciphers" $cipher }
            $outOBJ | Add-Member -MemberType NoteProperty -Name Ciphers -Value $cipher
        }
        $outssl = $null
        # Self-Signed
        if($v -eq $true -or $vv -eq $true) { Write-Host "`nChecking if cert is self-signed" -ForegroundColor Gray }
        $AllArgs ="s_client -showcerts -connect $WebsiteURL`:$Port"
        $outssl = $outRAW +"_CERTS.txt"
        delLOG $outCERT
        $tlsstat = killprocess $openssl $AllArgs "error:num=19:self signed" $outssl
        if($tlsstat) {
            if($v -eq $true -or $vv -eq $true) { Write-Host "`nCheck for self signed cert" -ForegroundColor Gray }
            if($tstcert -eq $false) {
                if($vv -eq $true) { fmtOUT "Self-signed" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name SelfSigned -Value "No" 
            } else {
                if($vv -eq $true) { fmtOUT "Self-signed" "Yes" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name SelfSigned -Value "Yes" 
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "Self-signed" "No" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name SelfSigned -Value "No"
        }
        if($v -eq $true -or $vv -eq $true) { Write-Host "`nSSL Mitigating Controls Check" -ForegroundColor Gray }
        $outssl = $outRAW +"_HSTS.txt"
        delLOG $outssl
        $AllArgs ="-k -s -D- https://$WebsiteURL"
        $tlsstat = killprocess $openssl $AllArgs "401 Unauthorized" $outssl
        $t1 = boolgrep $outssl "401 Unauthorized"
        $tc = linecount $outssl
        if ($tc -gt 1 -and $t1[0] -eq $false) { 
            if($tlsstat -eq $true) {
                if($vv -eq $true) { fmtOUT "HSTS" "Yes" } 
                $outOBJ | Add-Member -MemberType NoteProperty -Name HSTS -Value "Yes" 
            } else {
                if($vv -eq $true) { fmtOUT "HSTS" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name HSTS -Value "No" 
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "HSTS" "No" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name HSTS -Value "No"
        }
        $fallback = $false
        $outssl = $outRAW +"_FALLBACK.txt"
        delLOG $outssl
        
        $AllArgs ="s_client -ssl3 -fallback_scsv -connect $WebsiteURL`:$Port"
        $tlsstat = killprocess $openssl $AllArgs "inappropriate fallback" $outssl 
        $tc = linecount $outssl
        if ($tc -gt 1) { 
            if($tlsstat -eq $true) {
                if($vv -eq $true) { fmtOUT "FALLBACK" "Yes"}
                $fallback = $true
                $outOBJ | Add-Member -MemberType NoteProperty -Name FALLBACK -Value "Yes" 
            } else {
                if($vv -eq $true) { fmtOUT "FALLBACK" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name FALLBACK -Value "No" 
                $fallback = $false
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "FALLBACK" "No" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name "FALLBACK" -Value "No"
        }
        $outssl = $outRAW +"_OCSP.txt"
        delLOG $outssl
        
        $AllArgs ="s_client -status -tlsextdebugger -connect $WebsiteURL`:443"
        $tlsstat = killprocess $openssl $AllArgs "OCSP response: no response sent" $outssl
        $tc = linecount $outssl
        if ($tc -gt 1) { 
            if($tlsstat -eq $true) {
                if($vv -eq $true) { fmtOUT "OCSP" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name OCSP -Value "No" 
            } else {
                if($vv -eq $true) { fmtOUT "OCSP" "Yes"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name OCSP -Value "Yes" 
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "OCSP" "No" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name OCSP -Value "No" 
        }
        $rc4 = $false
        $outssl = $outRAW +"_RC4.txt"
        delLOG $outssl
        
        $AllArgs ="s_client -cipher RC4 -connect $WebsiteURL`:$Port"
        $t0 = killprocess $openssl $AllArgs "Cipher" "RC4" $outssl 
        if($t0 -eq $false) { 
            delLOG $outssl
            $t1 = killprocess $openssl $AllArgs "Cipher" "RC4" $outssl 
        }
        $tlsstat = gc $outssl | ?{$_ -match "Cipher    :"}
        $varstat = $($tlsstat -replace "Cipher    :"," ").Trim()
        $tc = linecount $outssl
        if ($tc -gt 1) { 
            if($vv -eq $true) { fmtOUT "RC4 Permitted" "$varstat" }
            if($varstat -like"RC4-") { 
                if($vv -eq $true) { fmtOUT "RC4" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name RC4 -Value "Yes" 
            } else { 
                if($vv -eq $true) { fmtOUT "RC4" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name RC4 -Value "No" 
            }
            $rc4 = $true
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $t0 = $null
        $tlsstat = $null
        $varstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "RC4" "No" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name RC4 -Value "No"
        }
        # Check if compression is enabled
        $compres = $false
        $outssl = $outRAW +"_RC4.txt"
        $tc = linecount $outssl
        if ($tc -gt 1) {     
            $tlsstat = grep $outssl "Compression:"
            $varstat = $($tlsstat -replace "Compression:"," ").Trim()
            if($vv -eq $true) { fmtOUT "Compression " "$varstat" }
            if($varstat -match "NONE") { 
                $compres = $true 
                if($vv -eq $true) { fmtOUT "Compression" "None" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name Compression -Value "None"
            } else { 
                $compres = $false 
                if($vv -eq $true) { fmtOUT "Compression" "Yes" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name Compression -Value $varstat
            }
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        }
        # Check if Secure Renegotiation is allowed
        $sregneg = $false
        $outssl = $outRAW +"_RC4.txt"
        $tc = linecount $outssl
        if ($tc -gt 1) {     
            $tlsstat = grep $outssl "Secure Renegotiation"
            $varstat = $($tlsstat -replace "Secure Renegotiation"," ").Trim()
            if($varstat -match "IS supported") { 
                $sregneg = $true
                if($vv -eq $true) { fmtOUT "SecureReneg" "Yes" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name SecureReneg -Value "Yes" 
            } else {
                if($vv -eq $true) { fmtOUT "SecureReneg" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name SecureReneg -Value "No"
            }
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        }
        # Check for Susceptiblity to FREAK, POODLE and HEARTBLEED
        if($v -eq $true -or $vv -eq $true) { Write-Host "`nCheck for Susceptiblity" -ForegroundColor Gray }
        # LogJam
        #s_client -connect trn2usa.cp.target.com:443 -cipher "EDH" | Select-String -Pattern "Server Temp Key"
        $outssl = $outRAW + "_LOGJAM.txt"
        delLOG $outssl
        $AllArgs ="s_client -connect $WebsiteURL`:$Port -cipher 'EDH' | Select-String -Pattern 'Server Temp Key'"
        $tlsstat = killprocess $openssl $AllArgs "Protocols advertised by server" $outssl


        # CRIME
        # Repeatly connect SSL connections against a target and Compression is Enabled
        if($compres = $false) {
            if($vv -eq $true) { fmtOUT "CRIME" "Yes" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name CRIME -Value "Yes"
        } else {
            if($vv -eq $true) { fmtOUT "CRIME" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name CRIME -Value "No"
        }
        $tlsstat = $null
        $varstat = $null
        # CRIME SPDY
        $outssl = $outRAW + "_CRIME_SPDY.txt"
        # if"Protocols advertised by server" or SPDY is not reported
        delLOG $outssl
        
        $AllArgs ="s_client -nextprotoneg NULL -connect $WebsiteURL`:$Port"
        $tlsstat = killprocess $openssl $AllArgs "Protocols advertised by server" $outssl 
        $t1 = boolgrep $openssl "SPDY"
        $tc = linecount $outssl
        if ($tc -gt 1) {  
            if($tlsstat -eq $true -or $t1 -eq $true) {
                if($vv -eq $true) { fmtOUT "CRIMESPDY" "Yes" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name CRIMESPDY -Value "Yes"
            } else {
                if($vv -eq $true) { fmtOUT "CRIMESPDY" "No"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name CRIMESPDY -Value "No"
            }
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "CRIMESPDY" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name CRIMESPDY -Value "No"
        }
        $freak = $false
        $outssl = $outRAW +"_FREAK.txt"
        delLOG $outssl
        
        $AllArgs ="s_client -connect $WebsiteURL`:$Port -cipher EXPORT -state"
        $t0 = killprocess $openssl $AllArgs $null $outssl 
        $t1 = boolgrep $outssl "handshake failure" 
        $t2 = boolgrep $outssl "no peer certificate available"
        $tlsstat = grep $outssl "Cipher    :"
        $varstat = $($tlsstat -replace "Cipher    :"," ").Trim()
        $tc = linecount $outssl
        if ($tc -gt 1) {
            if($t1 -eq $true -or $t2 -eq $true) {
                if($vv -eq $true) { fmtOUT "FREAK" "No"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name FREAK -Value "No"
                $freak = $false
            } else {
                if($varstat -match "EXP") {
                    if($vv -eq $true) { fmtOUT "FREAK" "Yes" }
                    $outOBJ | Add-Member -MemberType NoteProperty -Name FREAK -Value "Yes"
                    $freak = $true
                } else {
                    if($vv -eq $true) { fmtOUT "FREAK" "No"}
                    $outOBJ | Add-Member -MemberType NoteProperty -Name FREAK -Value "No"
                    $freak = $false
                }
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $t0 = $null
        $t1 = $null
        $t2 = $null
        $varstat = $null
        $tlsstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "FREAK" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name FREAK -Value "No"
        }
        $outssl = $outRAW +"_HEARTBLEED.txt"
        delLOG $outssl
        $AllArgs ="s_client -tlsextdebug -connect $WebsiteURL`:$Port"
        $tlsstat = killprocess $openssl $AllArgs "TLS server extension `"heartbeat`" " $outssl 
        $tc = linecount $outssl
        if ($tc -gt 1) {  
            if($t1 -eq $true -and $t2 -eq $true) {
                if($vv -eq $true) { fmtOUT "HEARTBLEED" "Yes"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name HEARTBLEED -Value "Yes"
            } else {
                if($vv -eq $true) { fmtOUT "HEARTBLEED" "No"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name HEARTBLEED -Value "No"
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $nulll
        $tlstemp = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "HEARTBLEED" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name HEARTBLEED -Value "No"
        }
        if($ssl3 -eq $true) {
            if($fallback -eq $true) {
                if($vv -eq $true) { fmtOUT "FALLBACK" "No"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name FALLBACK -Value "No"
            } else {
                if($vv -eq $true) { fmtOUT "FALLBACK" "Yes"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name FALLBACK -Value "Yes"
            }
        } else {
            if($vv -eq $true) { fmtOUT "FALLBACK" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name FALLBACK -Value "No"
        }
        # Lucky-13
        # While theoretically possible, it is fairly difficult to exploit. It is a timing attack and you would need to create a fairly 
        # large number of connections and measure the differences in timing.
        if($tls10 -eq $true) {
            if($rc4 -eq $true) {
                if($vv -eq $true) { fmtOUT "Lucky13" "Yes"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name Lucky13 -Value "Yes"
            } else {
                if($vv -eq $true) { fmtOUT "Lucky13" "No"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name Lucky13 -Value "No"
            }
        } else {
            if($vv -eq $true) { fmtOUT "Lucky13" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name Lucky13 -Value "No"
        }
        # BEAST
        if($tls10 -eq $true) {
            if($cbc -eq $true) {
                if($vv -eq $true) { fmtOUT "BEAST" "Yes" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name BEAST -Value "Yes"
            } else {
                if($vv -eq $true) { fmtOUT "BEAST" "No" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name BEAST -Value "No"
            }
        } else {
            if($vv -eq $true) { fmtOUT "BEAST" "No" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name BEAST -Value "No"
        }
        #Anonymous cipher suites 
        $outssl = $outRAW +"_aNULL.txt"
        delLOG $outssl
        
        $AllArgs ="s_client -cipher aNULL -connect $WebsiteURL`:$Port"
        $tlsstat = killprocess $openssl $AllArgs "no peer certificate available" $outssl 
        $tc = linecount $outssl
        if ($tc -gt 1) {  
            if($tlsstat[2] -eq $true) {
                if($vv -eq $true) { fmtOUT "AnonymousCipher" "No"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name AnonymousCipher -Value "No"
            }
            if($tlsstat[2] -eq $false) {
                if($vv -eq $true) { fmtOUT "AnonymousCipher" "Yes" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name AnonymousCipher -Value "Yes"
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "AnonymousCipher" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name AnonymousCipher -Value "No"
        }
        $outssl = $outRAW +"_WEAK.txt"
        delLOG $outssl
        $AllArgs ="s_client -cipher LOW:EXP:eNULL:aNULL -connect $WebsiteURL`:$Port -state"
        $tlsstat = killprocess $openssl $AllArgs "no peer certificate available" $outssl 
        $tc = linecount $outssl
        if ($tc -gt 1) { 
            if($tlsstat -eq $true -and $freak -eq $false) {
                if($vv -eq $true) { fmtOUT "WeakCipher" "No"}
                $outOBJ | Add-Member -MemberType NoteProperty -Name WeakCipher -Value "No"
            } else {
                if($vv -eq $true) { fmtOUT "WeakCipher" "Yes" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name WeakCipher -Value "Yes"
            }
            Copy-Item -Path $outssl -Destination $destraw
        $outssl = $null
        $AllArgs = $null
        $tlsstat = $null 
        $tc = $null
        } else {
            if($vv -eq $true) { fmtOUT "WeakCipher" "No"}
            $outOBJ | Add-Member -MemberType NoteProperty -Name WeakCipher -Value "No"
        }
    } else {
        $outOBJ | Add-Member -MemberType NoteProperty -Name RevocationFlag -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name RevocationMode -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name VerificationFlags -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SslProtocol -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CheckCertRevocationStatus -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CipherAlgorithm -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CipherStrength -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name HashAlgorithm -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name HashStrength -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name KeyExchangeAlgorithm -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name KeyExchangeStrength -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CertFormat -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CertExpiration -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CertIssueDate -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CertIssuer -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SerialNumber -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CertSubject -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CertType -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CertKeySize -Value "NA"        
        $outOBJ | Add-Member -MemberType NoteProperty -Name ValidDays -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv1 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv2 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SSLv3 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv1 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv11 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name TLSv12 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name Ciphers -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SelfSigned -Value "NA" 
        $outOBJ | Add-Member -MemberType NoteProperty -Name HSTS -Value "NA"        
        $outOBJ | Add-Member -MemberType NoteProperty -Name FALLBACK -Value "NA" 
        $outOBJ | Add-Member -MemberType NoteProperty -Name OCSP -Value "NA" 
        $outOBJ | Add-Member -MemberType NoteProperty -Name RC4 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name Compression -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SecureReneg -Value "NA"                 
        $outOBJ | Add-Member -MemberType NoteProperty -Name CRIME -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name CRIMESPDY -Value "NA"     
        $outOBJ | Add-Member -MemberType NoteProperty -Name FREAK -Value "NA"       
        $outOBJ | Add-Member -MemberType NoteProperty -Name HEARTBLEED -Value "NA"   
        $outOBJ | Add-Member -MemberType NoteProperty -Name Lucky13 -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name BEAST -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name ANAnymousCipher -Value "NA"
        $outOBJ | Add-Member -MemberType NoteProperty -Name WeakCipher -Value "NA"
    }     
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   Windows Management Interface   <<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($v -eq $true -or $vv -eq $true) { Write-Host "`nChecking if $WebsiteURL will accept remote request via the Get-WmiObject Cmdlet" }
    if((checkWMI $WebsiteURL) -eq $true) {
        if($vv -eq $true) { $sw = [Diagnostics.Stopwatch]::StartNew() }
        $outOBJ | Add-Member -MemberType NoteProperty -Name WMI -Value "Allowed"
        #$nwINFO = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $WebsiteURL
        $nwINFO = Get-WMIObjectCustom -Class Win32_NetworkAdapterConfiguration -ComputerName $WebsiteURL -TimeoutInSeconds 60
        $outOBJ | Add-Member -MemberType NoteProperty -Name SubnetMask -Value ($nwINFO.IPSubnet | & {$ofs=';';"$($nwINFO.IPSubnet)"}).TrimEnd(";")
        $outOBJ | Add-Member -MemberType NoteProperty -Name DefaultGateway -Value ($nwINFO.DefaultIPGateway | & {$ofs=';';"$($nwINFO.DefaultIPGateway)"}).TrimEnd(";")
        $outOBJ | Add-Member -MemberType NoteProperty -Name MACAddress -Value ($nwINFO.MACAddress | & {$ofs=';';"$($nwINFO.MACAddress)"}).TrimEnd(";")
        $outOBJ | Add-Member -MemberType NoteProperty -Name DNSServerSearchOrder -Value ($nwINFO.DNSServerSearchOrder | & {$ofs=';';"$($nwINFO.DNSServerSearchOrder)"}).TrimEnd(";")
        $outOBJ | Add-Member -MemberType NoteProperty -Name DHCPEnabled -Value ($nwINFO.DHCPEnabled)[0]
        if($v -eq $true -or $vv -eq $true) { 
            fmtOUT "Subnet Mask" ($nwINFO.IPSubnet | & {$ofs=';';"$($nwINFO.IPSubnet)"}).TrimEnd(";")
            fmtOUT "Default GW" ($nwINFO.DefaultIPGateway | & {$ofs=';';"$($nwINFO.DefaultIPGateway)"}).TrimEnd(";")
            fmtOUT "MAC Address" ($nwINFO.MACAddress | & {$ofs=';';"$($nwINFO.MACAddress)"}).TrimEnd(";")
            fmtOUT "DNS Servers" ($nwINFO.DNSServerSearchOrder | & {$ofs=';';"$($nwINFO.DNSServerSearchOrder)"}).TrimEnd(";")
            fmtOUT "DHCP Enabled" ($nwINFO.DHCPEnabled)[0]

            if($vv -eq $true) { 
                $sw.Stop()
                $ms = $sw.Elapsed.Milliseconds
                $sec = $sw.Elapsed.Seconds
                $min = $sw.Elapsed.Minutes
                $hrs = $sw.Elapsed.Hours
                $to = "$hrs`:$min`:$sec`:$ms"
                fmtOUT "Elasped Time to complete" $to
            }
        }
    } else {
        Write-Warning "Could not access $WebsiteURL using Get-WmiObject.  This host should be further reviewed to determine cause."
        $outOBJ | Add-Member -MemberType NoteProperty -Name WMI -Value "Not Allowed"
        $outOBJ | Add-Member -MemberType NoteProperty -Name SubnetMask -Value "UNK"
        $outOBJ | Add-Member -MemberType NoteProperty -Name DefaultGateway -Value "UNK"
        $outOBJ | Add-Member -MemberType NoteProperty -Name MACAddress -Value "UNK"
        $outOBJ | Add-Member -MemberType NoteProperty -Name DNSServerSearchOrder -Value "UNK"
    }
    if($testall -eq $true) {
        Write-Host "Hold on, we're digging deeper, might be a good time to get a refill..."
        if((checkWMI $WebsiteURL) -eq $true) {
            # Ref http://www.youdidwhatwithtsql.com/ping-all-domain-computers-with-powershell/209/
            if($vv -eq $true) { Write-Host "Grabbing host details..." }
            if ([bool](gwmi win32_computersystem -ComputerName $WebsiteURL).partofdomain -eq $true) {
                $outOBJ | Add-Member -MemberType NoteProperty -Name Domain -Value (gwmi win32_computersystem -ComputerName $WebsiteURL).Domain
            } else {
                $outOBJ | Add-Member -MemberType NoteProperty -Name Domain -Value "UNK"
            }
            $csINFO = Get-WMIObjectCustom -Class Win32_ComputerSystem -ComputerName $WebsiteURL -TimeoutInSeconds 60
            #$csINFO = gwmi win32_computersystem -ComputerName $WebsiteURL
            if($vv -eq $true) { Write-Host "Getting the currently logged on user" }
            $outOBJ | Add-Member -MemberType NoteProperty -Name Username -Value $csINFO.UserName
            if($vv -eq $true) { fmtOUT "Logged on User" $csINFO.UserName }
            if($vv -eq $true) { Write-Host "Determining if part of domain..." }
            $outOBJ | Add-Member -MemberType NoteProperty -Name PartOfDomain -Value $csINFO.PartOfDomain
            if($vv -eq $true) { fmtOUT "Part of Domain" $csINFO.PartOfDomain }
            if($vv -eq $true) { Write-Host "Determining Roles..." }
            $outOBJ | Add-Member -MemberType NoteProperty -Name Roles -Value ($csINFO.Roles | & {$ofs=';';"$($csINFO.Roles)"}).TrimEnd(";")               
            if($vv -eq $true) { fmtOUT "Roles" ($csINFO.Roles | & {$ofs=';';"$($csINFO.Roles)"}).TrimEnd(";") }
            if($vv -eq $true) { Write-Host "Determining Host Domain Type" }
            switch($csINFO.DomainRole) {
                0 { $msg = "Standalone Workstation" }
                1 { $msg = "Member Workstation" }
                2 { $msg = "Standalone Server" }
                3 { $msg = "Member Server" }
                4 { $msg = "Backup Domain Controller" }
                5 { $msg = "Primary Domain Controller" }
                default { $msg = $null }
            }
            $outOBJ | Add-Member -MemberType NoteProperty -Name DomainRole -Value $msg
            if($vv -eq $true) { fmtOUT "Domain Role" $msg }
            $msg = $null
            if($vv -eq $true) { Write-Host "Determining System Type..." }
            $outOBJ | Add-Member -MemberType NoteProperty -Name SystemType -Value $csINFO.SystemType
            if($vv -eq $true) { fmtOUT "SystemType" $csINFO.SystemType }
            switch($csINFO.PowerOnPasswordStatus) {
                0 { $msg = "Disabled" }
                1 { $msg = "Enabled" }
                2 { $msg = "Not Implemented" }
                3 { $msg = "Unknown" }
                default { $msg = $null }
            }
            $outOBJ | Add-Member -MemberType NoteProperty -Name PowerOnPassword -Value $msg
            if($vv -eq $true) { fmtOUT "Power on Password" $msg }
            $msg = $null
            if($vv -eq $true) { Write-Host "Determining System hardware security settings..." }
            # System hardware security settings for administrator password status
            switch($csINFO.AdminPasswordStatus) {
                0 { $msg = "Disabled" }
                1 { $msg = "Enabled" }
                2 { $msg = "Not Implemented" }
                3 { $msg = "Unknown" }
                default { $msg = "Unknown" }
            }
            if($vv -eq $true) { fmtOUT "AdminPasswordStatus" $msg }
            $outOBJ | Add-Member -MemberType NoteProperty -Name AdminPasswordStatus -Value $msg
            $msg = $null
            $CPUname = (Get-WMIObjectCustom -Class Win32_Processor -ComputerName $WebsiteURL -TimeoutInSeconds 60).Name
            fmtOUT "CPU" $CPUname
            $outOBJ | Add-Member -MemberType NoteProperty -Name CPU -Value $CPUname
            if($vv -eq $true) { Write-Host "Determining Drives and Freespace..." }
            if($psver -eq 4) {
                Get-WMIObjectCustom -Class Win32_LogicalDisk -ComputerName $WebsiteURL -TimeoutInSeconds 60 | Ft -GroupBy DriveType DeviceID,ProviderName,FreeSpace,Size,VolumeName | Out-File $outHOST -Append
                #gwmi Win32_LogicalDisk -ComputerName $WebsiteURL | Ft -GroupBy DriveType DeviceID,ProviderName,FreeSpace,Size,VolumeName | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Determining USB Devices..." }
                Get-WMIObjectCustom -Class Win32_USBControllerDevice -ComputerName $WebsiteURL -TimeoutInSeconds 60  | Sort Manufacturer,Description,DeviceID | Ft -GroupBy Manufacturer Description,Service,DeviceID | Out-File $outHOST -Append
                #gwmi Win32_USBControllerDevice -ComputerName $WebsiteURL |%{[wmi]($_.Dependent)} | Sort Manufacturer,Description,DeviceID | Ft -GroupBy Manufacturer Description,Service,DeviceID | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering running Services..." }
                Get-WMIObjectCustom -Class Win32_Service -ComputerName $WebsiteURL -TimeoutInSeconds 60 | Out-File $outHOST -Append
                #gwmi Win32_Service -ComputerName $WebsiteURL | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering installed Patches..." }
                Get-WMIObjectCustom -Class  Win32_QuickFixEngineering  -ComputerName $WebsiteURL -TimeoutInSeconds 60 | Out-File $outHOST -Append
                #gwmi Win32_QuickFixEngineering -ComputerName $WebsiteURL | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering UserProfiles..." }
                Get-WMIObjectCustom -Class  Win32_UserProfile  -ComputerName $WebsiteURL -TimeoutInSeconds 60 | Out-File $outHOST -Append
                #gwmi Win32_UserProfile -ComputerName $WebsiteURL | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering UserAccount..." }
                Get-WMIObjectCustom -Class  Win32_UserAccount -ComputerName $WebsiteURL -TimeoutInSeconds 60 | Out-File $outHOST -Append
                #gwmi Win32_UserAccount -Namespace "root\cimv2" -ComputerName $WebsiteURL | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discoverying what AntiVirus is Installed..." }
                Get-LHSAntiVirusProduct $WebsiteURL | Out-File $outHOST -Append
                fmtOUT "AntiVirus" (Get-LHSAntiVirusProduct $WebsiteURL).Name
                $outOBJ | Add-Member -MemberType NoteProperty -Name AntiVirus -Value (Get-LHSAntiVirusProduct $WebsiteURL).Name
            }
            if($psver -eq 2) {
                Get-WMIObject -Class Win32_LogicalDisk -ComputerName $WebsiteURL | Ft -GroupBy DriveType DeviceID,ProviderName,FreeSpace,Size,VolumeName | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Determining USB Devices..." }
                Get-WMIObject -Class Win32_USBControllerDevice -ComputerName $WebsiteURL  | Sort Manufacturer,Description,DeviceID | Ft -GroupBy Manufacturer Description,Service,DeviceID | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering running Services..." }
                Get-WMIObject -Class Win32_Service -ComputerName $WebsiteURL | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering installed Patches..." }
                Get-WMIObject -Class  Win32_QuickFixEngineering  -ComputerName $WebsiteURL | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering UserProfiles..." }
                Get-WMIObject -Class  Win32_UserProfile  -ComputerName $WebsiteURL | Out-File $outHOST -Append
                if($vv -eq $true) { Write-Host "Discovering UserAccount..." }
                Get-WMIObject -Class  Win32_UserAccount -ComputerName $WebsiteURL | Out-File $outHOST -Append
                
                $Obj = @()
                if((checkWMI $WebsiteURL) -eq $true) {
                    $OSVersion = (Get-WmiObject win32_operatingsystem -computername $WebsiteURL).version
                    $OS = $OSVersion.split(".")
                    if ($OS[0] -eq "5") {
                        Try {
                            $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $WebsiteURL -ErrorAction Stop
                        } Catch {
                            Continue
                        }    
                        $Register = $AntiVirusProduct.__Server;
                        $Name = $AntiVirusProduct.displayName;
                        $av1 = $AntiVirusProduct.versionNumber;
                        $av2= $AntiVirusProduct.onAccessScanningEnabled;
                        $av3 = $AntiVirusProduct.productUptoDate
                        $outSTR = "$Register$Name$av1$av2$av3"
                        if($outSTR -notcontains $outARRAY) {
                            $OutputString = [string]""
                            $OutputString += ($Register.ToUpper()).Trim() + "," + $Name + "," + $av1 + "," + $av2 + "," + $av3
                            $Obj += $OutputString
                            [array]$outARRAY = $outSTR
                        }
                    } 
                    if ($OS[0] -eq "6") {
                        Try {
                            $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $WebsiteURL -ErrorAction Stop
                        } Catch { }                
                        switch ($AntiVirusProduct.productState) {
                            "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                            "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                            "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                            "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                            "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                            "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                            "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                            "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                            "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                            "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                            default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
                        }            
                        $Register = $AntiVirusProduct.__Server
                        $Name = $AntiVirusProduct.displayName
                        $av1 = $AntiVirusProduct.pathToSignedProductExe
                        $av2 = $defstatus
                        $av3 = $rtstatus
                        $outSTR = "$Register$Name$av1$av2$av3" 
                        if($outSTR -notcontains $outARRAY) {
                            $OutputString = [string]""
                            $OutputString += ($Register.ToUpper()).Trim() + "," + $Name + "," + $av1 + "," + $av2 + "," + $av3
                            $Obj += $OutputString
                            [array]$outARRAY = $outSTR
                        }
                    } 
                }
            } else {  
                $Register = $WebsiteURL;
                $Name = "Unknown";
                $av1 = "Unknown";
                $av2 = "Unknown";
                $av3 = "Unknown";
                $outSTR = "$Register$Name$av1$av2$av3" 
                if($outSTR -notcontains $outARRAY) {
                    $OutputString = [string]""
                    $OutputString += ($Register.ToUpper()).Trim() + "," + $Name + "," + $av1 + "," + $av2 + "," + $av3
                    $Obj += $OutputString
                    [array]$outARRAY = $outSTR
                }
            } 
            Write-Output "Anti-Virus" | Out-File $outHOST -Append
            $Obj | Out-File $outHOST -Append              
            }            
        } else {
            if($vv -eq $true) { Write-Host "WMI request were not accepted..." }
            $outOBJ | Add-Member -MemberType NoteProperty -Name Domain -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name DHCPEnabled -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name Username -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name PartOfDomain -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name Roles -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name SystemType -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name DomainRole -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name SystemType -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name PowerOnPassword -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name AdminPasswordStatus -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name CPU -Value "UNK"
            $outOBJ | Add-Member -MemberType NoteProperty -Name AntiVirus -Value "UNK"
        }
        #
        ####> Not WMI Dependent
        #
        if($v -eq $true -or $vv -eq $true) { Write-Host "Doing an old-fashion net view to see what shares are available." }
        Write-Ouput "net view \\$WebsiteURL" | Out-File $outHOST -Append
        net view \\$WebsiteURL | Out-File $outHOST -Append
        if($v -eq $true -or $vv -eq $true) { Write-Host "Checking what processes are running..." }
        Write-Output "Get-Process -ComputerName $WebsiteURL" | Out-File $outHOST -Append
        Get-Process -ComputerName $WebsiteURL | Out-File $outHOST -Append
        if($v -eq $true -or $vv -eq $true) { Write-Host "Now checking who is in the Administrators group..." }
        $computer = [ADSI]("WinNT://" + $WebsiteURL.Trim() + ",computer")
        $AdminGroup = $computer.psbase.children.find("Administrators")
        $admins = ($AdminGroup.psbase.invoke("Members") | %{$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)})
        Write-Output "Administrator groups" | Out-File $outHOST -Append
        $admins | & {$ofs=';';"$admins"} | Out-File $outHOST -Append
        if($vv -eq $true) { fmtOUT "Admins" ($admins | & {$ofs=';';"$admins"}) }
        if($v -eq $true -or $vv -eq $true) { Write-Host "Made a copy for safe keeping (i.e., further analysis later)" }
        # Grab whatever info is in the registry regarding the host
        if($v -eq $true -or $vv -eq $true) { Write-Host "Going through the registry to see what comes up" }
        if($psver -eq 4) {
            Write-Output "Get-HWInfo $WebsiteURL" | Out-File $outHOST -Append
            Get-HWInfo $WebsiteURL | Out-File $outHOST -Append
            if($v -eq $true -or $vv -eq $true) { Write-Host "Checking what Tasks are Scheduled to be executed" }
            Write-Output "Get-ScheduledTask $WebsiteURL" | Out-File $outHOST -Append
            Get-ScheduledTask $WebsiteURL | Out-File $outHOST -Append
        }
        Get-WmiObject -Class Win32_BIOS -ComputerName $WebsiteURL | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_Processor -ComputerName $WebsiteURL | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_ComputerSystem -ComputerName $WebsiteURL | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_OperatingSystem -ComputerName $WebsiteURL | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $WebsiteURL | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_LogonSession -ComputerName $WebsiteURL | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_ComputerSystem -Property UserName -ComputerName $WebsiteURL | Select-Object -Property *user* | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_LocalTime -ComputerName $WebsiteURL | Select-Object -Property *user* | Out-File $outHOST -Append
        Get-WmiObject -Class Win32_Service -ComputerName $WebsiteURL | Format-Table -Property Status,Name,DisplayName -AutoSize -Wrap | Out-File $outHOST -Append
        # Put a copy of the report on the file server
        Copy-Item -Path $outHOST -Destination $nwRAWDATA -Force -ErrorAction SilentlyContinue
        #
        ####> Security Log
        #    
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>      Event ID      <<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
if($events -eq $true) {
            $Obj = @()
            function outcap($item) {
                $ac = ([regex]"(?i)\bAccount Name:\s+\w+\b").matches($item.Message) | select -prop value | %{ (($_.value -split ":")[1]) -replace "\s+","" }
                if($ac -match "($item.MachineName [A-Z]*)") { $ac = $ac.split(" ")[1] }
                $lt = ([regex]"(?i)\bLogon Type:\s+(\d){1,2}\b").matches($item.Message) | select -prop value | %{ (($_.value -split ":")[1]) -replace "\s+","" }
                $outOBJ | Add-Member -MemberType NoteProperty -Name Register -Value ($WebsiteURL.ToUpper()).Trim()
                if($lt -ne 5 -or $ac -inotmatch "($item.MachineName)") {
                    switch($lt) {
                        2 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Interactive" 
                            }
                        3 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Network" 
                            }
                                    
                        4 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Batch" 
                            }
                        5 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Service" 
                            }
                                        
                        7 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Unlock" 
                            }
                        8 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Cleartext" 
                            }
                        10 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Remote" 
                            }
                        11 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                            $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                            $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Cache" 
                            }
                    }
                    $outOBJ | Add-Member -MemberType NoteProperty -Name Hash -Value ($outOBJ.Register + $outOBJ.AccountName + $outOBJ.EventID + $outOBJ.LogonType).ToString()
                    if($outOBJ) { return $outOBJ }
                }
            }
            $logname="Security"
            foreach($seclog in (Get-EventLog -AsBaseObject -LogName $logname -ComputerName $WebsiteURL | where { $_.TimeWritten -gt ((get-date).adddays(-2)) } -ErrorAction Stop ) ) {
                $outOBJ = New-Object -TypeName PSobject
                if($logname -imatch "Security") {
                    switch($seclog.EventID) {
                        # Special privileges assigned
                        { $_ -match "(4672)" } { $outOBJ = outcap $seclog }
                        # Changed
                        { $_ -match "(47(20|22|23|24|38|67|81))" } { $outOBJ = outcap $seclog }
                        # Group Created
                        { $_ -match "(47(27|31|54))" } { $outOBJ = outcap $seclog }
                        # Group Changed
                        { $_ -match "(47(33|35|37|55))" } { $outOBJ = outcap $seclog }
                        # Logon Session Events - Remote re/dis connected
                        { $_ -match "(47(78|79))" } { $outOBJ = outcap $seclog }
                        # Logon Type
                        { $_ -match "(46(24|25))" } { $outOBJ = outcap $seclog }
                    }
                }
                if($outOBJ.Hash -notcontains $outARRAY) {
                    if($outOBJ.AccountName) {
                        $OutputString = [string]""
                        $OutputString += ($WebsiteURL.ToUpper()).Trim() + "," + $outOBJ.AccountName + "," + $outOBJ.EventID+ "," + $outOBJ.LogonType + "," + $outOBJ.LogonTypeDesc
                        $Obj += $OutputString
                        [array]$outARRAY = $outOBJ.Hash
                    }
                }
            }
            Write-Output "Event-ID" | Out-File $outHOST -Append
            $Obj | Out-File $outHOST -Append      
}
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>      Encryption Enable      <<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
if($bitset -eq $true) {
    if($vv -eq $true) { Write-Host "Checking if Encryption is enabled on the GPD" }
    $encrytstat = Select-String -Path \\$WebsiteURL\C$\CommonPOS\Logs\vfquery-VfE2EOff.log -Pattern "E2EE_ENCRYPT=(\d){1,2}" -AllMatches | %{$_.Matches}| %{$_.Value} | ? { $_ } | sort -Unique
    $encrytstat = $encrytstat | & {$ofs=';';"$encrytstat"}
    $outOBJ | Add-Member -MemberType NoteProperty -Name VfE2EOff -Value $encrytstat
    if($vv -eq $true) { fmtOUT "GPD Encryption" $encrytstat }
}
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>        Journal File      <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($journal -eq $true) {
        if($v -eq $true -or $vv -eq $true) { Write-Host "Gathering Information about the Register and GPD..." }
        # Register SN
        if($vv -eq $true) { Write-Host "Register's SN" }
        if((checkWMI $WebsiteURL) -eq $true) {
            try {
                $msg = (Get-WMIObjectCustom -Class Win32_BIOS -ComputerName $WebsiteURL -TimeoutInSeconds 60).SerialNumber
                $outOBJ | Add-Member -MemberType NoteProperty -Name REGSN -Value $msg
                fmtOUT "REGSN" $msg
                $msg = $null
            } catch {
                continue
            }
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name REGSN -Value "UNK" 
        }
        #GPD Model
        if($vv -eq $true) { Write-Host "GPD Model" }
        $gpdMODEL = Select-String -Path \\$WebsiteURL\C$\CommonPOS\Logs\vf*.log -Pattern "MODEL=[a-z0-9A-Z]*" -AllMatches | %{$_.Matches}| %{$_.Value} | %{$_ -replace "MODEL=",""} | ? { $_ } | sort -Unique
        if($gpdMODEL.Count -gt 1) { $outOBJ | Add-Member -MemberType NoteProperty -Name GPDModel -Value $($gpdMODEL | & {$ofs=';';"$gpdMODEL"}) }
        if($gpdMODEL.Count -eq 1) { $outOBJ | Add-Member -MemberType NoteProperty -Name GPDModel -Value $gpdMODEL }
        if(!$gpdMODEL) { $outOBJ | Add-Member -MemberType NoteProperty -Name GPDModel -Value "UNK" }
        # GPD SN
        if($vv -eq $true) { Write-Host "GPD's SN" }
        $gsntxt = Select-String -Path \\$WebsiteURL\C$\CommonPOS\Logs\* -pattern "PinPadSerialNumber.(\d){3}-(\d){3}-(\d){3}" -AllMatches | %{$_.Matches}| %{$_.Value} | %{$_ -replace "PinPadSerialNumber.",""} | ? { $_ } | sort -Unique
        if($gsntxt.Count -gt 1) { $outOBJ | Add-Member -MemberType NoteProperty -Name GPDSN -Value $($gsntxt | & {$ofs=';';"$gsntxt"}) }
        if($gsntxt.Count -eq 1) { $outOBJ | Add-Member -MemberType NoteProperty -Name GPDSN -Value $gsntxt }
        if(!$gsntxt) { $outOBJ | Add-Member -MemberType NoteProperty -Name GPDSN -Value "UNK" }  
        # Check if port 15 enabled
        if($vv -eq $true) { Write-Host "Checking what port the GPD is on, should be COM15..." }
        if((checkWMI $WebsiteURL) -eq $true) { 
            $verifone = gwmi Win32_USBControllerDevice -ComputerName $WebsiteURL -ErrorAction SilentlyContinue | % { [wmi]($_.Dependent) } 
        }
        if($verifone.Service -contains "VFIUNIUSB") {
            $vfnum = 0..($verifone.Name.Count - 1) | Where { $verifone.Name[$_] -match "Mx Family POS Terminal" }
            $comstatus = $verifone.Name[$vfnum]
        } else {
            $comstatus = "UNK"
        }
        $outOBJ | Add-Member -MemberType NoteProperty -Name COMStatus -Value $comstatus
        # VSS_KSN
        if($vv -eq $true) { Write-Host "VSS KSN" }
        $vssksn = Select-String -Path \\$WebsiteURL\C$\CommonPOS\Logs\* -Pattern "VSS_KSN.(\d)[A-Z](\d){11}[A-Z]*(\d){5}" -AllMatches | %{$_.Matches}| %{$_.Value} | %{$_ -replace "VSS_KSN=",""} | ? { $_ } | sort -Unique
        if($vssksn.Count -gt 1) { $outOBJ | Add-Member -MemberType NoteProperty -Name VSSKSN -Value $($vssksn | & {$ofs=';';"$vssksn"}) }
        if($vssksn.Count -eq 1) { $outOBJ | Add-Member -MemberType NoteProperty -Name VSSKSN -Value $vssksn }
        if(!$gsntxt) { $outOBJ | Add-Member -MemberType NoteProperty -Name VSSKSN -Value "UNK" }
        #Encryption
        if($vv -eq $true) { Write-Host "Is Encryption set..." }
        $encryptSTATUS = Select-String -Path \\$WebsiteURL\C$\CommonPOS\Logs\vf*.log -Pattern "Encryption State=(Off|On)" -AllMatches | %{$_.Matches}| %{$_.Value} | %{$_ -replace "Encryption State=",""} | ? { $_ } | sort -Unique
        if(!$encryptSTATUS) { $encryptSTATUS= "UNK" }
        $outOBJ | Add-Member -MemberType NoteProperty -Name EncryptionStatus -Value $encryptSTATUS
        if($v -eq $true -or $vv -eq $true) { 
            fmtOUT "Model" $gpdMODEL
            fmtOUT "GPD SN" $($gsntxt | & {$ofs=';';"$gsntxt"})
            fmtOUT "GPD USB" $comstatus
            fmtOUT "VSS KSN" $vssksn
            fmtOUT "Encryption Status" $encryptSTATUS
        }
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>          Tree         <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($tsttree -eq $true -or $testall -eq $true) { 
        if($v -eq $true -or $vv -eq $true) { Write-Host "Gathering Information directory tree" }  
        Get-ChildItem -Path \\$WebsiteURL\C$ | Tree | Out-File $outHOST -Append
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>        Dump File      <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($tstdmp -eq $true) {
        if($vv -eq $true) { Write-Host "Looking to see if the register is configured for where the crash dump file should go" }
        $dmpstatus = $false
        $dmpfolder = $null
        if($v -eq $true -or $vv -eq $true){ Write-Host "Checking for Dump Folder" }
        $LD = @("LocalDumps","LocalDump")
        foreach($LocalDump in $LD) { 
            $chkLD = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\" + $LocalDump + "\POS.exe"
            #fmtOUT "LocalDump" $chkLD
            if(([bool][Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$WebsiteURL).OpenSubKey($chkLD).GetValue('DumpFolder')) = $true) {  
                fmtOUT "Registry Key" "Enabled"
                $dmpfolder = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$WebsiteURL).OpenSubKey($chkLD).GetValue('DumpFolder')
                fmtOUT "Dump Folder" $dmpfolder
                $tmpdir = "Windows\" + ($dmpfolder -replace "[%WINDIR%[\\]", "")
                fmtOUT "Dump Directory" $tmpdir
                $outOBJ | Add-Member -MemberType NoteProperty -Name RegKeyDump -Value "Enabled"
                $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFolder -Value $dmpfolder
                if(([bool](gci -Path \\$WebsiteURL\C$\$tmpdir -Filter *.dmp)) -eq $true) {
                    $dmpfndir = gci -Path \\$WebsiteURL\C$\$tmpdir -Filter *.dmp
                    $dmpfname = $dmpfndir.Name
                    fmtOUT "Dump Filename" $dmpfname
                    $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFilename -Value $dmpfname
                    $cclookup = Select-String -Path \\$WebsiteURL\C$\$tmpdir\$dmpfname -Pattern "^((4|5)(\d){15}|5(1|2|3|4)(\d){14}|(34|35|36|37|38)(\d){13}|30(0|1|2|3|4|5)(\d){13}|60(11|65)(\d){12}|(2131|1800)(\d){12})$" -AllMatches| %{$_.Matches}| %{$_.Value}
                    if(([bool]($cclookup)) -eq $true) {
                        fmtOUT "PAN Info" "Found"
                        $outOBJ | Add-Member -MemberType NoteProperty -Name PANInfo -Value "Found"
                    } else {
                        fmtOUT "PAN Info" "Not Found"
                        $outOBJ | Add-Member -MemberType NoteProperty -Name PANInfo -Value "Not Found"
                    } 
                } else {
                    fmtOUT "Dump Filename" "Not Found"
                    fmtOUT "PAN Info" "NA"
                    $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFilename -Value "Not Found"
                    $outOBJ | Add-Member -MemberType NoteProperty -Name PANInfo -Value "Not Found"
                }
            } else {
                fmtOUT "Registry Key" "Not Enabled"
                fmtOUT "Dump Folder" "NA"
                fmtOUT "Dump Directory" "NA"
                fmtOUT "Dump Filename" "NA"
                fmtOUT "PAN Info" "NA"
                $outOBJ | Add-Member -MemberType NoteProperty -Name RegKeyDump -Value "Not Enabled"
                $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFolder -Value "NA"
                $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFilename -Value "NA"
                $outOBJ | Add-Member -MemberType NoteProperty -Name PANInfo -Value "NA"
            }
        }
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>    Execute|Download|Write   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($remoteexe -eq $true -or $testall -eq $true) {
        if((checkWMI $WebsiteURL) -eq $true) {
            if($v -eq $true -or $vv -eq $true) { Write-Host "Checking if what actions can be performed without authentication" }
            # Can I remotely Execute
            if($vv -eq $true) { Write-Host "Remote Execution" }            
            $tmpPath = "\\$WebsiteURL\C$\Temp"
            if($tmpPath.Exists -eq $false) { 
                $tmpPath = "\\$WebsiteURL\C$"
                Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd /c ipconfig.exe /displaydns > c:\ipconfig.txt") -ComputerName $WebsiteURL -ErrorAction SilentlyContinue
            } else {
                Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd /c ipconfig.exe /displaydns > c:\temp\ipconfig.txt") -ComputerName $WebsiteURL -ErrorAction SilentlyContinue
            }
            $tstPath = Get-ChildItem -Path $tmpPath -Filter "ipconfig.txt"
            if($tstPath.Exists -eq $true) {
                fmtOUT "Execute" "Yes"
                $outOBJ | Add-Member -MemberType NoteProperty -Name RmtExecute -Value "Yes"
                $e1 = $true
            } else {
                fmtOUT "Execute" "No"
                $outOBJ | Add-Member -MemberType NoteProperty -Name RmtExecute -Value "No"
                $e1 = $false
            }
            # Can I download a file from the remote host
            if($vv -eq $true) { Write-Host "Export to a neighboring hosts" }
            Copy-Item -path "$tmpPath\ipconfig.txt" -Destination $outDNS -force
            $tstMV = Get-ChildItem -Path $outDNS
            if($tstMV.Exists -eq $true) {
                fmtOUT "Export" "Yes"
                $outOBJ | Add-Member -MemberType NoteProperty -Name RmtDownload -Value "Yes"
                $e2 = $true
            } else {
                fmtOUT "Export" "No"
                $outOBJ | Add-Member -MemberType NoteProperty -Name RmtDownload -Value "No"
                $e2 = $false
            }
            # Can I copy a file to the remote host
            if($vv -eq $true) { Write-Host "Upload a file onto $WebsiteURL" }
            Copy-Item -Path $outDNS -Destination $tmpPath -force
            $tstUP = Get-ChildItem -Path "$tmpPath\$WebsiteURL`_DISPLAYDNS.txt"
            if($tstUP.Exists -eq $true) {
                fmtOUT "Upload" "Yes"
                $outOBJ | Add-Member -MemberType NoteProperty -Name RmtUpload -Value "Yes"
                $e3 = $true
            } else {
                fmtOUT "Upload" "No"
                $outOBJ | Add-Member -MemberType NoteProperty -Name RmtUpload -Value "No"
                $e3 = $false
            }
            # Put a copy of the report on the file server
            if($e1 -eq $true -and $e2 -eq $true -and $e3 -eq $true) { 
                if($vv -eq $true) { fmtOUT "Trifecta" "All of the necessary components are there to craft an nefarious attack against $WebsiteURL" }
            }
            Copy-Item -Path $outDNS -Destination $nwRAWDATA -Force -ErrorAction SilentlyContinue
        }    
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>        Interesting Logs     <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($getlogs -eq $true) {
        if($v -eq $true -or $vv -eq $true) { Write-Host "Looking for certain log files that could potentially help craft further attacks" }
        $tmpPath = "\\$WebsiteURL\C$\CommonPOS\Logs"
        #
        #####> SithLord - SQL statements
        #
        if($vv -eq $true) { Write-Host "How funny, there's a Star Wars fan out there, but the problem is, it contains SQL statements" }
        $tmpLOG  = ( Get-ChildItem -Path $tmpPath -Filter Sithlord* -ErrorAction SilentlyContinue)
        for($i=0;$i -le $($tmpLOG.Count - 1);$i++) {
                $LogFileName = $tmpPath + "\" + $tmpLOG[$i].Name
                $LogContent = gc $LogFileName
                Add-Content $outLOGS $LogContent
        }
        if($tmpLOG) {
            $outOBJ | Add-Member -MemberType NoteProperty -Name SQLSTMT -Value "Yes"
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name SQLSTMT -Value "No"
        }
        # Put a copy of the report on the file server
        Copy-Item -Path $outLOGS -Destination $nwRAWDATA -Force -ErrorAction SilentlyContinue
    }

#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>        Firewall Rules      <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
# 
if($fwr -eq $true -or $testall -eq $true) {
    if (!($Local) -and !($Gpo)) { $Local = $true }
    $Obj = @()
    $RegistryKeys = @() 
    if ($Local) { $RegistryKeys += 'Registry::HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' } 
    if ($GPO) { $RegistryKeys += 'Registry::HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules' } 
    Foreach ($Key in $RegistryKeys) { 
        if (Test-Path -Path $Key) { 
            (Get-ItemProperty -Path $Key).PSObject.Members | 
            Where-Object {(@('PSPath','PSParentPath','PSChildName') -notcontains $_.Name) -and ($_.MemberType -eq 'NoteProperty') -and ($_.TypeNameOfValue -eq 'System.String')} | 
            ForEach-Object { 
                $HashProps = @{ 
                    NameOfRule = $_.Name 
                    RuleVersion = ($_.Value -split '\|')[0] 
                    Action = $null 
                    Active = $null 
                    Dir = $null 
                    Protocol = $null 
                    LPort = $null 
                    App = $null 
                    Name = $null 
                    Desc = $null 
                    EmbedCtxt = $null 
                    Profile = $null 
                    RA4 = $null 
                    RA6 = $null 
                    Svc = $null 
                    RPort = $null 
                    ICMP6 = $null 
                    Edge = $null 
                    LA4 = $null 
                    LA6 = $null 
                    ICMP4 = $null 
                    LPort2_10 = $null 
                    RPort2_10 = $null 
                } 
                if ($Key -match 'HKLM\\System\\CurrentControlSet') { $HashProps.RuleType = 'Local' } else { $HashProps.RuleType = 'GPO' } 
                ForEach ($FireWallRule in ($_.Value -split '\|')) { 
                    switch (($FireWallRule -split '=')[0]) { 
                        'Action' {$HashProps.Action = ($FireWallRule -split '=')[1]} 
                        'Active' {$HashProps.Active = ($FireWallRule -split '=')[1]} 
                        'Dir' {$HashProps.Dir = ($FireWallRule -split '=')[1]} 
                        'Protocol' {$HashProps.Protocol = ($FireWallRule -split '=')[1]} 
                        'LPort' {$HashProps.LPort = ($FireWallRule -split '=')[1]} 
                        'App' {$HashProps.App = ($FireWallRule -split '=')[1]} 
                        'Name' {$HashProps.Name = ($FireWallRule -split '=')[1]} 
                        'Desc' {$HashProps.Desc = ($FireWallRule -split '=')[1]} 
                        'EmbedCtxt' {$HashProps.EmbedCtxt = ($FireWallRule -split '=')[1]} 
                        'Profile' {$HashProps.Profile = ($FireWallRule -split '=')[1]} 
                        'RA4' {$HashProps.RA4 = ($FireWallRule -split '=')[1]} 
                        'RA6' {$HashProps.RA6 = ($FireWallRule -split '=')[1]} 
                        'Svc' {$HashProps.Svc = ($FireWallRule -split '=')[1]} 
                        'RPort' {$HashProps.RPort = ($FireWallRule -split '=')[1]} 
                        'ICMP6' {$HashProps.ICMP6 = ($FireWallRule -split '=')[1]} 
                        'Edge' {$HashProps.Edge = ($FireWallRule -split '=')[1]} 
                        'LA4' {$HashProps.LA4 = ($FireWallRule -split '=')[1]} 
                        'LA6' {$HashProps.LA6 = ($FireWallRule -split '=')[1]} 
                        'ICMP4' {$HashProps.ICMP4 = ($FireWallRule -split '=')[1]} 
                        'LPort2_10' {$HashProps.LPort2_10 = ($FireWallRule -split '=')[1]} 
                        'RPort2_10' {$HashProps.RPort2_10 = ($FireWallRule -split '=')[1]} 
                        Default {} 
                    } 
                }
                $outSTR = $WebsiteURL + "" + $HashProps.Action + "" + $HashProps.Active + "" + $HashProps.Dir + "" + $HashProps.Protocol + "" + $HashProps.LPort + "" + $HashProps.App + "" + $HashProps.Name + "" + $HashProps.Desc
                if($outSTR -notcontains $outARRAY) {
                    $OutputString = [string]""
                    $OutputString += ($WebsiteURL.ToUpper()).Trim() + "," + $HashProps.Action + "," + $HashProps.Active + "," + $HashProps.Dir 
                    $OutputString += $HashProps.Protocol + "," + $HashProps.LPort + "," + $HashProps.App + "," + $HashProps.Name
                    $OutputString += $HashProps.Desc + "," + $HashProps.EmbedCtxt + "," + [array]$HashProps.RA4 + "," + [array]$HashProps.RA6
                    $OutputString += $HashProps.Svc + "," + $HashProps.RPort + "," + $HashProps.ICMP6 + "," + $HashProps.Edge
                    $OutputString += [array]$HashProps.LA4 + "," + [array]$HashProps.LA6 + "," + $HashProps.ICMP4 + "," + $HashProps.LPort2_10
                    $OutputString += $HashProps.RPort2_10
                    $Obj += $OutputString
                    [array]$outARRAY = $outSTR
                }
            } 
        } 
    }
    Write-Output "Firewall Rules" | Out-File $outHOST -Append
    $Obj | Out-File $outHOST -Append
}

#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>        Version Numbers      <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($getver -eq $true) {
        if($v -eq $true -or $vv -eq $true) { Write-Host "Gathering version numbers of certain security and core applications." }
        $WinReg_HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$WebsiteURL)
        # Get the version numbers
        $outOBJ | Add-Member -MemberType NoteProperty -Name POSRelease -Value $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\POSApplication").GetValue("Version"))
        $outOBJ | Add-Member -MemberType NoteProperty -Name OpenEPSBoot -Value $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\OpenEPSBootstrap").GetValue("VersionNumber"))
        $outOBJ | Add-Member -MemberType NoteProperty -Name OpenEPSBootTS -Value $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\OpenEPSBootstrap").GetValue("InstalledOn"))
        $outOBJ | Add-Member -MemberType NoteProperty -Name LogMiner -Value $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\RegisterLogMining").GetValue("VersionNumber"))
        $outOBJ | Add-Member -MemberType NoteProperty -Name SplunkFwde -Value $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\TgtRgstrSplunkFwd").GetValue("VersionNumber"))
        $outOBJ | Add-Member -MemberType NoteProperty -Name RegHealer -Value $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\RegisterHealer").GetValue("VersionNumber"))
        $outOBJ | Add-Member -MemberType NoteProperty -Name TgtVerifoneFw -Value $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\TgtVerifoneFw").GetValue("VersionNumber"))
        
        fmtOUT "POSRelease" $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\POSApplication").GetValue("Version"))
        fmtOUT "OpenEPSBoot" $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\OpenEPSBootstrap").GetValue("VersionNumber"))
        fmtOUT "OpenEPSBootTS" $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\OpenEPSBootstrap").GetValue("InstalledOn"))
        fmtOUT "LogMiner" $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\RegisterLogMining").GetValue("VersionNumber"))
        fmtOUT "SplunkFwde" $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\TgtRgstrSplunkFwd").GetValue("VersionNumber"))
        fmtOUT "RegHealer" $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\RegisterHealer").GetValue("VersionNumber"))
        fmtOUT "TgtVerifoneFw" $($WinReg_HKLM.OpenSubKey("SOFTWARE\TTS\InstalledPackages\TgtVerifoneFw").GetValue("VersionNumber"))       
        
        if( gci '\\$WebsiteURL\C$\Program Files\' -Filter "Microtrax" -ErrorAction SilentlyContinue ) {
            $outOBJ | Add-Member -MemberType NoteProperty -Name OpenEPSDirectory -Value (Get-Item "\\$WebsiteURL\C$\Program Files\Microtrax\OpenEPS\MTX_EPS.dll" -ErrorAction Continue).VersionInfo.FileVersion
            fmtOUT "OpenEPSDirectory" (Get-Item "\\$WebsiteURL\C$\Program Files\Microtrax\OpenEPS\MTX_EPS.dll" -ErrorAction Continue).VersionInfo.FileVersion
        } else {
            $outOBJ | Add-Member -MemberType NoteProperty -Name OpenEPSDirectory -Value "File Not Found"
            fmtOUT "OpenEPSDirectory" "File Not Found"
        }
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>   Network Connectivity Status Indicator   <<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($cdms -eq $true -or $testall -eq $true) {
        if($v -eq $true -or $vv -eq $true) { 
            Write-Warn "Determining if $WebsiteURL is phoning home to Microsoft ..."
            Write-Host "`nPart of what MS calls Network Awareness, it performs a network connectivity check which provides the Network Connectivity Status Indicator (NCSI) in the system tray and network properties."
            Write-Host "However, according to MS - the time and the soource IP address of $WebsiteURL is potentially logged to www.msftncsi.com everytime a check is completed..." 
        }
        $WinReg_HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$WebsiteURL)
        # Check if EnableActiveProbing is enabled
        if($vv -eq $true) { Write-Host "According to the registry..." }
        $chkCDMS = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NLaSvc\Parameters\Internet").GetValue("EnableActiveProbing"))
        switch($chkCDMS) {
            0 { $outOBJ | Add-Member -MemberType NoteProperty -Name EnableActiveProbing -Value "Disabled"; fmtOUT "NCSI" "Disabled" }
            1 { $outOBJ | Add-Member -MemberType NoteProperty -Name EnableActiveProbing -Value "Allowed"; fmtOUT "NCSI" "Allowed" }
        }
        # Check
        if($vv -eq $true) { Write-Host "Checking if the registry for msftncsi.com|131.107.255.255|dns.msftncsi.com" }
        fmtOUT "ActiveWebProbeHost" $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeHost')
        $outOBJ | Add-Member -MemberType NoteProperty -Name ActiveWebProbeHost -Value $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeHost')
        fmtOUT "ActiveWebProbePath" $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbePath')
        $outOBJ | Add-Member -MemberType NoteProperty -Name ActiveWebProbePath -Value $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbePath')
        fmtOUT "ActiveWebProbeContent" $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeContent')
        $outOBJ | Add-Member -MemberType NoteProperty -Name ActiveWebProbeContent -Value $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeContent')
        fmtOUT "ActiveDnsProbeContent" $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeContent')
        $outOBJ | Add-Member -MemberType NoteProperty -Name ActiveDnsProbeContent -Value $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeContent')
        fmtOUT "ActiveDnsProbeHost" $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeHost')
        $outOBJ | Add-Member -MemberType NoteProperty -Name ActiveDnsProbeContent -Value $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeHost')
        $chkPOLL = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('PassivePollPeriod')
        switch($chkPOLL) {
            5 { $outOBJ | Add-Member -MemberType NoteProperty -Name PassivePollPeriod -Value $chkPOLL; fmtOUT "PassivePollPeriod" "30 Seconds" }
            10 { $outOBJ | Add-Member -MemberType NoteProperty -Name PassivePollPeriod -Value $chkPOLL; fmtOUT "PassivePollPeriod" "Every Minute" }
            default { $outOBJ | Add-Member -MemberType NoteProperty -Name PassivePollPeriod -Value $chkPOLL; fmtOUT "PassivePollPeriod" $chkPOLL }
        }
        $chkThres = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('StaleThreshold')
        $outOBJ | Add-Member -MemberType NoteProperty -Name StaleThreshold -Value $chkThres
        fmtOUT "StaleThreshold" $chkThres
        $chkTO = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('WebTimeout')
        $outOBJ | Add-Member -MemberType NoteProperty -Name WebTimeout -Value $chkTO
        fmtOUT "WebTimeout" $chkTO

        # Check Hosts file
        if($vv -eq $true) { Write-Host "Checking if the hosts contains msftncsi.com|131.107.255.255|dns.msftncsi.com" }
        $hostARRY = @()
        $hostARRAY = Select-String -Path '\\$WebsiteURL\C$\Windows\System32\drivers\etc\hosts' -Pattern "(msftncsi.com|131.107.255.255|dns.msftncsi.com)"
        if($hostARRAY) {
            fmtOUT "Hosts" $($hostARRAY | & {$ofs=';';"$hostARRAY"})
            $outOBJ | Add-Member -MemberType NoteProperty -Name CDMHosts -Value $($hostARRAY | & {$ofs=';';"$hostARRAY"})
        } else {
            fmtOUT "Hosts" "None"
            $outOBJ | Add-Member -MemberType NoteProperty -Name CDMHosts -Value "No"
        }

    $Obj = @()
    try { 
        $WinReg_HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$WebsiteURL) 
        $chkCDMS = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NLaSvc\Parameters\fairlawnfamilyInternet").GetValue("EnableActiveProbing"))
        switch($chkCDMS) {
            0 { $EnableActiveProbing = "Disabled" }
            1 { $EnableActiveProbing = "Allowed" }
        }
        $ActiveWebProbeHost = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeHost')
        $ActiveWebProbePath = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbePath')
        $ActiveWebProbeContent = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeContent')
        $ActiveDnsProbeContent = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeContent')
        $ActiveDnsProbeHost = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeHost')
        $chkPOLL = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('PassivePollPeriod')
        switch($chkPOLL) {
            5 { $PassivePollPeriod = "30 Seconds" }
            10 { $PassivePollPeriod = "Every Minute" }
            default { $PassivePollPeriod = $chkPOLL }
        }
        $StaleThreshold = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('StaleThreshold') 
        $WebTimeout = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('WebTimeout')
        $hostARRY = @()
        $hostARRAY = Select-String -Path "\\$WebsiteURL\C$\Windows\System32\drivers\etc\hosts" -Pattern "(msftncsi.com|131.107.255.255|dns.msftncsi.com)" -ErrorAction SilentlyContinue
        if($hostARRAY) {
            $CDMHosts = $($hostARRAY | & {$ofs=';';"$hostARRAY"})
        } else {
            $CDMHosts = "No"
        }
    } catch { continue }
    $outSTR = "$WebsiteURL$EnableActiveProbing$ActiveWebProbeHost$ActiveWebProbePath$ActiveWebProbeContent$ActiveDnsProbeContent$ActiveDnsProbeHost$PassivePollPeriod$StaleThreshold$WebTimeout$CDMHosts"
    if($outSTR -notcontains $outARRAY) {
        $OutputString = [string]""
        $OutputString += ($WebsiteURL.ToUpper()).Trim() + "," + $EnableActiveProbing + "," + $ActiveWebProbeHost + "," + $ActiveWebProbePath + "," + $ActiveWebProbeContent + "," + $ActiveDnsProbeContent + "," + $ActiveDnsProbeHost + "," + $PassivePollPeriod + "," + $StaleThreshold + "," + $WebTimeout + "," + $CDMHosts
        $Obj += $OutputString
        [array]$outARRAY = $outSTR
    }
    Write-Output "Network Connectivity Status Indicator" | Out-File $outHOST -Append
    $Obj | Out-File $outHOST -Append
    
#
#>>>>>>>>>>>>>>>>>>>  Check if  Certain Services/Applications are Running  <<<<<<<<<<<<<<<<<#
#
    if($chkprocess -eq $true -or $testall -eq $true) {
        if($v -eq $true -or $vv -eq $true) { Write-Host "Gathering version numbers of certain security and core applications." }
        #  Checks to see whether the Splunk, LogMiner, and RegisterHealer processes are running
        if(!(Get-Process Splunkd -ComputerName $WebsiteURL -ErrorAction SilentlyContinue)) {$SplunkProc = "Not Running"} else {$SplunkProc = "Running"}
        $outOBJ | Add-Member -MemberType NoteProperty -Name SplunkProc -Value $SplunkProc
        if(!(Get-Process CombineRegisterLogs -ComputerName $WebsiteURL -ErrorAction SilentlyContinue)) {$LogMineProc = "Not Running"} else {$LogMineProc = "Running"}
        $outOBJ | Add-Member -MemberType NoteProperty -Name LogMineProc -Value $LogMineProc
        if(!(Get-Process RegHealth -ComputerName $WebsiteURL -ErrorAction SilentlyContinue)) {$RegHealProc = "Not Running"} else {$RegHealProc = "Running"}
        $outOBJ | Add-Member -MemberType NoteProperty -Name RegHealProc -Value $RegHealProc
    }
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>         End of Testing      <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>          Output to CSV      <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
    if($v -eq $true -or $vv -eq $true) { Write-Host "Finished the assessment for $WebsiteURL and wrote the results into $outCSV" }
    $outOBJ | Select-Object TargetHostName,IPAddress,openTCPports,FTP,XML,HTTP,SSL,  `
                            RevocationFlag,RevocationMode,VerificationFlags,SslProtocol,CheckCertRevocationStatus,CipherAlgorithm,CipherStrength,HashAlgorithm,HashStrength,KeyExchangeAlgorithm,KeyExchangeStrength,CertFormat,CertExpiration,CertExpiration,CertIssueDate,CertIssuer,SerialNumber,CertSubject,CertType,CertKeySize,ValidDays,  `
                            WMI,SubnetMask,DefaultGateway,MACAddress,DNSServerSearchOrder,Domain,DHCPEnabled,Username,PartOfDomain,Roles,DomainRole,SystemType,PowerOnPassword,AdminPasswordStatus,CPU,AntiVirus,  `
                            REGSN,GPDModel,GPDSN,COMStatus,VSSKSN,EncryptionStatus,RegKeyDump,DumpFolder,DumpFilename,PANInfo,RmtExecute,RmtDownload,RmtUpload,SECLOG,SQLSTMT,  `
                            VfE2EOff,EnableActiveProbing,CDMHosts,ActiveWebProbeHost,ActiveWebProbePath,ActiveWebProbeContent,ActiveDnsProbeContent,  `                            
                            POSRelease,OpenEPSBoot,OpenEPSBootTS,LogMiner,SplunkFwde,RegHealer,TgtVerifoneFw,OpenEPSDirectory,SplunkProc,LogMineProc,RegHealProc | Export-Csv -Path $outCSV -Force -NoTypeInformation -Append -NoClobber
    
    Copy-Item -Path $outCSV -Destination $nwRAWDATA -Force -ErrorAction SilentlyContinue
    
    # Remove all previously set varialbes except
    $exludelst = $excludelst + ",oRAW,oData,oRPT,rawfile,datafile,rptfile,nwDATA,nwREPORT,nwRAWDATA,nwRAWROOT,WebsiteURLs,portList"
    freshstart $exludelst

} # End Loop
#
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Combine Resutls into single CSV <<<<<<<<<<<<<<<<<<<<<<<<<<<<#
#
$DateTime         = Get-Date -f MMddyyyyHHmmss
$CombineOutput    = $rptfile + "\Rpt_Security_Validation_$DateTime.csv"
$ResultArray = @()
ForEach ($File in (Get-ChildItem -Path $rawfile -Filter *.csv)) { $ResultArray += (Import-Csv -Path $File.FullName) }
$ResultArray | Export-Csv -Path $CombineOutput -Force -NoTypeInformation
# Put a copy of the report on the file server
Copy-Item -Path $CombineOutput -Destination $nwREPORT -Force -ErrorAction SilentlyContinue
#
Write-Host "Finished! It took " -NoNewLine -ForegroundColor Cyan
Write-Host $(($elapsed).Elapsed | %{ $([string]::Format("`r{0:d2}:{1:d2}:{2:d2}",$_.hours, $_.minutes, $_.seconds)) }) -NoNewLine
Write-host " to complete." -ForegroundColor Cyan
# Remove all previous set variables before exit
Get-Variable | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue }
