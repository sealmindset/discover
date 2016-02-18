#!/bin/bash

function usage {
        echo "usage: $1 [-s subnet] [-l location] [-r livehost]"
        echo
        echo "      -s subnet:      e.g., 192.168.30.0/23, 192.168.31.206"
        echo "      -l location:    e.g., lab, home, work, big blue box or red"
        echo "      -r results:     e.g., results/ipList.txt"
        echo
}

subnet=""
location=""
ipList=""

while getopts ":s:l:r:h" OPT; do
        case $OPT in
                s) subnet=$OPTARG;;
                l) location=$OPTARG;;
                r) ipList=$OPTARG;;
                h) usage $0; exit;;
                *) usage $0; exit;;
        esac
done

if [ -z "$subnet" ]; then
        subnet="192.168.31.200-254"
fi

if [ -z "$location" ]; then
        location="lab6"
fi

if [ -z "$ipList" ]; then
        ipList="results/ipList.txt"
fi

# For creating report from the XML results
if [ $(type xsltproc | wc -l) -lt 1 ]; then
        apt-get install xsltproc
fi

if [ ! -f /usr/share/nmap/scripts/smb-check-vulns.nse ]; then
    if [ -f smb-check-vulns.txt ]; then
        cp smb-check-vulns.txt /usr/share/nmap/scripts/smb-check-vulns.nse
    fi
fi


# Creates the output and the results directory if they need to be created
if [ ! -d "output" ]; then
    mkdir output
    mkdir results
fi

echo "<!doctype html>" >> results/index.html
echo "<html>" >> results/index.html
echo "<head>" >> results/index.html
echo "  <title>Results Report</title>" >> results/index.html
echo "</head>" >> results/index.html
echo "<body>" >> results/index.html

# Run a host discovery scan to see which devices are available in the subnet
typeOfScan='nmap-sn'
nmap -sn $subnet -oG output/$location-$typeOfScan.gnmap

# From the host discovery put together a list of IP Addresses that can be used in future scans
if [ -f "output/$location-$typeOfScan.gnmap" ]; then
    grep Up output/$location-$typeOfScan.gnmap | cut -d" " -f2 > $ipList
else
    echo "Unable to find the nmap host discovery list."
    exit
fi

################### Create a loop of the various nmap scans to perform ##############################
declare -a nmapSwitches=('-Pn -n -sT --top-ports 20 --open'
            '-Pn -n -sV -p 20,21,22 --open --script=ftp-anon.nse'
            '-Pn -n -sV -p 5800,5801,5802,5803,5900,5901,5902,5903 --open --script=vnc-info.nse'
            '-Pn -n -sV -p 5800,5801,5802,5803,5900,5901,5902,5903 --open --script=realvnc-auth-bypass.nse'
            '-Pn -n -p 69 -sU --open --script tftp-enum.nse'
            '-Pn -n -p T:53,U:53 --open'
            '-Pn -n -p 161 -sU --script snmp-brute'
            '-Pn -n --script=smb-os-discovery.nse -p 445'
            '-Pn -n --script=smb-enum-users.nse -p 445'
            '-Pn -n --script=smb-enum-shares.nse --script-args smbdomain=domain,smbuser=user,smbpass=password -p 445'
            '-Pn -n --script=smb-check-vulns --script-args=unsafe=1 -p 139,445'
            '-Pn -n -sU --script=nbstat.nse -p 137'
            '-sU -A -PN -n -pU:19,53,123,161 --script=ntp-monlist,dns-recursion,snmp-sysdescr'
            '-Pn -n -sV -p 443 --script=ssl-heartbleed.nse --open'
            '-Pn -n -p 80,443 --script=http-title --open'
            '-Pn -n -p 80,443 --script=http-headers --open'
            '-Pn -n -p 80,443 --script=http-enum --open'
            '-Pn -n -p 80,443 --script=http-methods --open');
declare -a typeOfScan=('nmap-Top-20-TCP-Ports'
            'nmap-sV-FTP'
            'nmap-sV-VNC'
            'nmap-sV-VNC-auth-bypass'
            'nmap-sU-TFTP'
            'nmap-DNS'
            'nmap-SNMP'
            'nmap-Samba-445'
            'nmap-smb-enum-users'
            'nmap-Samba-enum-shares'
            'nmap-smb-check-vulns'
            'nmap-nbstat'
            'nmap-UDP-DDOS-reflectors'
            'nmap-heartbleed'
            'nmap-HTTP-Title'
            'nmap-HTTP-Headers'
            'nmap-HTTP-Paths'
            'nmap-HTTP-Methods');

for ((i=0; i<${#nmapSwitches[@]}; i++)); do
    typeOfScanVar=${typeOfScan[$i]}
    nmapSwitchesVar=${nmapSwitches[$i]}
    echo "Running Scan $typeOfScanVar"
    nmap $nmapSwitchesVar -iL $ipList -oA output/$location-$typeOfScanVar
    # Generate a report based on the results
        xsltproc output/$location-$typeOfScanVar.xml -o results/$location-$typeOfScanVar.html
        echo "<a href=" >> results/index.html
        echo $location-$typeOfScanVar.html >> results/index.html
        echo ">" >> results/index.html
        echo $typeOfScanVar >> results/index.html
        echo "</a></br>" >> results/index.html
done

echo "</body>" >> results/index.html
echo "</html>" >> results/index.html
