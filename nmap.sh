#!/bin/bash

if [ $(type xsltproc | wc -l) -lt 1 ]; then
        apt-get install xsltproc
fi

function usage {
        echo "usage: $1 [-s subnet] [-l location] [-r livehost]"
        echo
        echo "      -s subnet:      e.g., 192.168.30.0/23, 192.168.31.206"
        echo "      -l location:    e.g., lab, home, work, big blue box or red"
        echo "      -r results:     e.g., results/livehosts.txt"
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
        subnet="192.168.30.0/23"
fi

if [ -z "$location" ]; then
        location="lab"
fi

if [ -z "$ipList" ]; then
        ipList="ipList.txt"
fi

# Creates the output and the results directory if they need to be created
if [ ! -d "output" ]; then
    mkdir output
    mkdir results
fi

# Run a host discovery scan to see which devices are available in the subnet
typeOfScan='nmap-sP'
nmap -sP -oA output/$location-$typeOfScan $subnet

# From the host discovery put together a list of IP Addresses that can be used in future scans
if [ -f "output/$location-$typeOfScan.nmap" ]; then
    cat output/$location-$typeOfScan.nmap | grep "Nmap scan report for" | awk '{print $5}' > $ipList
else
    echo "Unable to find the nmap host discovery list."
    exit
fi

################### Create a loop of the various nmap scans to perform ##############################
declare -a nmapSwitches=('-sV -p 20,21,22 --open --script ftp-anon.nse' 
            '-sV -p 5800,5801,5802,5803,5900,5901,5902,5903 --open --script vnc-info.nse'
            '-sV -p 5800,5801,5802,5803,5900,5901,5902,5903 --open --script realvnc-auth-bypass.nse'
            '-p 69 -sU --open --script tftp-enum.nse'
            '-p T:53,U:53 --open'
            '-p 161 -sU --script snmp-brute'
            '--script smb-os-discovery.nse -p 445'
            '--script smb-check-vulns -p 445'
            '--script smb-enum-users.nse -p 445'
            '--script smb-enum-shares.nse --script-args smbdomain=domain,smbuser=user,smbpass=password -p 445'
            '--script smb-check-vulns.nse --script-args=unsafe=1 -p 445'
            '-sU --script nbstat.nse -p137'
            '-sV -sC');
declare -a typeOfScan=('nmap-sV-FTP' 
            'nmap-sV-VNC'
            'nmap-sV-VNC-auth-bypass'
            'nmap-sU-TFTP'
            'nmap-DNS'
            'nmap-SNMP'
            'nmap-Samba-445'
            'nmap-Samba-check-vulns'
            'nmap-smb-enum-users'
            'nmap-Samba-enum-shares'
            'nmap-check-vulns'
            'nmap-nbstat'
            'nmap-upnp-info');

for ((i=0; i<${#nmapSwitches[@]}; i++)); do
    typeOfScanVar=${typeOfScan[$i]}
    nmapSwitchesVar=${nmapSwitches[$i]}
    nmap $nmapSwitchesVar -iL $ipList -oA output/$location-$typeOfScanVar
    xsltproc output/$location-$typeOfScanVar.xml -o results/$location-$typeOfScanVar.html
    echo '<a href="$location-$typeOfScanVar.html">$typeOfScanVar</a>' >> results/index.html
done
