#!/bin/bash

function usage {
        echo "usage: $1 [-s subnet] [-l location] [-r livehost]"
        echo
        echo "      -s subnet:      e.g., 192.168.30.0/23"
        echo "      -l location:    e.g., lab"
        echo "      -r results:     e.g., livehosts.txt"
        echo
}

sn=""
lc=""
rs=""

while getopts ":s:l:r:" OPT; do
        case $OPT in
                s) sn=$OPTARG;;
                l) lc=$OPTARG;;
                r) rs=$OPTARG;;
                *) usage $0; ext;;
        esac
done

if [ -z "$sn" ]; then
    subnet = $sn
else
    subnet = '192.168.30.0/23'
fi

if [ -z "$lc" ]; then
    location = $lc
else
    location = 'lab'
fi

if [ -z "$rs" ]; then
    ipList = $rs
else
    ipList = 'results/ipList.txt'
fi

echo "$sn -> $lc -> $rs"
echo "$subnet -> $location -> $ipList"

# Creates the output and the results directory if they need to be created
if [ ! -d "output" ]; then
    mkdir output
    mkdir results
fi

# Run a host discovery scan to see which devices are available in the subnet
typeOfScan='nmap-sP'
nmap -sP $subnet -oA output/$location-$typeOfScan

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
            '--script smb-enum-shares.nse --script-args smbdomain=domain,smbuser=user,smbpass=password -p 445');
declare -a typeOfScan=('nmap-sV-FTP' 
            'nmap-sV-VNC'
            'nmap-sV-VNC-auth-bypass'
            'nmap-sU-TFTP'
            'nmap-DNS'
            'nmap-SNMP'
            'nmap-Samba-445'
            'nmap-Samba-check-vulns'
            'nmap-smb-enum-users'
            'nmap-Samba-enum-shares');

for ((i=0; i<${#nmapSwitches[@]}; i++)); do
    typeOfScanVar=${typeOfScan[$i]}
    nmapSwitchesVar=${nmapSwitches[$i]}
    nmap $nmapSwitchesVar -iL $ipList -oA output/$location-$typeOfScanVar
done
