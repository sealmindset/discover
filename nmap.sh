#!/bin/bash

location='tallBuilding'
subnet='127.0.0.1'
ipList='results/ipList.txt'

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
            '--script smb-enum-shares.nse --script-args smbdomain=domain,smbuser=user,smbpass=password -p 445');
declare -a typeOfScan=('nmap-sV-FTP' 
            'nmap-sV-VNC'
            'nmap-sV-VNC-auth-bypass'
            'nmap-sU-TFTP'
            'nmap-DNS'
            'nmap-SNMP'
            'nmap-Samba-445'
            'nmap-Samba-check-vulns'
            'nmap-Samba-enum-shares');

for ((i=0; i<${#nmapSwitches[@]}; i++)); do
    typeOfScanVar=${typeOfScan[$i]}
    nmapSwitchesVar=${nmapSwitches[$i]}
    nmap $nmapSwitchesVar -iL $ipList -oA output/$location-$typeOfScanVar
done
