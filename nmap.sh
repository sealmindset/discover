#!/bin/bash
#
# Copyright 2016... nmap.sh authors
#
# nmap.sh is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# nmap.sh is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with nmap.sh.  If not, see <http:#www.gnu.org/licenses/>.
#
# Description:
#
# This tool was meant to show the attack surface of any given device susceptible to vulnerabilities.  
#
# Two directories are created - output and results - output will contain the raw data, and results will provide the report.
# smb-check-vulns.nse seems to be missing in th the lastest incarnation of nmap 7.0.1 so a copy (source: offensive-security) is made.
# Part of the checks is to take a snapshot of any websites running on the next work, so used an updated version of Trustwave's 
# http-screenshot.nse patched by afxdub
#
# The main tool is nmap, but additional logic will be incorporated as needed.  This script is based on thepcn3rd handy work, with
# a couple of changes.
#
# To use: See usage
#
# Defaults
output=${PWD}/output
results=${PWD}/results
ipList=$results/ipList.txt

function usage {
        echo "usage: $1 [-s subnet] [-l location]"
        echo
        echo "      -s subnet:          e.g., 192.168.30.0/23, 192.168.31.206"
        echo "      -l location:        e.g., lab, home, work, big blue box or red"
        echo "      -h help:"
        echo
}

function updhtml {
lc=$1
sv=$2
for i in `ls $results/*.png | cut -d"/" -f5`;do
        hstat=""
        case `echo $i | sed 's/\.png//g' | cut -d"-" -f2` in
                443) hstat="https" ;;
                8443) hstat="https" ;;
                *) hstat="http" ;;
        esac
        b=${i/.png/ }
        b=${b/-/:}
        replace "Saved to $i" "<p><a href='$hstat://$b' target='_blank'>$hstat://$b</a></br><img src='$i'></p>" -- $results/$lc-$sv.html
done
}

subnet=""
location=""

while getopts ":s:l:h" OPT; do
        case $OPT in
                s) subnet=$OPTARG;;
                l) location=$OPTARG;;
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

# For creating report from the XML results
if [ $(type xsltproc | wc -l) -lt 1 ]; then
        apt-get install xsltproc
fi

if [ ! -f /usr/share/nmap/scripts/smb-check-vulns.nse ]; then
    if [ -f smb-check-vulns.txt ]; then
        cp ${PWD}/discover/smb-check-vulns.txt /usr/share/nmap/scripts/smb-check-vulns.nse
        nmap --script-updatedb
    fi
fi

if [ ! -f /usr/share/nmap/scripts/http-screenshot-html.nse ]; then
        wget -c http://download.gna.org/wkhtmltopdf/0.12/0.12.3/wkhtmltox-0.12.3_linux-generic-amd64.tar.xz
        tar -xJf wkhtmltox-0.12.3_linux-generic-amd64.tar.xz
        mv ${PWD}/wkhtmltox/bin/wkhtmltoimage /usr/local/bin
        git clone https://github.com/afxdub/http-screenshot-html.git
        mv ${PWD}/http-screenshot-html/http-screenshot-html.nse /usr/share/nmap/scripts/
        rm -rf ${PWD}/http-screenshot-html
        nmap --script-updatedb
fi

# Creates the output and the results directory if they need to be created
if [ ! -d "${PWD}/output" ]; then
    mkdir $output
    mkdir $results
fi

cat << 'EOF' > $results/index.html
<!doctype html>
<html>
        <head>
                <title>Results Report</title>
        </head>
        <body>
EOF

# Run a host discovery scan to see which devices are available in the subnet
typeOfScan='nmap-sn'
ognmap=$output/$location-$typeOfScan.gnmap
echo
echo "Network discovery of live hosts -> $ognmap"
echo
nmap -sn $subnet -oG $ognmap

# From the host discovery put together a list of IP Addresses that can be used in future scans
if [ -f "${output}/$location-$typeOfScan.gnmap" ]; then
    echo
    echo "Creating a $ipList from $ognmap"
    echo
    grep Up $ognmap | cut -d" " -f2 >> $ipList
else
    echo "************************************************"
    echo "* Unable to find the nmap host discovery list! *"
    echo "************************************************"    
    exit
fi

################### Create a loop of the various nmap scans to perform ##############################
declare -a nmapSwitches=('-Pn -n -sT --top-ports 20 --open'
            '-Pn -n -sV -p 20,21,22 --open --script=ftp-anon.nse'
            '-Pn -n -sV -p 5800,5801,5802,5803,5900,5901,5902,5903 --open --script=realvnc-auth-bypass.nse'
            '-Pn -n -p 69 -sU --open --script tftp-enum.nse'
            '-Pn -n -p T:53,U:53 --open'
            '-Pn -n --script=smb-os-discovery.nse -p 445'
            '-Pn -n --script=smb-enum-users.nse -p 445'
            '-Pn -n -sV -p 445 --script=smb-brute.nse'
            '-Pn -n --script=smb-enum-shares.nse --script-args smbdomain=domain,smbuser=user,smbpass=password -p 445'
            '-Pn -n --script=smb-check-vulns --script-args=unsafe=1 -p 139,445'
            '-Pn -n -sU --script=nbstat.nse -p 137'
            '-Pn -n -p 80,443 --script=http-headers --open'
            '-Pn -n -p 80,443 --script=http-enum --open'
            '-Pn -n -p 80,443 --script=http-methods --open'
            '-Pn -n --script=http-passwd'
            '-Pn -n -p 80,8000,443,8443 --script=http-screenshot-html --open');

declare -a typeOfScan=('nmap-Top-20-TCP-Ports'
            'nmap-sV-FTP'
            'nmap-sV-VNC-auth-bypass'
            'nmap-sU-TFTP'
            'nmap-DNS'
            'nmap-Samba-445'
            'nmap-smb-enum-users'
            'nmap-smb-brute'
            'nmap-Samba-enum-shares'
            'nmap-smb-check-vulns'
            'nmap-nbstat'
            'nmap-HTTP-Headers'
            'nmap-HTTP-Paths'
            'nmap-HTTP-Methods'
            'nmap-HTTP-PASSWD'
            'nmap-HTTP-screenshot');

for ((i=0; i<${#nmapSwitches[@]}; i++)); do
    typeOfScanVar=${typeOfScan[$i]}
    nmapSwitchesVar=${nmapSwitches[$i]}
    echo
    echo "Running scan $i of ${#nmapSwitches[@]} - $typeOfScanVar"
    echo
    nmap $nmapSwitchesVar -iL $ipList -oA $output/$location-$typeOfScanVar
    # Generate a report based on the results
        xsltproc $output/$location-$typeOfScanVar.xml -o $results/$location-$typeOfScanVar.html
        echo "<a href=\"" >> $results/index.html
        echo $location-$typeOfScanVar.html >> $results/index.html
        echo "\">" >> $results/index.html
        echo $typeOfScanVar >> $results/index.html
        echo "</a></br>" >> $results/index.html
done

if [ $( ls ${PWD}/*.png | wc -l ) -gt 1 ]; then
        mv ${PWD}/*.png $results
        rm ${PWD}/*.html
fi

echo
echo "Updating the $location-nmap-HTTP-screenshot.html"
echo
updhtml $location 'nmap-HTTP-screenshot'

cat << 'EOF3' >> $results/index.html
        </body>
</html>
EOF3
