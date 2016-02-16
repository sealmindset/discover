#!/bin/bash
#
# A little script to discover what shares are available
#
# 1. run a nmap scan
#    nmap --script smb-enum-shares.nse -p445 -oG smbshares -iL livehosts.txt
# 2. grab only the IP addresses
#    ./gnmap.sh -f smbshares -i > livesmbhost.txt
#

function usage {
        echo "usage: $1 [-f livesmbhost.txt] [-L lab]"
}

fn=""
lb=""

while getopts "f:L:" OPT; do
        case $OPT in
                f) fn=$OPTARG;;
                L) lb=$OPTARG;;
                *) usage $0; ext;;
        esac
done

if [[ -z $fn ]]; then
        if [[ -f ${HOME}/livesmbhost.txt ]]; then
                db=${HOME}/livesmbhost.txt
        else
                usage $0
                exit
        fi
fi

if [[ ! -z $ld ]]; then
        lb="lab"
fi

HOSTS="$(< $fn)"
for HOST in $HOSTS; do
        echo "$HOST $lb"
        smbclient -L $lb -g -N -I $HOST >> smbshares.txt
done
