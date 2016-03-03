#!/bin/bash

declare -a nmapNSE=('http-vhosts.nse',
                    'http-userdir-enum.nse',
                    'http-apache-negotiation.nse',
                    'http-backup-finder.nse',
                    'http-config-backup.nse',
                    'http-default-accounts.nse',
                    'http-email-harvest.nse',
                    'http-methods.nse',
                    'http-method-tamper.nse',
                    'http-passwd.nse',
                    'http-robots.txt.nse',
                    'ms-sql-info.nse',
                    'ms-sql-config.nse',
                    'ms-sql-dump-hashes.nse');

for ((i=0; i<${#nmapNSE[@]}; i++)); do
    nmapNSEVar=${nmapNSE[$i]}
    if [ ! -f /usr/share/nmap/scripts/$nmapNSEVar ]; then
        #cp ${PWD}/discover/smb-check-vulns.txt /usr/share/nmap/scripts/smb-check-vulns.nse
        #nmap --script-updatedb
        echo "$nmapNSEVar is missing"
    fi
done
