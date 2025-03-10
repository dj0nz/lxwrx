#!/bin/bash

# local network inventory scan
# djonz mar 2025


# temp file will get deleted after script run
INFILE=$(mktemp)
# get local link's network (will not work as expected on multihomed)
LOCALNET=$(ip route show | grep 'scope.link' | cut -d ' ' -f1)
# generate output file name from network
NETNAME=$(echo $LOCALNET | tr '/' '_')
OUTFILE=$NETNAME.csv

# create empty output
cat /dev/null > $OUTFILE

echo "Scanning local network ($LOCALNET)..."
# do the most simple inventory scan
nmap -sn -n $LOCALNET > $INFILE
# eliminate useless information
sed -i 's/Host.is.up.*$//' $INFILE

echo ""
printf "%-17s %-20s %s\n" "IP-Adress" "MAC" "Device"

while read -r LINE; do
    # only process lines that are not empty
    if [[ $LINE ]]; then
        # get ip from "Nmap scan report for" line
        if [[ $LINE =~ "Nmap" ]]; then
            IP=$(echo $LINE | awk '{print $NF}')
        else
            # extract mac address...
            MAC=$(echo $LINE | awk '{print $3}')
            # ...and assumed vendor
            SYS=$(echo $LINE | awk -F '(' '{print $2}' | tr -d ')')
            # if nmap doesn't know the vendor, perhaps someone else does...
            if [[ $SYS = "Unknown" ]]; then
                # convert mac to a format macvendors understand
                MAC2=$(echo $MAC | tr ':' '-')
                # get comma separated response body and code
                RESFULL=$(curl -s https://api.macvendors.com/$MAC2 -w ",%{http_code}")
                # code is second part
                CODE=$(echo $RESFULL | cut -d ',' -f2)
                # if macvendors has a record, get it
                if [[ $CODE = 200 ]]; then
                    SYS=$(echo $RESFULL | cut -d ',' -f1)
                fi
                # free api access is limited to 1 request per second and 1000 per day
                sleep 2
            fi
            # write record to $OUTFILE
            echo "$IP,$MAC,$SYS" >> $OUTFILE
            # and do nicely formatted screen output
            printf "%-17s %-20s %s\n" "$IP" "$MAC" "$SYS"
        fi
    fi
done < $INFILE

# cleaning up...
rm $INFILE
echo ""
echo "Machine readable (csv) output in $OUTFILE"
