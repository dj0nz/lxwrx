#!/usr/bin/python3

# create blacklist ipsets to use with local firewall forward or input chain
# see http://opendbl.net/ for blacklist info
# 
# iptables example:
# iptables -I INPUT -m set --match-set dshield src -j DROP
# iptables -I FORWARD -m set --match-set dshield src -j DROP
#
# you might want to use ferm (https://man.archlinux.org/man/extra/ferm/ferm.1.en)
# if you're still using iptables. if you're using nftables, you will need additional
# steps to convert ipsets to nft sets usinf ipset-translate.
# see https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_ipset_to_nftables
#
# dj0Nz 05/2024

import re, os, sys, ipaddress, requests, subprocess, time
from syslog import syslog

# set names and urls
blacklist = [{'name' : 'dshield', 'url': 'https://opendbl.net/lists/dshield.list'},
{'name' : 'ipsum', 'url': 'https://opendbl.net/lists/ipsum.list'},
{'name' : 'blocklistde', 'url': 'https://www.blocklist.de/downloads/export-ips_all.txt'},
{'name' : 'cins', 'url': 'http://cinsscore.com/list/ci-badguys.txt'},
{'name' : 'bleedingedge', 'url': 'https://rules.emergingthreats.net/open/snort-2.9.0/rules/compromised-ips.txt'},
{'name' : 'de-set', 'url' : 'https://www.ipdeny.com/ipblocks/data/countries/de.zone'},
{'name' : 'pt-set', 'url' : 'https://www.ipdeny.com/ipblocks/data/countries/pt.zone'}]

# Ipsets in this list must be of type net
netsets = ('de-set', 'pt-set', 'dshield')

# pattern to match lines that start with a number (assume ip address)
starts_with_number = re.compile(r'^\d')

# function to check if input is a valid ipv4 address or network
def is_ipv4(input_address):
    try:
        valid_addr = ipaddress.IPv4Address(input_address)
        return True
    except:
        try:
            valid_net = ipaddress.IPv4Network(input_address)
            return True
        except:
            return False

# the time is now
now = time.time()

# state file for monitoring
state_file = '/var/run/ipset.state'

# blacklist entry names 
blacklist_names = []

# create ipsets
for blacklist_entry in blacklist:
    ipset_name = blacklist_entry.get('name')
    ipset_url = blacklist_entry.get('url')
    blacklist_names.append(ipset_name)
    try:
        response = requests.get(ipset_url)
    except:
        message = str(now) + ' - ' + str(ipset_name) + ' - cant connect to service, check url!'
        syslog(message)
        continue
    if response:
        iplist = response.text.split('\n')
        if ipset_name in netsets:
            ipset_create = '/usr/sbin/ipset -q create ' + ipset_name + ' hash:net family inet'
        else:
            ipset_create = '/usr/sbin/ipset -q create ' + ipset_name + ' hash:ip family inet'
        ipset_flush = '/usr/sbin/ipset flush ' + ipset_name
        subprocess.run([ipset_create], shell=True, capture_output=False, text=True, check=False)
        subprocess.run([ipset_flush], shell=True, capture_output=False, text=True, check=False)
        for iplist_entries in iplist:
            if ipset_name == 'dshield':
                if starts_with_number.match(iplist_entries):
                    first_address = str(iplist_entries).split('-')[0]
                    if is_ipv4(first_address):
                        net_address = str(first_address) + '/24'
                        ipset_add = '/usr/sbin/ipset add ' + ipset_name + ' ' + str(net_address)
                        subprocess.run([ipset_add], shell=True, capture_output=False, text=True, check=False)
            else:
                if is_ipv4(iplist_entries):
                    ipset_add = '/usr/sbin/ipset add ' + ipset_name + ' ' + str(iplist_entries)
                    subprocess.run([ipset_add], shell=True, capture_output=False, text=True, check=False)

# counter for ipsets with zero entries
setnul = 0

# sometimes one of the urls returns no addresses. you should monitor state file content and raise an alarm if it contains a 0 (zero)
for ipset in blacklist_names:
    count_entries = '/usr/sbin/ipset -q list ' + ipset + ' | grep entries'
    entries = int(subprocess.run([count_entries], shell=True, capture_output=True, text=True, check=False).stdout.split()[3])
    if not entries > 0:
        setnul += 1

with open(state_file,'w') as output:
    output.write(str(setnul))
