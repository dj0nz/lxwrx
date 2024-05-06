#!/usr/bin/python3

# Python program to create ipset with zscaler ipv4 hubs to use in iptables firewall ruleset
# dj0Nz may 2024

import json, ipaddress, requests, os, subprocess, time
from syslog import syslog

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

# Variables needed
json_file = '/tmp/zs_hubs.json'
iplist = []
now = time.time()
max_age = 43200
ipset_name = 'zscaler'

# create file if it doesn't exist and set "I'm too old" timestamp causing it to get re-downloaded in next step
if not os.path.isfile(json_file):
    create_time = now - (max_age * 2)
    mod_time = now - (max_age * 2)
    with open(json_file,'w') as output:
        os.utime(json_file,(create_time,mod_time))

# If json file containing hub prefixes is older than max_age (initially 12h), refresh it
if os.stat(json_file).st_mtime < now - max_age:
    try:
        response = requests.get('https://api.config.zscaler.com/zscaler.net/hubs/cidr/json/recommended')
    except:
        syslog('Cant connect to zscaler api service. Check url.')
        quit()
    resp_json = response.json()
    with open(json_file,'w') as output:
        json.dump(resp_json,output,indent=2)
else:
    with open(json_file,'r') as input:
        resp_json = json.load(input)

# extract ipv4 hub prefixes
hub_prefixes = [ hub for hub in resp_json['hubPrefixes'] if is_ipv4(hub) ]

# create or refresh ipset
ipset_create = '/usr/sbin/ipset -q create ' + ipset_name + ' hash:net family inet'
ipset_flush = '/usr/sbin/ipset flush ' + ipset_name
subprocess.run([ipset_create], shell=True, capture_output=False, text=True, check=False)
subprocess.run([ipset_flush], shell=True, capture_output=False, text=True, check=False)
for prefix in hub_prefixes:
    ipset_add = '/usr/sbin/ipset add ' + ipset_name + ' ' + str(prefix)
    subprocess.run([ipset_add], shell=True, capture_output=False, text=True, check=False)

# Record success or failure
get_set_entries = '/usr/sbin/ipset list -t ' + ipset_name + ' | grep entries | awk \'{print $4}\''
set_entries = subprocess.run([get_set_entries], shell=True, capture_output=True, text=True, check=False).stdout.strip()
if set_entries == '0':
    message = 'Ipset zscaler: Something went wrong. No entries.'
else:
    message = 'Ipset zscaler created with ' + set_entries + ' entries.'
syslog(message)
