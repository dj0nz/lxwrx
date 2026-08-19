#!/usr/bin/env python3

# Infoblox Zone export tool.
#
# Connects to a Grid Master, auto-detects the highest supported WAPI version,
# exports zone objects of a given view to CSV and exports nsgroup configurations to JSON.
#
# Auth relies on requests' automatic netrc lookup 
# Requirement: a netrc file with a matching 'machine <GRID_IP>' entry must exist at ~/.netrc
#
# djonz Aug 2026

import sys, re, csv, json, requests, urllib3, socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Adjust to your environment
GRID_IP = "192.0.2.10"
ZONE_VIEW = "External"
CSV_OUTPUT = "zones.csv"
JSON_OUTPUT = "nsgroups.json"

# Fields pulled for nsgroup export. Adjust here if more detail is needed.
NSGROUP_FIELDS = (
    "name,comment,extattrs,use_external_primary,"
    "external_primaries,external_secondaries,grid_primary,grid_secondaries"
)

# check if port open
def port_open(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(2)
        sock.connect((ip, int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()
        
def build_session():
    session = requests.Session()
    session.verify = False
    return session

def detect_wapi_version(session, grid_ip):
    # Scrape the WAPI version from the Grid's WAPI doc page title.
    # Equivalent to: curl -sk https://<IP>/wapidoc/index.html | sed -n 's/.*<title>.*WAPI \\([0-9.]*\\) documentation.*/\\1/p'
    url = f"https://{grid_ip}/wapidoc/index.html"
    resp = session.get(url, timeout=15)
    resp.raise_for_status()
    match = re.search(r"<title>.*WAPI ([0-9.]+) documentation", resp.text)
    if not match:
        sys.exit("Could not determine WAPI version from /wapidoc/index.html - aborting.")
    return match.group(1)

def wapi_get(session, base_url, obj_type, params):
    resp = session.get(f"{base_url}/{obj_type}", params=params, timeout=30)
    resp.raise_for_status()
    # WAPI returns null instead of [] for some empty result sets
    return resp.json() or []

def build_nsgroup_tsig_lookup(nsgroups):
    # Map ns_group name -> True if any external primary/secondary member of that group has a TSIG key configured, else False.
    lookup = {}
    for group in nsgroups:
        name = group.get("name")
        # WAPI returns null instead of [] for unused external server lists
        externals = (group.get("external_primaries") or []) + (
            group.get("external_secondaries") or []
        )
        lookup[name] = any(ext.get("tsig_key_name") for ext in externals)
    return lookup

def export_zones(session, base_url, nsgroup_tsig):
    params = {
        "view": ZONE_VIEW,
        "_return_fields": "fqdn,ns_group,is_dnssec_signed,dnssec_keys",
        "_max_results": 100000,
    }
    zones = wapi_get(session, base_url, "zone_auth", params)
    with open(CSV_OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["zone_name", "ns_group", "tsig_configured", "dnssec_signed", "key_count", "dnssec_consistent"]
        )
        for z in zones:
            ns_group = z.get("ns_group", "")
            tsig = nsgroup_tsig.get(ns_group, "n/a") if ns_group else "n/a"

            # WAPI may return null instead of [] for zones without keys
            keys = z.get("dnssec_keys") or []
            key_count = len(keys)
            is_signed = z.get("is_dnssec_signed", False)

            # flag mismatch between reported status and actual key presence
            consistent = (is_signed and key_count > 0) or (not is_signed and key_count == 0)

            writer.writerow(
                [z.get("fqdn", ""), ns_group, tsig, is_signed, key_count, consistent]
            )
    return len(zones)
    
def export_nsgroups(session, base_url):
    params = {
        "_return_fields": NSGROUP_FIELDS,
        "_max_results": 100000,
    }
    nsgroups = wapi_get(session, base_url, "nsgroup", params)

    with open(JSON_OUTPUT, "w") as f:
        json.dump(nsgroups, f, indent=2, sort_keys=True)

    return nsgroups

def main():
    
    if not port_open(GRID_IP, 443):
        print('Infoblox Grid unreachable')
        exit(2)
    
    session = build_session()

    try:
        version = detect_wapi_version(session, GRID_IP)
    except requests.exceptions.RequestException as exc:
        sys.exit(f"Could not reach Grid or authenticate: {exc}")

    base_url = f"https://{GRID_IP}/wapi/v{version}"
    print(f"Using WAPI version: {version}")

    try:
        nsgroups = export_nsgroups(session, base_url)
        print(f"Name Server Groups: {len(nsgroups)} -> {JSON_OUTPUT}")

        nsgroup_tsig = build_nsgroup_tsig_lookup(nsgroups)
        zone_count = export_zones(session, base_url, nsgroup_tsig)
        print(f"Zones in view '{ZONE_VIEW}': {zone_count} -> {CSV_OUTPUT}")
    except requests.exceptions.HTTPError as exc:
        sys.exit(f"WAPI request failed: {exc}")

if __name__ == "__main__":
    main()
