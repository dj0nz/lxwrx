#!/bin/bash

# Poor Man's Port Scan - Scannt ein /24 Netzwerk ohne Root-Rechte
# Input: Netzwerk-ID  (erste drei Oktette, Default = lokales Netz)
# Ports: 22 (SSH), 135 (RPC), 445 (SMB), 3389 (RDP)
# dj0Nz Mai 2026

NETWORK="${1:-$(ip route show default | awk -F'[. ]' '{print $3"."$4"."$5}')}"
PORTS=(22 135 445 3389)
TIMEOUT=1
WORKDIR=$(mktemp -d)

scan_host() {
    local ip="$1"
    local open_port=""
    local mac=""

    # TCP connect - first port that responds wins
    for port in "${PORTS[@]}"; do
        if (timeout "${TIMEOUT}" bash -c "echo >/dev/tcp/${ip}/${port}") 2>/dev/null; then
            open_port="${port}"
            break
        fi
    done

    # ARP cache check - FAILED/incomplete entries excluded
    local neigh
    neigh=$(ip neigh show "${ip}" 2>/dev/null)
    if echo "${neigh}" | grep -v -E 'FAILED|incomplete' | grep -qE '([0-9a-f]{2}:){5}[0-9a-f]{2}'; then
        mac=$(echo "${neigh}" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}')
        [[ "${mac}" == "00:00:00:00:00:00" ]] && mac=""
    fi

    [[ -z "${open_port}" && -z "${mac}" ]] && return

    # Build reason string
    local reason=""
    [[ -n "${open_port}" ]] && reason="tcp/${open_port}"
    if [[ -n "${mac}" ]]; then
        [[ -n "${reason}" ]] \
            && reason="${reason} | arp: ${mac}" \
            || reason="arp-only | mac: ${mac}"
    fi

    echo "${ip}|${reason}" > "${WORKDIR}/${ip}"
}

echo "Scanning ${NETWORK}.1-254 on ports ${PORTS[*]} ..."

for i in $(seq 1 254); do
    scan_host "${NETWORK}.${i}" &
done
wait

echo ""
echo "Host               Detection"
echo "------------------ ----------------------------------------"

if ls "${WORKDIR}"/* &>/dev/null; then
    for f in $(ls "${WORKDIR}/" | sort -t. -k4 -n); do
        IFS='|' read -r ip reason < "${WORKDIR}/${f}"
        printf "%-18s %s\n" "${ip}" "${reason}"
    done
else
    echo "No hosts found."
fi

rm -rf "${WORKDIR}"
