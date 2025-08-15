#bin/bash

# ====== CONFIGURATION ======
network="192.168.29.0/24"    # Target network range
my_ip=$(hostname -I | awk '{print $1}')  # Detect your own IP

# ====== MAIN PATHS ======
main_dir=$(pwd)
new_dir="$main_dir/full_scan"
mkdir -p "$new_dir"

# ====== FIND_LIVE_HOSTS ======

echo -e "\e[31m[*]\e[0m\e[32m Scanning for live hosts in $network...\e[0m"
fping -a -g "$network" 2>/dev/null | grep -v "$my_ip" > live_hosts.txt

# Check if any hosts were found
if [ ! -s live_hosts.txt ]; then
    echo "[!] No live hosts found in $network."
    exit 1
fi

# ====== FUNCTION: FULL_SCAN ======
# FUNCTION: FULL_SCAN
# Performs a complete scan for each host in live_hosts.txt
FULL_SCAN() {
    # Print starting message in colored format
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting FULL scan...\e[0m"

    # Loop through each IP address from live_hosts.txt
    for i in $(cat live_hosts.txt); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: $i\e[0m"

        # Create a dedicated directory for this host's results
        mkdir -p "$new_dir/$i"

        # TCP scan: service/version detection, OS detection
        nmap -Pn -sC -sV -O "$i" \
            -oX "$new_dir/$i/res_tcp_${i}.xml" \
            -oN "$new_dir/$i/res_tcp_${i}.txt" \
            > /dev/null 2>&1

        # UDP scan: top 10 ports, service detection
        nmap -Pn -sU --top-ports 10 -sV "$i" \
            -oX "$new_dir/$i/res_udp_${i}.xml" \
            -oN "$new_dir/$i/res_udp_${i}.txt" \
            > /dev/null 2>&1

        # Convert XML reports into readable HTML
        xsltproc "$new_dir/$i/res_tcp_${i}.xml" -o "$new_dir/$i/res_tcp_${i}.html"
        xsltproc "$new_dir/$i/res_udp_${i}.xml" -o "$new_dir/$i/res_udp_${i}.html"

        MAPPING "$i"
    done
}

# ====== FUNCTION: MAPPING ======
# Processes scan results, extracts open ports, and runs vulnerability scan
MAPPING() {
    local host="$1"
    echo -e "\e[31m[*]\e[0m\e[32m Mapping for: $host\e[0m"

    # Extract open TCP ports from the text report
    ports=$(awk '/open/{print $1}' "$new_dir/$host/res_tcp_${host}.txt" \
        | cut -d'/' -f1 | sort -n | tr '\n' ',' | sed 's/,$//')

    # If there are open ports, run vulnerability scan
    if [ -n "$ports" ]; then
        nmap -p"$ports" --script vuln "$host" \
            -oX "$new_dir/$host/mapping_tcp_${host}.xml" > /dev/null 2>&1

        # Convert vulnerability scan report to HTML
        xsltproc "$new_dir/$host/mapping_tcp_${host}.xml" \
            -o "$new_dir/$host/mapping_tcp_${host}.html" > /dev/null 2>&1
    else
        # No open ports found — skip vulnerability scan
        echo -e "\e[33m[!] No open ports found for $host, skipping vuln scan\e[0m"
    fi
}

# Run the FULL_SCAN function
FULL_SCAN
