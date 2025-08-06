#!/bin/bash


network=192.168.29.129
main_dir=$(pwd)
new_dir="$main_dir/full_scan"
mkdir -p "$new_dir"

#FUNCTION: FULL_SCAN
# Runs an advanced scan with full NSE: vuln scripts, brute-force, OS detection, etc.
FULL_SCAN()
{
    # Print starting message with color formatting
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting FULL scan...\e[0m"

    # Use fping to find live hosts in the target network and save IPs to address.txt
    fping -a -g "$network" 2>/dev/null | awk '{print $1}' > address.txt

    # Loop over each live IP address found
    for i in $(cat address.txt); do
        # Inform user which IP is currently being scanned
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: $i\e[0m"

        # Create a separate directory for each IP to store its scan results
        mkdir -p "$i"

        # Run nmap scan with service/version detection and OS detection, output XML to the IP directory
        nmap -Pn -sV --version-all "$i"  -oN "./$i/res_${i}.txt" -oX "./$i/res_${i}.xml" > /dev/null 2>&1

        # Convert the XML output to a human-readable HTML report in the same directory
        xsltproc "./$i/res_${i}.xml" -o "./$i/res_${i}.html"
    done
}

FULL_SCAN