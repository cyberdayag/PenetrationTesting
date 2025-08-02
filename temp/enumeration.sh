#!/bin/bash

SELECT_SCAN_METOD() {

    # Prompt for target IP address
    read -p $'\e[31m[!]\e[0m\e[34m Enter target IP address: \e[0m' target_ip
    
    # Prompt for output folder name
    read -p $'\e[31m[!]\e[0m\e[34m Enter folder name for scan result: \e[0m' working_dir

    # Prompt for scan metod
    read -p $'\e[31m[?]\e[0m\e[34m Choose scan mode: [B]asic or [F]ull: \e[0m' scan_mode

    # Create output directory if it doesn't exist
    mkdir -p "$working_dir" > /dev/null 2>&1

    # Change to output directory
    cd "$working_dir"

    if [[ "$scan_mode" =~ ^[Bb]$ ]]; then
        BASIC_SCAN
    else
        FULL_SCAN
    fi
}



# FUNCTION: BASIC_SCAN
# Runs a basic scan: TCP+UDP, version detection, and basic brute-force.
BASIC_SCAN()
{
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting BASIC scan...\e[0m"
    # Run nmap with basic scan options and save to file
    nmap -Pn -sS -sV -O "$target_ip" > "basic_scan_${target_ip}.txt"
    nmap -Pn -sU --top-ports 20 "$target_ip">> "basic_scan_${target_ip}.txt"

    # Проверка, открыт ли порт 22 (SSH)
    if nmap -p 22 "$target_ip" | grep -q "22/tcp *open"; then
        echo -e "\e[31m[*]\e[0m\e[32m Port 22 is open. Starting ssh-brute...\e[0m"
        {
            echo ""
            nmap --script=ssh-brute "$target_ip" | grep -i "Valid credentials"
        } >> "basic_scan_${target_ip}.txt"
    else
        echo -e "\n\e[91m\e[107m[!] Port 22 is not open. Skipping ssh-brute.\e[0m\n"
        
    fi
}


# FUNCTION: FULL_SCAN
# Runs an advanced scan with full NSE: vuln scripts, brute-force, OS detection, etc.
FULL_SCAN() {
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting FULL scan (may take longer)...\e[0m"

    nmap -Pn -sS -sU --top-ports 20 -sV -O --script "default,vuln" "$target_ip" > "full_scan_${target_ip}.txt"

    if nmap -p 22 "$target_ip" | grep -q "22/tcp *open"; then
        echo -e "\e[31m[*]\e[0m\e[32m Port 22 open — running ssh-brute...\e[0m"
        {
          echo ""
          nmap --script=ssh-brute "$target_ip" | grep -i "Valid credentials"
        } >> "full_scan_${target_ip}.txt"
    fi
}