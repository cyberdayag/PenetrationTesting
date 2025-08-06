#!/bin/bash

main_dir=$(pwd)

# SELECT_SCAN_METOD
# Prompts the user for scan parameters, sets up the environment,
# validates input, and starts either a basic or full scan.
SELECT_SCAN_METOD() {

    # Prompt the user to enter an IP address to scan
    read -p $'\e[31m[!]\e[0m\e[34m Enter IP address to scan: \e[0m' network

    # Prompt the user to enter a folder name where scan results will be stored
    read -p $'\e[31m[!]\e[0m\e[34m Enter folder name for scan results: \e[0m' working_dir

    # Prompt the user to choose scan mode: Basic or Full
    read -p $'\e[31m[?]\e[0m\e[34m Choose scan mode: [B]asic or [F]ull: \e[0m' scan_mode_raw

    # Normalize scan mode to readable form
    if [[ "$scan_mode_raw" =~ ^[Bb]$ ]]; then
        scan_mode="Basic"
    else
        scan_mode="Full"
    fi

    # Show summary and ask for confirmation
    echo -e "\n\e[31m[*]\e[0m\e[32m Please verify the entered data:\e[0m"
    echo ""
    echo -e "    Target network : $network"
    echo -e "    Output folder  : $working_dir"
    echo -e "    Scan mode      : $scan_mode"

    read -p $'\n\e[31m[!]\e[0m\e[34m Is everything correct? (y/n): \e[0m' validation

    if [[ "$validation" == "y" || "$validation" == "Y" ]]; then
        # Create output directory if it doesn't exist
        mkdir -p "$working_dir" > /dev/null 2>&1

        # Change to the output directory
        cd "$working_dir"

        # Run the selected scan
        if [[ "$scan_mode" == "Basic" ]]; then
            BASIC_SCAN
        else
            FULL_SCAN
        fi
    else
        # Restart the process if user declined
        SELECT_SCAN_METOD
    fi
}




# BASIC_SCAN
# Runs a basic scan: TCP+UDP, version detection, and basic brute-force.
BASIC_SCAN()
{
    # Print starting message with color formatting
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting BASIC scan...\e[0m"

    # Use fping to find live hosts in the target network and save IPs to address.txt
    my_ip=$(hostname -I | awk '{print $1}')
    fping -a -g "$network" 2>/dev/null | awk '{print $1}' | grep -v "$my_ip" > address.txt

    # Loop over each live IP address found
    for i in $(cat address.txt); do
        # Inform user which IP is currently being scanned
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: $i\e[0m"

        # Create a separate directory for each IP to store its scan results
        mkdir -p "$i"

        # Run nmap scan with service/version detection and OS detection, output XML to the IP directory
        nmap -Pn -sV --version-all "$i" -oX "./$i/res_${i}.xml" -oN "./$i/res_${i}.txt"> /dev/null 2>&1

        # Convert the XML output to a human-readable HTML report in the same directory
        xsltproc "./$i/res_${i}.xml" -o "./$i/res_${i}.html"
    done

    CONFIGURE_WORDLISTS
}



# FUNCTION: FULL_SCAN
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
        nmap -Pn -sV -O --version-all "$i" -oX "./$i/res_${i}.xml" > /dev/null 2>&1

        # Convert the XML output to a human-readable HTML report in the same directory
        xsltproc "./$i/res_${i}.xml" -o "./$i/res_${i}.html"

        # Check if port 22 (SSH) is open on the target IP
        if nmap -Pn -p 22 "$i" | grep -q "22/tcp *open"; then
            echo -e "\e[31m[*]\e[0m\e[32m Port 22 on address $i is open. Starting ssh-brute...\e[0m"
            {
                echo ""
                # Run nmap ssh-brute script and save any valid credentials found to a file
                nmap -Pn --script=ssh-brute "$i" | grep -i "Valid credentials"
            } >> "./$i/brut_force_${i}_result.txt"
        else
            # Notify user if port 22 is closed or filtered and skipping brute-force attempt
            echo -e "\e[91m\e[107m[!] Port 22 on address $i is not open. Skipping ssh-brute.\e[0m\n"
        fi
    done
}


# CONFIGURE_WORDLISTS
# Downloads or sets up required wordlists for brute-force operations.
CONFIGURE_WORDLISTS() {
    # Define the path to the wordlists directory
    data="$main_dir/$working_dir/wordlists_dir"
    
    # Create the wordlists directory if it doesn't exist
    mkdir -p "$data"
    
    # Change to the wordlists directory
    cd "$data"

    # Download default usernames list silently
    wget -O usernames.lst --no-check-certificate \
        'https://docs.google.com/uc?export=download&id=1mPSHpfd-P35FNv4r4nQVxfJmAesVLER_' > /dev/null 2>&1

    # Ask user to choose a password list type
    read -p $'\e[31m[!]\e[0m\e[34m Choose password list: [S]tandard or [C]ustom: \e[0m' passwd_lst_raw

    if [[ "$passwd_lst_raw" =~ ^[Ss]$ ]]; then
        # Download standard passwords list
        wget -O passwords.lst --no-check-certificate \
            'https://docs.google.com/uc?export=download&id=1dCdCBwTg15ZeUmTyZ7YyU7oxb3mccGAu' > /dev/null 2>&1
        passwd_lst="$data/passwords.lst"
    else
        # Prompt user to provide custom password list and copy it to the wordlists directory
        read -p $'\e[31m[!]\e[0m\e[34m Enter the full path to your custom password list: \e[0m' custom_passwd_lst
        cp "$custom_passwd_lst" "$data"
        passwd_lst="$data/$(basename "$custom_passwd_lst")"
    fi

    # Verify that both username and password lists exist
    if [[ ! -f "$data/usernames.lst" || ! -f "$passwd_lst" ]]; then
        echo -e "\e[91m[!] Required wordlists not found. Exiting.\e[0m"
        exit 1
    fi

    # Start credential brute-force process
    WEAK_CREDENTIALS
}

# WEAK_CREDENTIALS
# Attempts to discover weak credentials on open services using Nmap scripts and Hydra.
# SSH, FTP, and Telnet are scanned using Nmap scripts.
# RDP is scanned using Hydra because Nmap lacks RDP brute-force support.

WEAK_CREDENTIALS() {
    for ip in $(cat "$main_dir/$working_dir/address.txt"); do
        echo -e "\e[34m[*] Searching for weak passwords on $ip...\e[0m"
        cd "$main_dir/$working_dir/$ip"

        # Extract login-related protocols from open ports in Nmap result
        grep -i "open" "res_${ip}.txt" | grep -E "ftp|ssh|telnet|rdp" | awk '{print $3}' | sort -u > protocol_for_scan.txt

        for protocol in $(cat protocol_for_scan.txt); do
            echo -e "\e[33m[>>] Trying $protocol on $ip...\e[0m"

            if [[ "$protocol" == "telnet" ]]; then
                # Telnet brute-force via Nmap script
                nmap -p 23 "$ip" --script telnet-brute \
                    --script-args userdb="$data/usernames.lst",\
passdb="$passwd_lst",brute.threads=5 \
                    -oN "nmap_telnet_brute_${ip}.txt" > /dev/null 2>&1

                if grep -q "Valid credentials" "nmap_telnet_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for telnet on $ip:\e[0m"
                    grep "Valid credentials" "nmap_telnet_brute_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for telnet on $ip\e[0m"
                    rm -f "nmap_telnet_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "ssh" ]]; then
                # SSH brute-force via Nmap script
                nmap -p 22 "$ip" --script ssh-brute \
                    --script-args userdb="$data/usernames.lst",\
passdb="$passwd_lst",brute.threads=5 \
                    -oN "nmap_ssh_brute_${ip}.txt" > /dev/null 2>&1

                if grep -q "Valid credentials" "nmap_ssh_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for ssh on $ip:\e[0m"
                    grep "Valid credentials" "nmap_ssh_brute_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for ssh on $ip\e[0m"
                    rm -f "nmap_ssh_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "ftp" ]]; then
                # FTP brute-force via Nmap script
                nmap -p 21 "$ip" --script ftp-brute \
                    --script-args userdb="$data/usernames.lst",\
passdb="$passwd_lst",brute.threads=5 \
                    -oN "nmap_ftp_brute_${ip}.txt" > /dev/null 2>&1

                if grep -q "Valid credentials" "nmap_ftp_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for ftp on $ip:\e[0m"
                    grep "Valid credentials" "nmap_ftp_brute_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for ftp on $ip\e[0m"
                    rm -f "nmap_ftp_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "rdp" ]]; then
                # RDP brute-force via Hydra (Nmap doesn't support it)
                hydra -L "$data/usernames.lst" \
                      -P "$passwd_lst" \
                      -t 8 \
                      -o "hydra_rdp_${ip}.txt" \
                      rdp://$ip 2>/dev/null

                if grep -qE "login:|password:|\[SUCCESS\]" "hydra_rdp_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for rdp on $ip:\e[0m"
                    grep -E "login:|password:|\[SUCCESS\]" "hydra_rdp_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for rdp on $ip\e[0m"
                    rm -f "hydra_rdp_${ip}.txt"
                fi
            fi
        done

        cd ..
    done
}



SELECT_SCAN_METOD