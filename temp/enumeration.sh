#!/bin/bash

main_dir=$(pwd)
my_ip=$(hostname -I | awk '{print $1}')

# SELECT_SCAN_METOD
# Prompts the user for scan parameters, sets up the environment,
# validates input, and starts either a basic or full scan.
SELECT_SCAN_METOD() {

    # Prompt the user to enter an IP address to scan
    read -p $'\e[31m[!]\e[0m\e[34m Enter network address/mask (CIDR), e.g., 192.168.0.0/24: \e[0m' network

    if [[ ! "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        echo -e "\e[91m\e[107m[!] Wrong format. Example: 192.168.0.0/24\e[0m\n"
        SELECT_SCAN_METOD    
    fi

    # Prompt the user to choose scan mode: Basic or Full
    read -p $'\e[31m[?]\e[0m\e[34m Choose scan mode: [B]asic or [F]ull: \e[0m' scan_mode_raw

    # Normalize scan mode to readable form
    if [[ "$scan_mode_raw" =~ ^[Bb]$ ]]; then
        scan_mode="Basic"
    elif [[ "$scan_mode_raw" =~ ^[Ff]$ ]]; then
        scan_mode="Full"
    else
        echo -e "\e[91m\e[107m[!]Wrong choice. Example: B or F\e[0m\n"
        return
    fi

    # Prompt the user to enter a folder name where scan results will be stored
    read -p $'\e[31m[!]\e[0m\e[34m Enter folder name for scan results: \e[0m' working_dir

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

        # Use fping to find live hosts in the target network and save IPs to live_hosts.txt
        fping -a -g "$network" 2>/dev/null | awk '{print $1}' | grep -v "$my_ip" > live_hosts.txt

        # Run the selected scan
        if [[ "$scan_mode" == "Basic" ]]; then
            BASIC_SCAN
        else
            FULL_SCAN
        fi
    else
        # Restart the process if user declined
        echo ""
        SELECT_SCAN_METOD
    fi
}


# BASIC_SCAN
# Runs a basic scan: TCP+UDP, version detection, and basic brute-force.
BASIC_SCAN()
{
    # Print starting message with color formatting
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting BASIC scan...\e[0m"

    # Loop over each live IP address found
    for i in $(cat live_hosts.txt); do
        # Inform user which IP is currently being scanned
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: $i\e[0m"

        # Create a separate directory for each IP to store its scan results
        mkdir -p "$i"

        # Run nmap scan with service/version detection and OS detection, output XML to the IP directory
        nmap -Pn -sS -sU --top-port 20 "$i" -oX "./$i/res_${i}.xml" -oN "./$i/res_${i}.txt"> /dev/null 2>&1

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

    # Loop over each live IP address found
    for i in $(cat live_hosts.txt); do
        # Inform user which IP is currently being scanned
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: $i\e[0m"

        # Create a separate directory for each IP to store its scan results
        mkdir -p "$i"

        # Run nmap scan with service/version detection and OS detection, output XML to the IP directory
        nmap -Pn -sC -sS -sU --top-port 10 -sV -O "$i" -oX "./$i/res_${i}.xml" -oN ./$i/res_${i}.txt > /dev/null 2>&1
        # Convert the XML output to a human-readable HTML report in the same directory
        xsltproc "./$i/res_${i}.xml" -o "./$i/res_${i}.html"
    done
    CONFIGURE_WORDLISTS
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

    # Download the default usernames list silently using aria2c
    aria2c -x 4 -s 4 -o usernames.lst \
        'https://docs.google.com/uc?export=download&id=1mPSHpfd-P35FNv4r4nQVxfJmAesVLER_' > /dev/null 2>&1

    # Prompt the user to choose between standard or custom password list
    read -p $'\e[31m[?]\e[0m\e[34m Choose password list: [S]tandard or [C]ustom: \e[0m' passwd_lst_raw

    if [[ "$passwd_lst_raw" =~ ^[Ss]$ ]]; then
        # Download the standard passwords list silently using aria2c
        aria2c -x 4 -s 4 -o passwords.lst \
            'https://docs.google.com/uc?export=download&id=1dCdCBwTg15ZeUmTyZ7YyU7oxb3mccGAu' > /dev/null 2>&1
        passwd_lst="$data/passwords.lst"
    else
        # Ask user to provide full path to their custom password list
        read -p $'\e[31m[!]\e[0m\e[34m Enter the full path to your custom password list: \e[0m' custom_passwd_lst
        passwd_lst="$custom_passwd_lst"
    fi

    # Check that both username and password lists exist; if not, exit with error
    if [[ ! -f "$data/usernames.lst" || ! -f "$passwd_lst" ]]; then
        echo -e "\e[91m[!] Required wordlists not found. Exiting.\e[0m"
        exit 1
    fi

    # Proceed to the brute-force credential scanning function
    WEAK_CREDENTIALS
}

# WEAK_CREDENTIALS
# Attempts to discover weak credentials on open services using Nmap scripts and Hydra.
# SSH, FTP, and Telnet are scanned using Nmap scripts.
# RDP is scanned using Hydra because Nmap lacks RDP brute-force support.
WEAK_CREDENTIALS() {
    # Define the path to the wordlists directory (needed here as well)
    data="$main_dir/$working_dir/wordlists_dir"

    # Loop over each IP address from the address list
    for ip in $(cat "$main_dir/$working_dir/live_hosts.txt"); do
        echo -e "\e[34m[*] Searching for weak passwords on $ip...\e[0m"
        
        # Change to the directory corresponding to this IP address
        cd "$main_dir/$working_dir/$ip" || { echo "Failed to enter directory for $ip"; continue; }

        # Extract protocols of interest (ftp, ssh, telnet, rdp) from nmap scan results,
        # filtering only open services and removing duplicates
        grep -i "open" "res_${ip}.txt" | grep -iE "\b(ftp|ssh|telnet|rdp)\b" | awk '{print $3}' | sort -u > protocol_for_scan.txt

        # Prepare common script arguments for nmap brute scripts
        script_args="userdb=$data/usernames.lst,passdb=$passwd_lst,brute.threads=10"

        # Loop over each protocol found for this IP
        for protocol in $(cat protocol_for_scan.txt); do
            echo -e "\e[33m[>>] Trying $protocol on $ip...\e[0m"

            if [[ "$protocol" == "ftp" ]]; then
                # Run FTP brute-force using nmap ftp-brute script with given wordlists
                nmap -p 21 "$ip" --script ftp-brute --script-args "$script_args" -oN "nmap_ftp_brute_${ip}.txt" > /dev/null 2>&1
                
                # Check if valid credentials were found and output results or clean up
                if grep -q "Valid credentials" "nmap_ftp_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for ftp on $ip:\e[0m"
                    grep "Valid credentials" "nmap_ftp_brute_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for ftp on $ip\e[0m"
                    rm -f "nmap_ftp_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "ssh" ]]; then
                # Run SSH brute-force using nmap ssh-brute script
                nmap -p 22 "$ip" --script ssh-brute --script-args "$script_args" -oN "nmap_ssh_brute_${ip}.txt" > /dev/null 2>&1

                if grep -q "Valid credentials" "nmap_ssh_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for ssh on $ip:\e[0m"
                    grep "Valid credentials" "nmap_ssh_brute_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for ssh on $ip\e[0m"
                    rm -f "nmap_ssh_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "telnet" ]]; then
                # Run Telnet brute-force using nmap telnet-brute script
                nmap -p 23 "$ip" --script telnet-brute --script-args "$script_args" -oN "nmap_telnet_brute_${ip}.txt" > /dev/null 2>&1

                if grep -q "Valid credentials" "nmap_telnet_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for telnet on $ip:\e[0m"
                    grep "Valid credentials" "nmap_telnet_brute_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for telnet on $ip\e[0m"
                    rm -f "nmap_telnet_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "rdp" ]]; then
                # Run RDP brute-force using hydra, since nmap doesn't support RDP brute-force
                hydra -L "$data/usernames.lst" -P "$passwd_lst" -t 8 -o "hydra_rdp_${ip}.txt" rdp://$ip 2>/dev/null

                if grep -qE "login:|password:|\[SUCCESS\]" "hydra_rdp_${ip}.txt"; then
                    echo -e "\e[32m[+] Found valid credentials for rdp on $ip:\e[0m"
                    grep -E "login:|password:|\[SUCCESS\]" "hydra_rdp_${ip}.txt"
                else
                    echo -e "\e[90m[-] No valid credentials for rdp on $ip\e[0m"
                    rm -f "hydra_rdp_${ip}.txt"
                fi
            fi
        done
        # Return to parent directory for next IP
        cd ..
    done
}

SELECT_SCAN_METOD