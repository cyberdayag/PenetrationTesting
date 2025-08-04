#!/bin/bash


# FUNCTION: SELECT_SCAN_METOD
# Prompts the user for scan parameters, sets up the environment,
# validates input, and starts either a basic or full scan.
SELECT_SCAN_METOD() {

    # Prompt the user to enter an IP address to scan
    read -p $'\e[31m[!]\e[0m\e[34m Enter IP address to scan: \e[0m' host_ip

    # Calculate the network address by replacing the last octet with 0 and appending /24 subnet mask
    network="${host_ip%.*}.0/24"

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

    read -p $'\n\e[31m[!]\e[0m\e[34m Are the details you entered correct? (y/n): \e[0m' validation

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




# FUNCTION: BASIC_SCAN
# Runs a basic scan: TCP+UDP, version detection, and basic brute-force.
BASIC_SCAN()
{
    # Print starting message with color formatting
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting BASIC scan...\e[0m"

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



# FUNCTION: FULL_SCAN
# Runs an advanced scan with full NSE: vuln scripts, brute-force, OS detection, etc.
FULL_SCAN() {
    echo -e "\n\e[31m[*]\e[0m\e[32m Starting FULL scan (may take longer)...\e[0m"

    nmap -Pn -sS -sU --top-ports 20 -sV -O --script "default,vuln" "$host_ip" > "full_scan_${host_ip}.txt"

    if nmap -Pn -p 22 "$host_ip" | grep -q "22/tcp *open"; then
        echo -e "\e[31m[*]\e[0m\e[32m Port 22 open — running ssh-brute...\e[0m"
        {
          echo ""
          nmap -Pn --script=ssh-brute "$host_ip" | grep -i "Valid credentials"
        } >> "full_scan_${host_ip}.txt"
    fi
}

SELECT_SCAN_METOD