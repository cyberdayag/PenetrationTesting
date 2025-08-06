#!/dev/null


# WEAK_CREDENTIALS
# Attempts to discover weak credentials on open services using Nmap scripts and Hydra.
# SSH, FTP, and Telnet are scanned using Nmap scripts.
# RDP is scanned using Hydra because Nmap lacks RDP brute-force support.

WEAK_CREDENTIALS() {
    for ip in $(cat "$main_dir/$working_dir/address.txt"); do
        echo -e "\e[34m[*] Searching for weak passwords on $ip...\e[0m"
        cd "$main_dir/$working_dir/$ip" || continue

        # Extract login-related protocols from open ports in Nmap result
        grep -i "open" "res_${ip}.txt" | grep -E "ftp|ssh|telnet|rdp" | awk '{print $3}' | sort -u > protocol_for_scan.txt

        for protocol in $(cat protocol_for_scan.txt); do
            echo -e "\e[33m[>>] Trying $protocol on $ip...\e[0m"

            if [[ "$protocol" == "telnet" ]]; then
                # Telnet brute-force via Nmap script
                nmap -p 23 "$ip" --script telnet-brute \
                    --script-args userdb="$main_dir/data/popular_usernames.txt",\
passdb="$main_dir/data/popular_passwords.txt",brute.threads=5 \
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
                    --script-args userdb="$main_dir/data/popular_usernames.txt",\
passdb="$main_dir/data/popular_passwords.txt",brute.threads=5 \
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
                    --script-args userdb="$main_dir/data/popular_usernames.txt",\
passdb="$main_dir/data/popular_passwords.txt",brute.threads=5 \
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
                hydra -L "$main_dir/data/popular_usernames.txt" \
                      -P "$main_dir/data/popular_passwords.txt" \
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

        cd .. || exit
    done
}
