#!/bin/bash

#+-----------------------------------------------------------------------------------------+
#|                                                                                         |
#|                     Bash Script for Penetration Testing                                 |
#|                                                                                         |
#|  ▸ Checks for required utilities                                                        |
#|  ▸ Automatically installs 'nipe' to route traffic through the TOR network               |
#|  ▸ Masks your MAC addres                                                                |
#|  ▸ Masks your IP address and verifies anonymity                                         |
#|  ▸ Metasploitable2 was used as a testbed for development and debugging.                 |
#|  ▸ This is just a homework project — you will not be able to hack anyone with it 🙂     |
#|                                                                                         |
#|                              Requires root privileges!                                  |
#|                                                                                         |
#+-----------------------------------------------------------------------------------------+


# Global variables used to store key paths, IP information, and working directories
nipe_path=""
real_ip=""
real_country=""
main_dir=""
working_dir=""
timestamp=""
password=""
username=""
target=""
script_start=$(date +%s)
# Get the real external IP address before activating Nipe
real_ip=$(curl -s http://ip-api.com/json | jq -r '.query')
# Get the real country based on the current IP
real_country=$(curl -s http://ip-api.com/json | jq -r '.country')
# Identify the first active non-loopback network interface
iface=$(ip link show up | grep -E '^[0-9]+' | awk -F: '{print $2}' | grep -v lo | head -n1 | tr -d ' ')
# Get and display the current MAC address
orig_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')



# SPINNER - Function to display a rotating spinner
# - Indicates that a background process is running
# - Shows a red rotating spinner (| / - \) and green "..." while waiting
# - The original idea and base code for this function were developed by ChatGPT.
# - The function was further refined and adapted by the script's author.
SPINNER() 
{
    local pid=$1
    local done_message=${3:-""}
    local delay=0.2
    local spinstr='|/-\'

    # Loop while the process with the given PID is still running
    while kill -0 "$pid" 2>/dev/null; do
        for (( i=0; i<${#spinstr}; i++ )); do
            printf "\r\e[31m[%c]\e[0m %s\e[32m...\e[0m" "${spinstr:$i:1}"
            sleep $delay
        done
    done

    # Clear the line after the spinner ends
    printf "\r%-60s\r" ""
}


# START - Function to initialize the script
# - Verifies if the script is run as root
# - Displays a banner using figlet
# - Creates main and working directories for storing results
# - Changes to the working directory
# - Calls the function to check internet connection
START()
{
    local user=$(whoami)

    # Check if the script is run with root privileges
    if [[ "$user" != "root" ]]; then
        echo -e "\n\e[91m\e[107m[!] You must run this script as root.\e[0m\n"
        exit
    else
        # Generate a timestamp for naming result directories
        timestamp=$(date +"%d%m%H%M%S")

        # Display the project banner
        figlet "PENETRATION TESTING"
        echo -e "\nOleksandr Shevchuk S21, TMagen773637, Erel Regev\n"

        # Set the path for the main results directory
        main_dir=$(pwd)/remote_control_results
        mkdir -p "$main_dir" > /dev/null 2>&1

        # Create a subdirectory named with the timestamp
        cd "$main_dir"
        working_dir="$(pwd)/$timestamp"
        mkdir -p "$working_dir"
        cd "$working_dir"

        # Display the current working directory
        echo -e "\e[30m\e[107mCurrent working directory: $(pwd)\e[0m\n"

        # Display current IP address
        echo -e "\n\e[31m[*]\e[0m\e[32m Your IP before nipe.pl: \e[0m$real_ip"
        sleep 0.5

         # Display current country
        echo -e "\e[31m[*]\e[0m\e[32m Your country before nipe.pl: \e[0m$real_country"
        sleep 0.5
        
        # Display the current MAC address
        echo -e "\e[31m[*]\e[0m\e[32m Original MAC address: \e[0m$orig_mac\n"
        sleep 0.5

        # Call the function to verify internet connectivity
        CHECK_INTERNET_CONNECTION
    fi     
}


# CHECK_INTERNET_CONNECTION - Function to verify internet connectivity
# - Displays a message about checking required utilities
# - Pings 8.8.8.8 to test internet access
# - If successful, updates the package list and calls CHECK_APP
# - If unsuccessful, displays a warning and exits the script
CHECK_INTERNET_CONNECTION()
{
    # Inform the user that the script is checking for required utilities
    echo -e "\e[31m[*]\e[0m\e[34m Checking for the presence of utilities required for performing the analysis:\e[0m"
    sleep 2

    # Attempt to ping Google's DNS server with a 3-second timeout
    if ping -c 1 -W 3 8.8.8.8 > /dev/null 2>&1; then
        # If ping is successful, silently update the package list
        apt update > /dev/null 2>&1 &
        SPINNER $!
        # Call function to check required applications
        CHECK_APP
    else
        # If ping fails, notify the user and exit
        echo -e "\n\e[91m\e[107m[!] No internet connection. Check your network.\e[0m\n"
        sleep 2
        exit 1
    fi
}


# CHECK_APP - Function to verify and install required utilities
# - Defines a list of essential utilities for the script
# - Checks whether each utility is installed
# - If not installed, attempts to install it using apt
# - Displays the status of each utility
# - Calls the CHECK_NIPE function after verification
CHECK_APP()
{
    # Define a list of required utilities
    local utilities_for_check="curl exploitdb ftp hydra jq medusa nmap perl rdesktop ssh sshpass telnet tor whois"

    # Iterate through each utility in the list
    for i in $utilities_for_check; do
        # Check if the utility is installed
        if ! command -v "$i" > /dev/null 2>&1; then
            # If not installed, print a warning and attempt to install it
            echo -e "\e[91m\e[107m[!] '$i' is not installed.\e[0m"
            apt install "$i" -y || { echo -e "\e[91m\e[107m[!] Failed to install '$i'.\e[0m"; exit 1; }
        else
            # If already installed, print success message
            echo -e "\e[32m[✔] $i\e[0m"
        fi
        sleep 0.6
    done

    # Call the CHECK_NIPE function to continue
    CHECK_NIPE
}


# CHECK_NIPE - Function to check for and install the 'nipe' anonymity tool
# - Searches for the nipe.pl script on the system
# - If not found, attempts to clone and install 'nipe' and its dependencies
# - Verifies the creation of necessary directories and installation steps
# - Calls the RUN_NIPE function after completion
CHECK_NIPE()
{
    # Search for the nipe.pl script on the system
    nipe_path=$(find /opt/nipe -type f -name nipe.pl 2>/dev/null)

    # If nipe is not found, install it
    if [[ -z "$nipe_path" ]]; then
        echo -e "\e[91m\e[107m[!] 'nipe.pl' not found on the system.\e[0m"
        echo -e "\e[31m[*]\e[0m\e[34m Installing nipe...\e[0m"
        
        # Check if /opt directory exists, create it if not
        if [[ ! -d /opt ]]; then
            mkdir -p /opt || { 
                echo -e "\e[91m\e[107m[!] Failed to create /opt directory.\e[0m"
                exit 1
            }
        fi

        # Navigate to /opt and clone the nipe repository
        cd /opt
        
        git clone https://github.com/htrgouvea/nipe.git || {
            echo -e "\e[91m\e[107m[!] Failed to clone nipe.\e[0m"
            exit 1
        } & SPINNER $!
        
        # Change to the nipe directory
        cd nipe || { echo -e "\e[91m\e[107m[!] Failed to change directory to /opt/nipe.\e[0m"; exit 1; }
        
        # Install required CPAN modules
        yes | cpan install Try::Tiny Config::Simple JSON || {
            echo -e "\e[91m\e[107m[!] Failed to install CPAN modules.\e[0m"
            exit 1
        }

        # Run nipe installation
        perl nipe.pl install || {
            echo -e "\e[91m\e[107m[!] Failed to install nipe.\e[0m"
            exit 1
        }

        # Inform the user of successful installation
        echo -e "\e[31m[*]\e[0m\e[32m nipe installed successfully\e[0m"
        
        # Search again for the nipe.pl path
        nipe_path=$(find /opt/nipe -type f -name nipe.pl 2>/dev/null)
    else
        # If nipe was already found, confirm it
        echo -e "\e[32m[✔] nipe\e[0m"
    fi

    # Call the RUN_NIPE function
    RUN_NIPE
}



# RUN_NIPE - Function to start and verify the Nipe anonymization service
# - Retrieves and displays the real IP and country before Nipe is started
# - Starts the Nipe service and waits for it to become active
# - If the status is not "true", restarts Nipe until it works (up to 20 attempts)
# - Displays the new IP and country after Nipe is enabled
RUN_NIPE()
{
    # Notify the user that Nipe is being started
    echo -e "\n\e[31m[*]\e[0m\e[34m Starting Nipe...\e[0m"

    # Change to the Nipe installation directory and start it
    cd /opt/nipe
    perl nipe.pl start > /dev/null 2>&1 &
    nipe_pid=$!
    SPINNER $nipe_pid

    # Attempt to verify Nipe status up to 20 times
    for i in {1..20}; do
        # Get the current status of Nipe
        nipe_status=$(perl nipe.pl status | grep -i "status" | awk '{print $3}')
        if [[ "$nipe_status" == "true" ]]; then
            # If Nipe is active, confirm anonymity
            echo -e "\e[31m[!]\e[0m\e[32m You are anonymous!\e[0m"
            break
        else
            # Notify the user of the waiting status
            echo -e "\e[31m[$i]\e[0m\e[34m Waiting for Nipe to be ready...\e[0m"
            # If not active, attempt to restart Nipe
            perl nipe.pl restart > /dev/null 2>&1 &
            restart_pid=$!
            SPINNER $restart_pid
        fi
        # Notify the user of the waiting status
        #echo -e "\e[31m[$i]\e[0m\e[34m Waiting for Nipe to be ready...\e[0m"
        #sleep 10
    done

    # Get and display the new IP address after Nipe is enabled
    local new_ip=$(curl -s http://ip-api.com/json | jq -r '.query')
    echo -e "\e[31m[*]\e[0m\e[32m NEW IP: \e[0m$new_ip"

    # Get and display the new country based on the new IP
    local new_country=$(curl -s http://ip-api.com/json | jq -r '.country')
    echo -e "\e[31m[*]\e[0m\e[32m NEW country: \e[0m$new_country"

    #Call the CHANGE_MAC function
    CHANGE_MAC
}

# CHANGE_MAC - Function to change the MAC address of the active network interface
# - Displays the new MAC address after the change
CHANGE_MAC()
{
    # Exit if no active interface is found
    if [ -z "$iface" ]; then
        echo -e "\e[91m\e[107m[!] No active network interface found.\e[0m"
        exit
    fi

    # Bring the interface down, change MAC address, and bring it up again
    ip link set "$iface" down > /dev/null 2>&1
    macchanger -r "$iface" down > /dev/null 2>&1
    ip link set "$iface" up down > /dev/null 2>&1

    # Get and display the new MAC address
    new_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')
    echo -e "\e[31m[*]\e[0m\e[32m New MAC address: \e[0m$new_mac\n"
    exit
}

# TODO: Implement reconnaissance phase
# - Perform initial host discovery
# - Scan open ports and detect services
# - Collect banners and OS info
# - Identify potential attack vectors

# TODO: Implement scanning & enumeration phase
# - Perform detailed service enumeration
# - Identify versions and known vulnerabilities
# - Extract usernames, shares, configurations

# TODO: Implement vulnerability analysis phase
# - Map discovered services to known CVEs
# - Use searchsploit or exploitdb for local exploits
# - Check for misconfigurations and weak passwords

# TODO: Implement exploitation phase
# - Launch targeted attacks or use Metasploit modules
# - Gain initial access to the system

# TODO: Implement post-exploitation phase
# - Escalate privileges if needed
# - Dump credentials, tokens, sensitive data
# - Maintain access via backdoors or reverse shells

# TODO: Implement cleanup phase
# - Remove logs or artifacts
# - Close any opened backdoors
# - Restore system state if required

# TODO: Document all findings
# - Create technical report with evidence
# - Include recommendations and remediation steps



# STOP - Function to gracefully stop the script and restore system state
# - Calculates and displays the total duration of script execution
# - Stops the Nipe service and shows its status
# - Resets iptables rules to default policy (ACCEPT) and flushes existing rules
STOP()
{
    # Stop the Nipe service
    cd /opt/nipe
    perl nipe.pl stop 2>/dev/null

    # Reset iptables rules and policies
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null

    # Get and display the current IP address and country
    echo -e "\n\e[91m\e[107m[!] Nipe is stopped. You are not anonymous.\e[0m\n"
    sleep 0.5
    echo -e "\e[31m[*]\e[0m\e[32m Your IP: \e[0m$real_ip"
    sleep 0.5
    echo -e "\e[31m[*]\e[0m\e[32m Your country: \e[0m$real_country"
    sleep 0.5

    # Recover MAC address
    ip link set "$iface" down > /dev/null 2>&1
    macchanger -p "$iface" > /dev/null 2>&1
    ip link set "$iface" up > /dev/null 2>&1

    # Get and display the recovered MAC address
    orig_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')
    echo -e "\e[31m[*]\e[0m\e[32m Original MAC restored: \e[0m$orig_mac"
    sleep 0.5

    # Record the script end time and calculate duration
    local script_end=$(date +%s)
    local duration=$((script_end - script_start))
    echo -e "\e[31m[*]\e[0m\e[32m Script finished. \e[0mDuration: $((duration / 60)) min $((duration % 60)) sec"
    sleep 0.5
}

# trap - Ensures the STOP function is called automatically when the script exits
trap STOP EXIT

# Start the script by calling the START function
START