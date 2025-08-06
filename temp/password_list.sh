#!/bin/bash
main_dir=$(pwd)

# CONFIGURE_WORDLISTS
# Downloads or sets up required wordlists for brute-force operations.
# Downloads a default usernames list and either a standard or custom passwords list,
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
}

CONFIGURE_WORDLISTS