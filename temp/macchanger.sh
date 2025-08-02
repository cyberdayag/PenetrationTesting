#!/bin/bash

CHANGE_MAC() {
    iface=$(ip link show up | grep -E '^[0-9]+' | awk -F: '{print $2}' | grep -v lo | head -n1 | tr -d ' ')
    
    if [ -z "$iface" ]; then
        echo -e "\e[91m[!] No active network interface found (except lo).\e[0m"
        return 1
    fi

    echo -e "\e[31m[*]\e[0m Changing MAC address on interface $iface..."

    ip link set "$iface" down
    macchanger -r "$iface"
    ip link set "$iface" up

    new_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')
    echo -e "\e[32m[✔]\e[0m New MAC address: $new_mac"
    sleep 5
    restore_mac "$iface"
}


RESTORE_MAC() {
    iface=$1
    if [ -z "$iface" ]; then
        echo "Usage: restore_mac <interface>"
        return 1
    fi

    echo -e "\e[31m[*]\e[0m Restoring original MAC address on $iface..."

    ip link set "$iface" down
    macchanger -p "$iface"
    ip link set "$iface" up

    orig_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')
    echo -e "\e[32m[✔]\e[0m Original MAC restored: $orig_mac"
}

change_mac
