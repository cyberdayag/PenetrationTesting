#!/bin/bash

LOCAL_IP=$(hostname -I)
function BASIC()
{
	nmap $network_range -sn | grep report | awk '{print $NF}' >> $dir_name/ips.txt
	
	for ip in $(cat $dir_name/ips.txt)
	do
		mkdir $dir_name/$ip
		nmap $ip -sV >> $dir_name/$ip/scanning_results #includes banner grabbing
		#add masscan for UDP and save it as well.
	done
	
LOGIN_SERVICES="ssh ftp telnet"

	for service in $LOGIN_SERVIECS
	do
		if grep -q "$LOGIN_SERVICES" $dir_name/$ip/scanning_results; then
		echo "$LOGIN_SERVICES found"
		#add hydra/medusa part against the found service! remember to save it into the user's directory, inside the relevant sub_directory $dir_name/$ip/hydra_results.txt for example.
		else
		echo "$LOGIN_SERVICES not found"
	fi

}

#function FULL()
#{
	##remember to find the live hosts in the network here, same as in the BASIC function.
	#cat scanning_results | grep open | awk '{ $1=$2=$3=""; print $0}' to get the services (find any useful way)
	#IFS=$'\n' 
	#after declaring the Internal Field Separator -->> run over the versions using for loop, to get SEARCHSPLOIT sresults.
	
#}

function START()
{
	echo "What is the network range to scan?"
	read network_range

	echo "Please choose a name for the output directory:"
	read dir_name
	mkdir $dir_name

	read -p "Please choose the scanning level [B/F]" LEVEL
	case $LEVEL in
	B)
		BASIC
	;;

	F)
		FULL
	;;
	
	*)
		START
	;;
	esac
}

START
