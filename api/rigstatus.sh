#!/bin/bash

# cpuminer's on network summarizer.
# Tested with Verium(VRM) v1.4 fireworm71 miner.
# May work on other miner software...
# GPL. No warranty or support of any kind.

# 30 seconds timeout during probing
probetimeout=30;

# seconds to human readable time function
convertsecs() {
 ((h=${1}/3600))
 ((m=(${1}%3600)/60))
 ((s=${1}%60))
 printf "%02d:%02d:%02d(H:M:S)\n" $h $m $s
}

printf "\n\e[1mQuery Miner's status on LAN utility.\e[0m\n";

if ! [ -x "$(command -v nmap)" ]; then
  printf "Error: nmap is not installed.\n";
  printf "use \e[1msudo apt-get install nmap\e[0m and try again...\n";
  exit 1
fi

if ! [ -x "$(command -v nc)" ]; then
  printf "Error: nc (netcat) is not installed.\n";
  printf "use \e[1msudo apt install netcat-openbsd\e[0m and try again...\n";
  exit 1
fi

if [ -n "$1" ]; then
        port=$1;
if [ $1 = "help" ]; then
printf "You can specify port number and IP Class.\n";
printf "If specifying IP Class, you must also give Port number as first parameter...\n";
printf "Usage example:-\n";
printf "$0 4048 192.168.0\n\n";
printf "Note(1). All miners must be run with \x1b[36m--api-bind 0.0.0.0:4048\x1b[0m parameter in their commandline\n";
printf "in order for this script to successfuly query the running miner. Change recommended Port if needed.\n";
printf "Note(2). WIFI adapters with powers saving enabled, maybe unreliable to probing.\n";
printf "\e[1m$0 help\e[0m for usage instruction (i.e. providing Port number and IP Class)\n";
exit 0;
fi

else
        port="4048";
fi

if [ -z "$2" ]; then
	ipclass=`echo $(hostname -I) | cut -d . -f 1,2,3;`;
else
        ipclass=`echo $2 | cut -d . -f 1,2,3;`;
fi

printf "Press 'CTRL+C' to cancel at any time...\n";
printf "* Using IP Class\e[33m ${ipclass}\e[0m & Port\e[33m ${port}\e[0m\n";
ipaddresslist=`nmap --max-retries=25 -sn ${ipclass}.0-255 -oG - | awk '/Up$/{print $2}';`;

if [[ -z $ipaddresslist ]]; then

printf "\x1b[33m No valid IP addresses found...\x1b[0m\n";
printf "Is Router isolating clients?\n";
printf "Note(1). All miners must be run with \x1b[36m--api-bind 0.0.0.0:4048\x1b[0m parameter in their commandline\n";
printf "in order for this script to successfuly query the running miner. Change recommended Port if needed.\n";
printf "Note(2). WIFI adapters with powers saving enabled, maybe unreliable to probing.\n";
printf "\e[1m$0 help\e[0m for usage instruction (i.e. providing Port number and IP Class)\n";

else

minercount=0;

for dest in $ipaddresslist; do

summary=`echo summary | nc -i 1 -s ${probetimeout} -w ${probetimeout} -n ${dest} ${port} 2> /dev/null;`;

if [ -n "$summary" ]; then

IFS=';' read -r -a minersummaryarray <<< "$summary";
kshashrate=${minersummaryarray[5]#*=};
uptime=$(convertsecs ${minersummaryarray[14]#*=});
difficulty=${minersummaryarray[10]#*=};
cpufreq=$((${minersummaryarray[13]#*=} / 1000));
acceptedshares=${minersummaryarray[7]#*=};
rejectedshares=${minersummaryarray[8]#*=};
efficiency=$(awk -vp=$acceptedshares -vq=$rejectedshares 'BEGIN{printf "%.2f" ,(1 - q / p) * 100}');
hashrate=$(awk -vp=$kshashrate -vq=60000 'BEGIN{printf "%.2f" ,p * q}');
printf "${dest} - ${hashrate} h/m, miner uptime ${uptime}, accepted shares ${efficiency}%%, cpufreq ${cpufreq}Mhz\n";
minercount=$((minercount+1))

else
otherips+="${dest}\n";

fi

done;
if [ $minercount = 0 ]; then
color="\033[0;31m";
else
color="\033[0;32m";
fi
printf "${color}Total of ${minercount} active miners responded...\x1b[0m\n";
printf "\nOther IP addresses on LAN (could be inactive miner, Router, Smartphones, PC's etc)...\n";
printf "${otherips}";
printf "Note(1). All miners must be run with \x1b[36m--api-bind 0.0.0.0:4048\x1b[0m parameter in their commandline\n";
printf "in order for this script to successfuly query the running miner. Change recommended Port if needed.\n";
printf "Note(2). WIFI adapters with power saving enabled, maybe unreliable to probing.\n";
printf "\e[1m$0 help\e[0m for usage instruction (i.e. providing Port number and IP Class)\n";
fi
