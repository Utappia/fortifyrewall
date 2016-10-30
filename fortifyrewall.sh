#!/bin/bash
# Name: Fortifyrewall
# Devel: Salih Emin
# Contact: https://github.com/Utappia/fortifyrewall
# License: GPL3

clear
echo "~~~~~~~~~~ Welcome to 'Fortifyrewall' ~~~~~~~~~~~~~~~~~~"
echo "                 v16.10-31.0022"
echo ""
echo "After applying most of the well kown security best practicies,"
echo "this script will apply the most basic settings that will"
echo "discourage any attempts for port scanning and it will also"
echo "block any incomming connections on any port except to"
echo "those defined by the user, before using this script"
echo ""
echo ""
echo "press Ctrl+X to stop befor initiallisation"
echo ""
echo "~~~~~~~~~~~~ Initiallising ~~~~~~~~~~~~~~~~~~~~~~~"
echo "             in 5 secconds"
sleep 1
echo "5....."
sleep 1
echo "4...."
sleep 1
echo "3..."
sleep 1
echo "2.."
sleep 1
echo "1."
sleep 1
echo "Starting Fortifyrewall..."
sleep 1
echo "Checking if iptables-persistent is installed"
sleep 1
echo ""
echo ""
if apt-get -qq install iptables-persistent; then
    echo ""
    echo "OK iptables-persistent is installed ! Procceding..."
    sleep 2
    echo ""
else
    echo ""
    echo "Sorry but I need to install iptables-persistent..."
    sleep 2
    apt update
    apt -y install iptables-persistent
    echo ""
fi
sleep 2
echo ""
echo "Deleting all Firewall settings to start clean..."
# Start clean by setting the default policies for each of the built-in chains to ACCEPT.
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
# Flush the nat and mangle tables, flush all chains (-F), and delete all non-default chains (-X)
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X
sleep 2
echo ""
echo "Dropping Source Routed Packets..."
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
sysctl net.ipv4.conf.all.accept_source_route=0
sleep 2
echo ""
echo "Enable SYN flooding protection (TCP SYN Cookies)..."
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
sysctl net.ipv4.tcp_syncookies=1
sleep 2
echo ""
echo "Drop ICMP redirect messages..."
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
sysctl net.ipv4.conf.all.accept_redirects=0
sleep 2
echo ""
echo "Dont Send ICMP redirect messages..."
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
sysctl net.ipv4.conf.all.send_redirects=0
sleep 2
echo ""
echo "Enable source address spoofing protection..."
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
sysctl net.ipv4.conf.all.rp_filter=1
sleep 2
echo ""
echo "Enable logging of packets with forged source addresses..."
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
sysctl net.ipv4.conf.all.log_martians=1
sleep 2
echo ""
echo "Allow Traffic on loopback interface..."
iptables -A INPUT -i lo -j ACCEPT
sleep 2
echo ""
echo "Allow previously initiated connections to bypass rules..."
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
sleep 2
echo ""
echo "Protect against spoofing packets..."
iptables -A INPUT -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP
sleep 2
echo ""
echo "Disable smb/windows sharing packets because they generate too much logging..."
iptables -A INPUT -p tcp -i eth0 --dport 137:139 -j REJECT
iptables -A INPUT -p udp -i eth0 --dport 137:139 -j REJECT
sleep 2
echo ""
echo "Creating a IP whitelist from which, all connections will be accepted..."
iptables -I INPUT -m recent --name whitelist --rcheck -j ACCEPT
echo ""
echo "Set default policies to DROP..."
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP
sleep 2
echo ""
echo "Enable SMURF attack protection..."
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP

iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
sleep 2
echo ""
echo "Droping all invalid packets..."
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
sleep 2
echo ""
echo "In case of Nmap scan, mess up its scan timing, and start dropping packets..."
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 7 -j DROP
sleep 2
echo ""
echo "In case of Nmap scan, defeat port scanning in non standard configurations (XMAS , Banner Scan, etc)..."
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
sleep 2
####~~~~~~~~ SETTINGS YOU SHOULD CHANGE starts bleow ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~####
# Here you should specify which ports should be open for incomming connections (e.g SSH, FTP, Apache etc)
echo ""
echo "Allow incoming connections to user defined ports..."
# Allow the following ports through from outside if you need them
# SMTP = 25
# DNS =53
# HTTP = 80
# HTTPS = 443
# SSH = 22, or whatever port you have difined in /etc/ssh/sshd_config
# e.g :
#iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT #uncomment if you use webserver
#iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT #uncomment if you use SSL on your webserver
#iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT # accept SSH

# OR for ssh, if you do not use ssh key based authentication uncomment and adjust to your needs:

#iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH -j ACCEPT
#iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j LOG --log-prefix "Fortifyrewall_Blocked_SSH_brute_force "
#iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP

####~~~~~~~~ SETTINGS YOU SHOULD CHANGE ends above ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~####
sleep 2
echo ""
echo "Creating a chain port scan and add logging to it with the 'Fortifyrewall_Blocked_scans' prefix..."
iptables -N portscan
iptables -A portscan -j LOG --log-level 4 --log-prefix 'Fortifyrewall_Blocked_scans '
iptables -A portscan -j DROP
sleep 2
echo ""
echo "Creating a chain UDP flood attemt with the 'Fortifyrewall_UDP_FLOOD' prefix... "
iptables -N UDP
iptables -A UDP -j LOG --log-level 4 --log-prefix 'Fortifyrewall_UDP_FLOOD '
iptables -A UDP -p udp -m state --state NEW -m recent --set --name UDP_FLOOD
iptables -A UDP -j DROP
sleep 2
echo ""
echo "Creating a chain Domainscans with the 'Fortifyrewall_Blocked_domain_scans' prefix... "
iptables -N domainscan
iptables -A domainscan -j LOG --log-level 4 --log-prefix 'Fortifyrewall_Blocked_domain_scans '
iptables -A domainscan -p tcp -m state --state NEW -m recent --set --name Webscanners
iptables -A domainscan -j DROP
sleep 2
echo ""
echo "Adding Blocking mechanism for 24 hours when a scan is detected..."
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j portscan
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j portscan
iptables -A INPUT -m recent --name UDP_FLOOD --rcheck --seconds 86400 -j portscan
iptables -A FORWARD -m recent --name UDP_FLOOD --rcheck --seconds 86400 -j portscan

# Remove attacking IP after 24 hours
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove
iptables -A INPUT -m recent --name UDP_FLOOD --remove
iptables -A FORWARD -m recent --name UDP_FLOOD --remove

#Anyone who does not match the above rules (open ports) is trying to access a port our sever does not serve. So, as per design we consider them port scanners and we block them for an entire day
iptables -A INPUT -p tcp -m tcp -m recent -m state --state NEW --name portscan --set -j portscan
iptables -A INPUT -p udp -m state --state NEW -m recent --set --name domainscans
iptables -A INPUT -p udp -m state --state NEW -m recent --rcheck --seconds 5 --hitcount 5 --name domainscans -j UDP
sleep 2
echo ""
echo "Last but not least, save these awesome new rules..." 
sleep 2
dpkg-reconfigure iptables-persistent
echo ""
echo "~~~~~~~~~~ 'Fortifyrewall has completed applying its settings' ~~~~~~~~~~~"
echo ""
echo "		I hope it saved you valuable time with its usefullness"
echo ""
echo "For any Feedback you have, visit: https://github.com/Utappia/fortifyrewall "
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
sleep 2
