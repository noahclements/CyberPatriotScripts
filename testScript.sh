#!/bin/bash

# This script will be used by Noah Clements from Fredericton High School, Canada, in the CyberTitan Competition.
# Using this script can result in penalties, so please only use for ideas or inspiration for making your own script.

echo "deleting all unneeded files"
find /home -name '*.mp3' -type f -delete
find /home -name '*.mov' -type f -delete
find /home -name '*.mp4' -type f -delete
find /home -name '*.avi' -type f -delete
find /home -name '*.mpg' -type f -delete
find /home -name '*.mpeg' -type f -delete
find /home -name '*.flac' -type f -delete
find /home -name '*.m4a' -type f -delete
find /home -name '*.flv' -type f -delete
find /home -name '*.ogg' -type f -delete
find /home -name '*.gif' -type f -delete
find /home -name '*.png' -type f -delete
find /home -name '*.jpg' -type f -delete
find /home -name '*.jpeg' -type f -delete
echo "done"

echo "Reinstalling core utilities"
sudo apt-get install --reinstall coreutils

echo "update and upgrading"
sudo apt-get -y upgrade
sudo apt-get -y update


echo "*Installing system upgrades*"
sudo apt-get dist-upgrade


echo "enabling firewall"
sudo apt-get install ufw
sudo ufw enable
sudo ufw reset
sudo ufw enable
sudo ufw incoming
sudo ufw outgoing
sudo ufw allow out 53
sudo ufw allow out 80
sudo ufw allow out 443
echo "done"

# lock out root user
sudo passwd -l root


# no guest account
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf

echo "*Resetting bash history*"
sudo rm ~/.bash_history 



echo "Installing cracklib"
sudo apt-get install libpam-cracklib --force-yes -y

echo "setting passwd requisites"
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs

echo "password      requisite           pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password
echo "password      requisite           pam_history.so use_authtok remember=25 enforce_for_root" >> /etc/pam.d/common-password
echo "password      [success=1 default=ignore]  pam_unix.so obscure use_authtok sha512 shadow" >> /etc/pam.d/common-password
echo "auth      optional            pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" >> /etc/pam.d/common-auth

echo "changing all the passwords to complex"
# must have user_list.txt
for i in `more user_list.txt ` 
    do
    echo -e “C0mpl3xPassw0rd\nC0mpl3xPassw0rd” | passwd $i
    
done
echo "*Command complete*"

echo "upgrading firefox and libreoffice"
sudo apt-get --purge --reinstall install firefox
sudo add-apt-repository -y ppa:libreoffice/ppa
sudo apt-get update
sudo apt-get --purge --reinstall install libreoffice

echo "mySQL"
sudo apt-get -y install mysql-server
  # Disable remote access
  sudo sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf
  sudo service mysql restart

  echo "openSSH"
  sudo apt-get -y install openssh-server
  # Disable root login
  sudo sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
  sudo sed -i '/^Protocol/ c\Protocol 2' /etc/ssh/sshd_config
  sudo sed -i '/^IgnoreRhosts/ c\IgnoreRhosts yes' /etc/ssh/sshd_config
  sudo sed -i '/^HostbasedAuthentication/ c\HostbasedAuthentication no' /etc/ssh/sshd_config
  sudo sed -i '/^Banner/ c\Banner   /etc/issue' /etc/ssh/sshd_config
  sudo sed -i '/^PermitEmptyPasswords/ c\PermitEmptyPasswords no' /etc/ssh/sshd_config
  sudo sed -i '/^LogLevel/ c\LogLevel INFO' /etc/ssh/sshd_config
  sudo sed -i '/^UsePrivilegeSeparation/ c\UsePrivilegeSeparation yes' /etc/ssh/sshd_config
  sudo sed -i '/^StrictModes/ c\StrictModes yes' /etc/ssh/sshd_config 
  sudo sed -i '/^VerifyReverseMapping/ c\VerifyReverseMapping yes' /etc/ssh/sshd_config 
  sudo sed -i '/^AllowTcpForwarding/ c\AllowTcpForwarding no' /etc/ssh/sshd_config 
  sudo sed -i '/^X11Forwarding/ c\X11Forwarding no' /etc/ssh/sshd_config
sudo service ssh restart

echo "FTP"
sudo apt-get -y install vsftpd
  sudo sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
  sudo sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
  sudo sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
sudo service vsftpd restart

echo "malware"
sudo apt-get -y purge hydra*
sudo apt-get -y purge john*
sudo apt-get -y purge nikto*
sudo apt-get -y purge netcat*

echo "reset crontab"
    crontab -r
    cd /etc/
    /bin/rm -f cron.deny at.deny
    echo root >cron.allow
    echo root >at.allow
    /bin/chown root:root cron.allow at.allow
    /bin/chmod 644 cron.allow at.allow

echo "iptables"
apt-get install -y iptables
apt-get install -y iptables-persistent

iptables -t nat -F
    iptables -t mangle -F
    iptables -t nat -X
    iptables -t mangle -X
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    ip6tables -t nat -F
    ip6tables -t mangle -F
    ip6tables -t nat -X
    ip6tables -t mangle -X
    ip6tables -F
    ip6tables -X
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP

    iptables -A INPUT -s 127.0.0.0/8 -i firefox -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -s 100.64.0.0/10 -j DROP
    iptables -A INPUT -s 169.254.0.0/16 -j DROP
    iptables -A INPUT -s 192.0.0.0/24 -j DROP
    iptables -A INPUT -s 192.0.2.0/24 -j DROP
    iptables -A INPUT -s 198.18.0.0/15 -j DROP
    iptables -A INPUT -s 198.51.100.0/24 -j DROP
    iptables -A INPUT -s 203.0.113.0/24 -j DROP
    iptables -A INPUT -s 224.0.0.0/3 -j DROP
    #Blocks bogons from leaving the computer
    iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
    iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
    iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
    iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
    iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
    iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
    iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
    iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
    iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
    iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
    #Blocks outbound from source bogons - A bit overkill
    iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
    iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
    iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
    iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
    iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
    iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
    iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
    iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
    iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
    iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
    #Block receiving bogons intended for bogons - Super overkill
    iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
    iptables -A INPUT -d 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 100.64.0.0/10 -j DROP
    iptables -A INPUT -d 169.254.0.0/16 -j DROP
    iptables -A INPUT -d 192.0.0.0/24 -j DROP
    iptables -A INPUT -d 192.0.2.0/24 -j DROP
    iptables -A INPUT -d 198.18.0.0/15 -j DROP
    iptables -A INPUT -d 198.51.100.0/24 -j DROP
    iptables -A INPUT -d 203.0.113.0/24 -j DROP
    iptables -A INPUT -d 224.0.0.0/3 -j DROP
    iptables -A INPUT -i lo -j ACCEPT
    #Least Strict Rules
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    #Strict Rules -- Only allow well known ports (1-1022)
    iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -P OUTPUT DROP
    #Very Strict Rules - Only allow HTTP/HTTPS, NTP and DNS
    iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -P OUTPUT DROP
    mkdir /etc/iptables/
    touch /etc/iptables/rules.v4
    touch /etc/iptables/rules.v6
    iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

echo "sysctl"
sysctl -w net.ipv4.tcp_syncookies=1
    sysctl -w net.ipv4.ip_forward=0
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.send_redirects=0
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.default.accept_redirects=0
    sysctl -w net.ipv4.conf.all.secure_redirects=0
    sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -p

echo "installing some good programs"
sudo apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles

    #This will download lynis 2.4.0, which may be out of date
    wget https://cisofy.com/files/lynis-2.5.5.tar.gz -O /lynis.tar.gz
    sudo tar -xzf /lynis.tar.gz --directory /usr/share/

echo "virus scan"

    #chkrootkit

    chkrootkit -q

    #Rkhunter
    rkhunter --update
    rkhunter --propupd #Run this once at install
    rkhunter -c --enable all --disable none

    #Lynis
    cd /usr/share/lynis/
    /usr/share/lynis/lynis update info
    /usr/share/lynis/lynis audit system

    #ClamAV
    systemctl stop clamav-freshclam
    freshclam --stdout
    systemctl start clamav-freshclam
    clamscan -r -i --stdout --exclude-dir="^/sys" /


# no guest account
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf

echo "*Resetting bash history*"
sudo rm ~/.bash_history 



echo "Installing cracklib"
sudo apt-get install libpam-cracklib --force-yes -y

echo "setting passwd requisites"
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs

echo "password      requisite           pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password
echo "password      requisite           pam_history.so use_authtok remember=25 enforce_for_root" >> /etc/pam.d/common-password
echo "password      [success=1 default=ignore]  pam_unix.so obscure use_authtok sha512 shadow" >> /etc/pam.d/common-password
echo "auth      optional            pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" >> /etc/pam.d/common-auth

echo "changing all the passwords to complex"
# must have user_list.txt
for i in `more user_list.txt ` 
    do
    echo -e “C0mpl3xPassw0rd\nC0mpl3xPassw0rd” | passwd $i
    
done
echo "*Command complete*"

echo "upgrading firefox and libreoffice"
sudo apt-get --purge --reinstall install firefox
sudo add-apt-repository -y ppa:libreoffice/ppa
sudo apt-get update
sudo apt-get --purge --reinstall install libreoffice

echo "mySQL"
sudo apt-get -y install mysql-server
  # Disable remote access
  sudo sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf
  sudo service mysql restart

  echo "openSSH"
  sudo apt-get -y install openssh-server
  # Disable root login
  sudo sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
sudo service ssh restart

echo "FTP"
sudo apt-get -y install vsftpd
  sudo sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
  sudo sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
  sudo sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
sudo service vsftpd restart

echo "malware"
sudo apt-get -y purge hydra*
sudo apt-get -y purge john*
sudo apt-get -y purge nikto*
sudo apt-get -y purge netcat*


sudo apt-get -y update


echo "*Installing system upgrades*"
sudo apt-get dist-upgrade



echo "Installing cracklib"
sudo apt-get install libpam-cracklib --force-yes -y

echo "setting passwd requisites"
sudo perl -pi -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/g' /etc/login.defs
sudo perl -pi -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/g' /etc/login.defs
sudo perl -pi -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/g' /etc/login.defs

echo "password      requisite           pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password
echo "password      requisite           pam_history.so use_authtok remember=25 enforce_for_root" >> /etc/pam.d/common-password
echo "password      [success=1 default=ignore]  pam_unix.so obscure use_authtok sha512 shadow" >> /etc/pam.d/common-password
echo "auth      optional            pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" >> /etc/pam.d/common-auth

echo "changing all the passwords to complex"
# must have user_list.txt
for i in `more user_list.txt `
    do
    echo -e “C0mpl3xPassw0rd\nC0mpl3xPassw0rd” | passwd $i
    
done
echo "*Command complete*"
