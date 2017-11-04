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
sudo sysctl -n net.ipv4.tcp_syncookies
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
