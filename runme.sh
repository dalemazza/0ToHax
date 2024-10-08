#!/bin/bash

installs=""

## Apt installer
apter () {
    sudo apt install -y $@
}

## Snap installer
snapper () {
    sudo snap install $1
}

## Add to bashrc
add2bashrc () {
    echo "$@" >> ~/.bashrc
}


## Waiter
waiter() {
    echo "Press any key to continue once burp is ready!"
    while [ true ] ; do
    read -t 3 -n 1
    if [ $? = 0 ] ; then
    break ;
    else
    echo "OI! Load Burp! Then once ready press any key!"
    fi
    done
}

# All from home
cd ~

# Update init
sudo apt update
# Just cus
#sudo apt upgrade -y

# Setup
## Ctfs
mkdir ~/ctfs
mkdir ~/ctfs/thm
mkdir ~/ctfs/htb
## General
mkdir ~/tools
mkdir ~/lists
mkdir ~/tools/pivot
mkdir ~/tools/pivot/ligolo-ng
mkdir ~/tools/john
mkdir ~/scripts
mkdir ~/tools/enumeration
## Linux
mkdir ~/tools/linux
mkdir ~/tools/linux/pe
mkdir ~/tools/shells
## Windows
mkdir ~/tools/windows
mkdir ~/tools/windows/generic
mkdir ~/tools/windows/powershell
mkdir ~/tools/windows/cve
mkdir ~/tools/windows/exes
mkdir ~/tools/windows/pe
mkdir ~/tools/windows/pe/sebackupprivilege
mkdir ~/tools/windows/impacket
mkdir /var/www/ady

# Quality of life
installs+="terminator "

apter $installs


## install go
curl -OL https://go.dev/dl/go1.20.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xvf go1.20.2.linux-amd64.tar.gz
add2bashrc 'export PATH=$PATH:/usr/local/go/bin'
source ~/.bashrc


# General Hacking
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O ~/lists/rockyou.txt
git clone https://github.com/cddmp/enum4linux-ng.git ~/tools/enumeration/enum4linux-ng


# Linux Hacking
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O ~/tools/linux/linpeas.sh
wget https://github.com/carlospolop/PEASS-ng/releases/download/20230419-58ad97a0/winPEASany.exe -O ~/tools/windows/pe
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ~/tools/linux/pspy64
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ~/tools/linux/pspy32
git clone https://github.com/arthaud/git-dumper ~/tools/linux/git-dumper
git clone https://github.com/internetwache/GitTools ~/tools/linux/git-tools
git clone https://github.com/nsonaniya2010/SubDomainizer ~/tools/linux/subdomainizer
## Windows Generic
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O ~/tools/windows/generic/kerbrute
chmod +x ~/tools/windows/generic/kerbrute
## Powershell
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -P ~/tools/windows/powershell/
git clone https://github.com/PowerShellMafia/PowerSploit ~/tools/windows/powershell/powersploit
git clone https://github.com/Kevin-Robertson/Powermad ~/tools/windows/powershell/powermad
git clone https://github.com/BloodHoundAD/BloodHound ~/tools/windows/powershell/bloodhound
git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack ~/tools/windows/powersharppack
## Windows Exes
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries ~/tools/windows/exes/ghostpack-CompiledBinaries
git clone https://github.com/ParrotSec/mimikatz ~/tools/windows/exes/mimikatz
# Windows PE
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O ~/tools/windows/pe/printspoofer.exe
wget https://github.com/giuliano108/SeBackupPrivilege/blob/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll?raw=true -O ~/tools/windows/sebackupprivilege
wget https://github.com/giuliano108/SeBackupPrivilege/blob/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll?raw=true -O ~/tools/windows/sebackupprivilege

#Seatbelt
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe -O ~/tools/windows/pe/seatbelt.exe

##Fixing the remote path tab complete
cd /tmp
wget https://ftp.ruby-lang.org/pub/ruby/2.7/ruby-2.7.3.tar.gz
tar -xf ruby-2.7.3.tar.gz
cd ruby-2.7.3/ext/readline
ruby ./extconf.rb
make
sudo cp -f readline.so /usr/lib/x86_64-linux-gnu/ruby/3.0.0/readline.so

## Pivot stuff start
# Chisel
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O ~/chisel.gz
gunzip ~/chisel.gz
chmod +x ~/chisel
mv ~/chisel ~/tools/pivot
# Ligolo-ng
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.3.3/ligolo-ng_agent_0.3.3_Linux_64bit.tar.gz -O ~/tools/pivot/ligolo-ng/linux.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.3.3/ligolo-ng_agent_0.3.3_Windows_64bit.zip -O ~/tools/pivot/ligolo-ng/windows.zip
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.3.3/ligolo-ng_proxy_0.3.3_Linux_64bit.tar.gz -O ~/tools/pivot/ligolo-ng/proxy.tar.gz
tar -xvf ~/tools/pivot/ligolo-ng/linux.tar.gz -C ~/tools/pivot/ligolo-ng
tar -xvf ~/tools/pivot/ligolo-ng/proxy.tar.gz -C ~/tools/pivot/ligolo-ng
unzip -o ~/tools/pivot/ligolo-ng/windows.zip -d ~/tools/pivot/ligolo-ng


## Pivot stuff end

### Docker Start
apter ca-certificates
apter gnupg 
apter lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update init
sudo apt update
apter docker-ce 
apter docker-ce-cli
apter containerd.io
apter docker-compose-plugin

### Docker End

## conpty
git clone https://github.com/antonioCoco/ConPtyShell.git ~/tools/shells/windows/

### pypykatz
pip3 install pypykatz

# nmapautomator
git clone https://github.com/21y4d/nmapAutomator.git ~/tools/nmapautomator

## clone stuff i need

git clone https://github.com/dalemazza/AD_tools.git ~/tools/ad_tools

# Alias(es)
add2bashrc "alias files='echo Serving /var/www;sudo python3 -m http.server --directory /var/www 80'"
add2bashrc "alias filesad='echo Serving /var/www/ad;sudo python3 -m http.server --directory /var/www/ad 80'"

# Edit Path
add2bashrc 'export PATH=$PATH:~/go/bin'
add2bashrc 'export PATH=$PATH:~/tools/scripts'
add2bashrc 'export PATH=$PATH:~/tools/enumeration/nmapautomator'

#sliver
sudo wget https://github.com/BishopFox/sliver/releases/download/v1.5.41/sliver-client_linux -O /usr/local/bin/sliver-client
sudo wget https://github.com/BishopFox/sliver/releases/download/v1.5.41/sliver-server_linux -O /usr/local/bin/sliver-server
sudo chmod +x /usr/local/bin/sliver*


# add passwordless sudo
echo "kali   ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers


# Clear un-needed
sudo apt autoremove -y

# update file locations
echo "Updating locate"
sudo updatedb 2>/dev/null


#print stuff
printf "Now add passwordless sudo\n"
printf "kali   ALL=(ALL) NOPASSWD:ALL >> /etc/sudoers\n"
