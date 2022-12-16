#!/bin/bash

installs=""

## Apt installer
apter () {
    sudo apt install -qq -y $@
}

## Snap installer
snapper () {
    sudo snap install $1
}

## Alias adder
alias () {
    echo "$@" >> ~/.bashrc
}

# All from home
cd ~

# Update init
sudo apt update
# Just cause
sudo apt upgrade -y

# Setup
## General
mkdir ~/Tools
mkdir ~/Lists
mkdir ~/Info
## Linux
mkdir ~/Tools/Linux
## Windows
mkdir ~/Tools/Windows
mkdir ~/Tools/Windows/Generic
mkdir ~/Tools/Windows/Powershell
mkdir ~/Tools/Windows/CVEs
mkdir ~/Tools/Windows/Exes


# Quality of life
installs+="vim "
installs+="python3 "
installs+="python3-pip "
installs+="net-tools "
installs+="git "
installs+="tilix "
installs+="wireshark "
installs+="wine "
installs+="mono-complete "
installs+="curl "
installs+="nfs-common "
installs+="openvpn "
installs+="sqsh "
installs+="ltrace "
installs+="strace "
installs+="ntpdate "
installs+="ffuf "
installs+="wfuzz "
installs+="hexedit "
installs+="binwalk "
installs+="smbclient "
installs+="unzip "
installs+="nmap "
installs+="hydra "
installs+="john "
installs+="hashcat "
installs+="nikto " # Yes I still scan with nikto, it finds stuff... sometimes
installs+="locate"

apter $installs
# Info
git clone https://github.com/HitmanAlharbi/Windows-AD-attacking ~/Info/Windows-AD-attacking
git clone https://github.com/0xJs/RedTeaming_CheatSheet ~/Info/RedTeaming_CheatSheet
python3 -m pip install  grip
# General Hacking
apter sqlmap
git clone https://github.com/danielmiessler/SecLists ~/Lists/SecLists
python3 -m pip install dirsearch
python3 -m pip install pyftpdlib
python3 -m pip install updog
sudo gem install wpscan
# Linux Hacking
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O ~/Tools/Linux/linpeas.sh
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ~/Tools/Linux/pspy64
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ~/Tools/Linux/pspy32
git clone https://github.com/arthaud/git-dumper ~/Tools/Linux/Git-Dumper
git clone https://github.com/internetwache/GitTools ~/Tools/Linux/Git-Tools
git clone https://github.com/nsonaniya2010/SubDomainizer ~/Tools/Linux/SubDomainizer
# Windows Hacking
snapper crackmapexec
snapper impacket
snapper enum4linux
apter ruby-dev
sudo gem install evil-winrm
## Windows Generic
git clone https://github.com/SpiderLabs/Responder ~/Tools/Windows/Generic/Responder 
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O ~/Tools/Windows/Generic/kerbrute
chmod +x ~/Tools/Windows/Generic/kerbrute
## Powershell
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -P ~/Tools/Windows/Powershell/
git clone https://github.com/PowerShellMafia/PowerSploit ~/Tools/Windows/Powershell/PowerSploit
## Windows CVEs
git clone https://github.com/dirkjanm/CVE-2020-1472 ~/Tools/Windows/CVEs/ZeroLogon
## Windows Exes
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries ~/Tools/Windows/Exes/Ghostpack-CompiledBinaries
git clone https://github.com/ParrotSec/mimikatz ~/Tools/Windows/Exes/mimikatz
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -P ~/Tools/Windows/Exes/
unzip ~/Tools/Windows/Exes/SysinternalsSuite.zip -d ~/Tools/Windows/Exes/Sysinternals/
rm ~/Tools/Windows/Exes/SysinternalsSuite.zip



# Powershell start
# Install pre-requisite packages.
sudo apt-get install -y wget apt-transport-https software-properties-common
# Download the Microsoft repository GPG keys
wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
# Register the Microsoft repository GPG keys
sudo dpkg -i packages-microsoft-prod.deb
# Update the list of packages after we added packages.microsoft.com
sudo apt update
# Install PowerShell
sudo apt install -y powershell
# Clean up
rm packages-microsoft-prod.deb
# Powershell End


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

sudo docker pull bannsec/bloodhound
### Docker End

### Metasploit Start
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
rm msfinstall
### Metasploit End

### ___2john Start
git clone https://github.com/openwall/john
mv ~/john/run/ ~/Tools/2John
sudo rm -r ~/john
python3 -m pip install pyasn1 # Kirbi2john.py
### ___2john End

### Burp (I need to make this better)
wget "https://portswigger-cdn.net/burp/releases/download?product=community&version=2022.12.4&type=Linux" -O ~/burp
bash ~/burp
rm ~/burp
###

### Budgie?
read -p 'Yo? You Want budgie desktop? (y) or (n): ' answer
if [ "$answer" = "y" ] || [ "$answer" = "Y" ]
then
    apter ubuntu-budgie-desktop
fi
###

### If its me then change it to me
if [ "$USER" = "magna" ]
then
	wget https://avatars.githubusercontent.com/u/72981738?v=4 -O ~/Pictures/magna.jpg
	sudo cp ~/Pictures/magna.jpg /var/lib/AccountsService/icons/magna
	sudo sed -i '/Icon=/c\Icon=/var/lib/AccountsService/icons/'$USER /var/lib/AccountsService/users/$USER
fi
###

# Alias(es)
alias "alias powershell='pwsh'"

# update file locations
sudo updatedb 2>/dev/null

