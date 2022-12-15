#!/bin/bash

installs=""

## Apt installer
apter () {
    sudo apt install -y $1
}

## Snap installer
snapper () {
    sudo snap install $1
}


# Update init
sudo apt update

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
installs+="locate "

apter $installs
# Info
git clone https://github.com/HitmanAlharbi/Windows-AD-attacking ~/Info/
git clone https://github.com/0xJs/RedTeaming_CheatSheet ~/Info/
python3 -m pip install  grip
# General Hacking
apter sqlmap
git clone https://github.com/danielmiessler/SecLists ~/Lists/
python3 -m pip install dirsearch
python3 -m pip install pyftpdlib
python3 -m pip install updog
sudo gem install wpscan


# Linux Hacking
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O ~/Tools/Linux/linpeas.sh
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ~/Tools/Linux/pspy64
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ~/Tools/Linux/pspy32
git clone https://github.com/arthaud/git-dumper ~/Tools/Linux/
git clone https://github.com/internetwache/GitTools ~/Tools/Linux/
git clone https://github.com/nsonaniya2010/SubDomainizer ~/Tools/Linux/
# Windows Hacking
snapper crackmapexec
snapper impacket
snapper enum4linux
apter ruby-dev
sudo gem install evil-winrm
## Generic
git clone https://github.com/SpiderLabs/Responder ~/Tools/Windows/Generic
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O ~/Tools/Windows/Generic/kerbrute
chmod +x ~/Tools/Windows/Generic/kerbrute
## Powershell
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -P ~/Tools/Windows/Powershell/
git clone https://github.com/PowerShellMafia/PowerSploit ~/Tools/Windows/Powershell
## CVEs
git clone https://github.com/dirkjanm/CVE-2020-1472 ~/Tools/Windows/CVEs
## Exes
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries ~/Tools/Windows/Exes
git clone https://github.com/ParrotSec/mimikatz ~/Tools/Windows/Exes
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -P ~/Tools/Windows/Exes
unzip ~/Tools/Windows/Exes/SysinternalsSuite.zip
rm ~/Tools/Windows/Exes/SysinternalsSuite.zip


# Docker Start
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
# Docker End

# Metasploit Start
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Metasploit End