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

## Firefox extension adder
# I couldnt get -install-global-extension to work.. cheers OpenGPT
fext () {
    echo "Installing $1"
    firefox $1
    echo "Press any key to continue once installed"
    while [ true ] ; do
    read -t 3 -n 1
    if [ $? = 0 ] ; then
    break ;
    else
    echo "OI! Add the extension!"
    fi
    done
}

## Waiter
######### CHANGE THIS TO VIEW PIDS ND SHIT
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
# Just cause
sudo apt upgrade -y

# Setup
## General
mkdir ~/Tools
mkdir ~/Lists
mkdir ~/Info
mkdir ~/Tools/Pivot
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
installs+="proxychains "
installs+="unzip "
installs+="nmap "
installs+="hydra "
installs+="php-cli "
installs+="hashcat "
installs+="libnss3-tools "
installs+="nikto " # Yes I still scan with nikto, it finds stuff... sometimes
installs+="sshuttle "
installs+="golang-go "
installs+="ruby-dev "
installs+="locate" # End of list, nae space at the end on purpose

apter $installs
# Info
git clone https://github.com/HitmanAlharbi/Windows-AD-attacking ~/Info/Windows-AD-attacking
git clone https://github.com/0xJs/RedTeaming_CheatSheet ~/Info/RedTeaming_CheatSheet
python3 -m pip install  grip
# General Hacking
apter sqlmap
git clone https://github.com/danielmiessler/SecLists ~/Lists/SecLists
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O ~/Lists/rockyou.txt
python3 -m pip install dirsearch
python3 -m pip install pyftpdlib
python3 -m pip install updog
sudo gem install wpscan
go install github.com/OJ/gobuster/v3@latest
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


## Pivot stuff start
# Chisel
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O ~/chisel.gz
gunzip ~/chisel.gz
chmod +x ~/chisel
mv ~/chisel ~/Tools/Pivot
# Ligolo-ng
git clone https://github.com/nicocha30/ligolo-ng
cd ligolo-ng
go build -o agent cmd/agent/main.go
go build -o proxy cmd/proxy/main.go
GOOS=windows go build -o agent.exe cmd/agent/main.go
GOOS=windows go build -o proxy.exe cmd/proxy/main.go
cd ..
mv ligolo-ng/ ~/Tools/Pivot/
## Pivot stuff end


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
# Alias
alias powershell='pwsh'
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

### john Start
git clone https://github.com/openwall/john
mv ~/john/run/ ~/Tools/2John
sudo rm -r ~/john
python3 -m pip install pyasn1 # Kirbi2john.py
# John docker cause it never f****** works otherwise
# https://hub.docker.com/r/phocean/john_the_ripper_jumbo
sudo docker pull phocean/john_the_ripper_jumbo
sudo docker image tag phocean/john_the_ripper_jumbo phocean/jtr
alias jtr='sudo docker run -it --hostname jtr --rm -v $(pwd):/hashes:ro -v ~/Lists:/lists:ro phocean/jtr'
### john End

### Burp (I need to make this better)
wget "https://portswigger-cdn.net/burp/releases/download?product=community&version=2022.12.4&type=Linux" -O ~/burp
bash ~/burp
rm ~/burp
###

### Create firefox structure and extensions
fext https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-standard/ 
fext https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/
sudo killall firefox
###


### Burp Certs into firefox
f_profile=$(ls -Al ~/snap/firefox/common/.mozilla/firefox/ | grep ".default" | cut -d " " -f 9)
waiter
wget http://burp/cert -O burp.crt -e use_proxy=yes -e http_proxy=http://127.0.0.1:8080
certutil -A -n "burp" -t "TC,," -i ~/burp.crt -d sql:/home/magna/snap/firefox/common/.mozilla/firefox/$f_profile
sudo killall java # Burp runs via java
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

# Edit Path
export PATH=$PATH:~/Tools/2John

# Clear un-needed
sudo apt autoremove

# update file locations
echo "Updating locate"
sudo updatedb 2>/dev/null
