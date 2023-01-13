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

## Add to bashrc
add2bashrc () {
    echo "$@" >> ~/.bashrc
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
# Just cus
sudo apt upgrade -y

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
mkdir ~/scripts
## Linux
mkdir ~/tools/linux
mkdir ~/tools/linux/pe
## Windows
mkdir ~/tools/windows
mkdir ~/tools/windows/generic
mkdir ~/tools/windows/powershell
mkdir ~/tools/windows/cve
mkdir ~/tools/windows/exes
mkdir ~/tools/windows/pe
mkdir ~/tools/windows/impacket

# Quality of life
installs+="vim "
installs+="python3 "
installs+="python3-pip "
installs+="net-tools "
installs+="git "
installs+="terminator "
installs+="wireshark "
installs+="curl "
installs+="nfs-common "
installs+="openvpn "
installs+="sqlite3 "
installs+="remmina "
installs+="mysql-client "
installs+="sqsh "
installs+="ltrace "
installs+="strace "
installs+="ntpdate "
installs+="openjdk-11-jdk "
installs+="socat "
installs+="ffuf "
installs+="wfuzz "
installs+="hexedit "
installs+="binwalk "
installs+="fping "
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
installs+="rubygems "
installs+="python3-impacket "
installs+="john "
installs+="wireshark "
installs+="locate" # End of list, nae space at the end on purpose

apter $installs
# General Hacking
apter sqlmap
git clone https://github.com/danielmiessler/SecLists ~/lists/seclists
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O ~/lists/rockyou.txt
python3 -m pip install dirsearch
python3 -m pip install pyftpdlib
python3 -m pip install updog
python3 -m pip install uploadserver
sudo gem install wpscan
go install github.com/OJ/gobuster/v3@latest
# Linux Hacking
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O ~/tools/linux/linpeas.sh
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ~/tools/linux/pspy64
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ~/tools/linux/pspy32
git clone https://github.com/arthaud/git-dumper ~/tools/linux/git-dumper
python3 -m pip install dulwich
git clone https://github.com/internetwache/GitTools ~/tools/linux/git-tools
git clone https://github.com/nsonaniya2010/SubDomainizer ~/tools/linux/subdomainizer
## Windows Generic
git clone https://github.com/SpiderLabs/Responder ~/tools/windows/responder 
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O ~/tools/windows/generic/kerbrute
chmod +x ~/tools/windows/generic/kerbrute
## Powershell
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -P ~/tools/windows/powershell/
git clone https://github.com/PowerShellMafia/PowerSploit ~/tools/windows/powershell/powersploit
git clone https://github.com/Kevin-Robertson/Powermad ~/tools/windows/powershell/powermad
git clone https://github.com/BloodHoundAD/BloodHound ~/tools/windows/powershell/bloodhound
git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack ~/tools/windows/powersharppack
## Windows CVEs
git clone https://github.com/dirkjanm/CVE-2020-1472 ~/tools/windows/cves/zerologon
## Windows Exes
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries ~/tools/windows/exes/ghostpack-CompiledBinaries
git clone https://github.com/ParrotSec/mimikatz ~/tools/windows/exes/mimikatz
# Windows PE
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O ~/tools/windows/pe

##ffufez
git clone https://github.com/dalemazza/ffufez ~/tools/scripts

#enum4linux
snap install enum4linux

#evil-winrm
gem install evil-winrm


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
unzip ~/tools/pivot/ligolo-ng/windows.zip -d ~/tools/pivot/ligolo-ng


## Pivot stuff end

# Powershell start
snap install powershell --classic
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

### Docker End

### Metasploit Start
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
rm msfinstall
### Metasploit End

### john Start
git clone https://github.com/openwall/john
mv ~/john/run/ ~/tools/2john
sudo rm -r ~/john
wget https://github.com/Sjord/jwtcrack/raw/master/jwt2john.py -O ~/tools/2john
python3 -m pip install pyasn1


### Burp (I need to make this better)
wget "https://portswigger-cdn.net/burp/releases/download?product=community&version=2022.12.4&type=Linux" -O ~/burp
bash ~/burp
rm ~/burp
###

### Create firefox structure and extensions
fext https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-standard/ 
fext https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/
fext https://addons.mozilla.org/en-GB/firefox/addon/cookie-editor/
sudo killall firefox
###


### Burp Certs into firefox
f_profile=$(ls -Al ~/snap/firefox/common/.mozilla/firefox/ | grep ".default" | cut -d " " -f 9)
waiter
wget http://burp/cert -O burp.crt -e use_proxy=yes -e http_proxy=http://127.0.0.1:8080
certutil -A -n "burp" -t "TC,," -i ~/burp.crt -d sql:/home/magna/snap/firefox/common/.mozilla/firefox/$f_profile
sudo killall java # Burp runs via java
###

###zap start
snap install zaproxy --classic

###zap end

##bloodhound
apt-get install wget curl git

wget -O - https://debian.neo4j.org/neotechnology.gpg.key | sudo apt-key add -
echo 'deb http://debian.neo4j.org/repo stable/' | sudo tee /etc/apt/sources.list.d/neo4j.list
echo "deb http://httpredir.debian.org/debian jessie-backports main" | sudo tee -a /etc/apt/sources.list.d/jessie-backports.list


##bloodhound
sudo apt-get install openjdk-8-jdk openjdk-8-jre
sudo apt-get install neo4j
echo "dbms.active_database=graph.db" >> /etc/neo4j/neo4j.conf
echo "dbms.connector.http.address=0.0.0.0:7474" >> /etc/neo4j/neo4j.conf
echo "dbms.connector.bolt.address=0.0.0.0:7687" >> /etc/neo4j/neo4j.conf
echo "dbms.allow_format_migration=true" >> /etc/neo4j/neo4j.conf

git clone https://github.com/adaptivethreat/BloodHound.git ~/tools/windows/generic
cd ~/tools/windows/generic/BloodHound
mkdir /var/lib/neo4j/data/databases/graph.db
cd BloodHound/
cp -R BloodHoundExampleDB.graphdb/* /var/lib/neo4j/data/databases/graph.db
neo4j start
##bloodhound end

#impacket
git clone https://github.com/fortra/impacket.git ~/tools/windows/impacket

git clone https://github.com/dalemazza/AD_tools.git ~/tools/windows/generic


### Budgie
apter ubuntu-budgie-desktop
###

##evil-winrm
apt install rubygems
apt install ruby-dev
gem install evil-winrm

# Alias(es)
add2bashrc "alias powershell='pwsh'"

# Edit Path
add2bashrc 'export PATH=$PATH:~/tools/2john'
add2bashrc 'export PATH=$PATH:~/go/bin'
add2bashrc 'export PATH=$PATH:~/tools/windows/impacket'

# Clear un-needed
sudo apt autoremove -y

# update file locations
echo "Updating locate"
sudo updatedb 2>/dev/null
