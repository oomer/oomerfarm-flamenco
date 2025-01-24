#!/bin/bash
# bootstrapmanager.sh

# Turns this machine into a renderfarm hub running
# - [ ] flamenco-manager 
# - [ ] a Nebula VPN lighthouse for internet discovery on port 42042/udp
# - [ ] a Nebula VPN node with limited ACL with private ip address of 10.88.0.1/16
# - [ ] Nebula firewall rules limited to server exposure
# - [ ] samba share as oomerfarm rooted at /mnt/oomerfarm bound to 10.88.0.1:445
# - [ ] SELinux enabled ( Thus limited to Alma/RockyLinux, AppArmor for Debian/Ubuntu in future release)
# - [ ] firewalld blocking all internet ports except 22/tcp and 42042/udp
# - [ ] decryption of Nebula keys uses ephemeral passphrase 
# - [ ] due to the pirate seas of the internet, this script attempts security hardening
# - [ ] causing breakage of any existing server's services, you have been warned 

source /etc/os-release # get os envars
skip="yes"
os_name=$(awk -F= '$1=="NAME" { print $2 ;}' /etc/os-release)

# Nebula VPN
nebula_name="farm"
nebula_ip="10.88.0.1"
nebula_public_port="42042"
nebula_version="v1.9.5"
nebulasha256="af57ded8f3370f0486bb24011942924b361d77fa34e3478995b196a5441dbf71"
nebula_url="https://github.com/slackhq/nebula/releases/download/${nebula_version}/nebula-linux-amd64.tar.gz"
farm_name="oomerfarm"
user_name="oomerfarm"
linux_password="oomerfarm"  

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    dnf -y install tar curl initscripts
elif ! [ $skip == "yes" ]; then
    if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
        apt -y update
        apt -y install tar curl
    fi
else
    echo "\e[31mFAIL:\e[0m Unsupported operating system $os_name"
    exit
fi

public_ip=$(curl ifconfig.me)

# Bella path traeer
bella_version="24.6.1"
bella_url="https://downloads.bellarender.com/bella_cli-${bella_version}.tar.gz"
bellasha256="3ddcff1994dd3f13a7048472ccf7fbb48b0651b1fd627d07f35cab94475c9261"

#blender
blenderversion="4.3.2"
blenderurl="https://mirrors.ocf.berkeley.edu/blender/release/Blender4.3"
blendersha256=""

# Flamenco 
flamenco_version="3.6"
flamenco_url="https://flamenco.blender.org/downloads/"
flamenco_tar="flamenco-${flamenco_version}-linux-amd64.tar.gz"
flamencosha256="545860f477d0fe4c0bd9a3cd0a9547c9eb469e30bfa55ab8dec9d6fd7209ad63"

echo -e "\n\e[32mTurns this machine into a renderfarm\e[0m \e[36m\e[5mhub\e[0m\e[0m"
echo -e "\e[31mWARNING:\e[0m Mandatory Security hardening will occur to limit internet facing ports"
echo -e "\e[31mWARNING:\e[0m ALL EXISTING SERVICES ON THIS MACHINE WILL BREAK"
echo -e " - become VPN node at \e[36m${nebula_ip}/16\e[0m"
echo -e " - deploy VPN lighthouse at \e[36m${public_ip}\e[0m for internet-wide network 42042/udp"
echo -e " - deploy VPN file server, at \e[36msmb://${nebula_name}.oomer.org\e[0m, \e[36m//${nebula_name}.oomer.org\e[0m (win) 10.88.0.1"
echo -e " - \e[37mfirewall\e[0m blocks ALL non-${farm_name} ports"
echo -e " - enforce \e[37mselinux\e[0m for maximal security"
echo -e " - Supported on Alma/Rocky 8.x 9,x Linux"
echo -e "\e[32mContinue on\e[0m \e[37m$(hostname)?\e[0m"

read -p "(Enter Yes) " accept
if [ "$accept" != "Yes" ]; then
    echo -e "\n\e[31mFAIL:\e[0m Script aborted because Yes was not entered"
    exit
fi

if [ "$nebula_name" = "farm" ]; then

    # EXTRA SECURITY for Redhat like
    if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    # abort if selinux is not enforced
    # selinux provides a os level security sandbox and is very restrictive
    # especially important since renderfarm jobs can included arbitrary code execution on the workers
        test_selinux=$( getenforce )
        if [ "$test_selinux" == "Disabled" ] || [ "$test_selinux" == "Permissive" ];  then
           echo -e "\n\e[31mFAIL:\e[0m Selinux is disabled, edit /etc/selinux/config"
           echo "==================================================="
           echo "Change SELINUX=disabled to SELINUX=enforcing"
           echo -e "then \e[5mREBOOT\e[0m ( SELinux chcon on boot drive takes awhile)"
           echo -e "On some Linux distros, selinux is force disabled"
           echo -e "run this to fix:"
           echo -e "grubby --update-kernel ALL --remove-args selinux"
           echo "=================================================="
           exit
        fi
        # Enable Firewalld
        firewalld_status=$(systemctl status firewalld)
        if [ -z "$firewalld_status" ]; then
           echo -e "\e[32mInstalling firewalld...\e[0m"
           if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
               apt -y install firewalld
           elif [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
               dnf -y install firewalld
           fi
           systemctl enable --now firewalld
        fi
        if ! [[ "$firewalld_status" == *"running"* ]]; then
           systemctl enable --now firewalld
        fi
    fi

    echo -e "\nENTER \e[36m\e[5mpassphrase\e[0m\e[0m to decode \e[32m${nebula_name}.keys.encrypted\e[0m YOU set in \"bolstersecurity.sh\"  ( keystrokes hidden )"
    IFS= read -rs encryption_passphrase < /dev/tty
    if [ -z "$encryption_passphrase" ]; then
        echo -e "\n\e[31mFAIL:\e[0m Invalid empty passphrase"
        exit
    fi

    echo -e "\n\e[36m\e[5mURL\e[0m\e[0m to \e[32m${nebula_name}.keys.encrypted\e[0m"
        read -p "Enter: " keybundle_url
    if [ -z "$keybundle_url" ]; then
        echo -e "\e[31mFAIL:\e[0m URL cannot be blank"
        exit
    fi
fi

### Ensure max security
# disallow ssh password authentication
sed -i -E 's/#?PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config 


if id "${user_name}" &>/dev/null; then
  echo "User ${user_name} exists"
else
    echo -e "\e[32mCreating user:\e[0m ${user_name}"
    groupadd -g 3000 ${user_name}
    useradd -g 3000 -u 3000 -m ${user_name}
fi
#- [TODO] add feature to set linux_password at runtime avoiding password in code
echo "${user_name}:${linux_password}" | chpasswd

# Install Nebula VPN
mkdir -p /etc/nebula
echo -e "\e[32mDownloading Nebula VPN\e[0m"
curl -L -O ${nebula_url}
MatchFile="$(echo "${nebulasha256} nebula-linux-amd64.tar.gz" | sha256sum --check)"
if [ "$MatchFile" = "nebula-linux-amd64.tar.gz: OK" ] ; then
    echo -e "Extracting ${nebula_url}\n"
    tar --skip-old-files -xzf nebula-linux-amd64.tar.gz
else
    echo -e "\e[31mFAIL:\e[0m nebula-linux-amd64.tar.gz checksum failed, file possibly maliciously altered on github"
    exit
fi
mv nebula /usr/local/bin/nebula
chmod +x /usr/local/bin/
mv nebula-cert /usr/local/bin/
chmod +x /usr/local/bin/nebula-cert
rm -f nebula-linux-amd64.tar.gz

# SELinux extra security
if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    chcon -t bin_t /usr/local/bin/nebula # SELinux security clearance
fi

# Get keys.encrypted from public url, Google Drive links are proxied
if [[ "$keybundle_url" == *"https://drive.google.com/file/d"* ]]; then
    # if find content-length, then gdrive link is not restricted, this is a guess
    head=$(curl -s --head ${keybundle_url} | grep "content-length")
    echo ${head}	
    if [[ "$head" == *"content-length"* ]]; then
        # Extract Google uuid 
        googlefileid=$(echo $keybundle_url | egrep -o '(\w|-){26,}')
        head2=$(curl -s --head -L "https://drive.google.com/uc?export=download&id=${googlefileid}" | grep "content-length")
        if [[ "$head2" == *"content-length"* ]]; then
            echo -e "\e[32mDownloading secret keys https://drive.google.com/uc?export=download&id=${googlefileid}\e[0m"
            curl -L "https://drive.google.com/uc?export=download&id=${googlefileid}" -o ${nebula_name}.keys.encrypted
        else
            echo -e "\e[31mFAIL:\e[0m ${keybundle_url} is not public, Set General Access to Anyone with Link"
            exit
        fi
    else
        echo -e "\e[31mFAIL:\e[0m ${keybundle_url} is not a valid Google Drive link"
        exit
    fi
# This should work with URL's pointing to normal website locations or public S3 storage 
else
    curl -L "${keybundle_url}"  -o ${nebula_name}.keys.encrypted
    if ! ( test -f ${nebula_name}.keys.encrypted ) ; then
        echo -e "\e[31mFAIL:\e[0m ${nebula_name}.keys.encrypted URL you entered \e[31m${keybundle_url}\e[0m does not exist"
        exit
    fi
fi

# decrypt keys.encrypted
while :
do
    if openssl enc -aes-256-cbc -pbkdf2 -d -in ${nebula_name}.keys.encrypted -out ${nebula_name}.tar -pass file:<( echo -n "$encryption_passphrase" ) ; then
    rm ${nebula_name}.keys.encrypted
        break
    else
        echo "WRONG passphrase entered for ${nebula_name}.keys.encrypted, try again"
        echo "Enter passphrase for ${nebula_name}.keys.encrypted, then hit return"
        echo "==============================================================="
        IFS= read -rs $encryption_passphrase < /dev/tty
    fi 
done  

testkeybundle=$( tar -tf ${nebula_name}.tar ${nebula_name}/${nebula_name}.key 2>&1 )
if ! [[ "${testkeybundle}" == *"Not found"* ]]; then
    tar --to-stdout -xvf ${nebula_name}.tar ${nebula_name}/ca.crt > ca.crt
    tar --to-stdout -xvf ${nebula_name}.tar ${nebula_name}/${nebula_name}.crt > ${nebula_name}.crt
    ERROR=$( tar --to-stdout -xvf ${nebula_name}.tar ${nebula_name}/${nebula_name}.key > ${nebula_name}.key 2>&1 )
    if ! [ "$ERROR" == *"Fail"* ]; then
        if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
            chown root:root "${nebula_name}.key"
            chown root:root "${nebula_name}.crt"
            chown root:root "ca.crt"
        else
            chown root.root "${nebula_name}.key"
            chown root.root "${nebula_name}.crt"
            chown root.root "ca.crt"
        fi
        chmod go-rwx "${nebula_name}.key"
        mv ca.crt /etc/nebula
        mv "${nebula_name}.crt" /etc/nebula
        mv "${nebula_name}.key" /etc/nebula
        rm ${nebula_name}.tar
    else
        rm ${nebula_name}.tar
    fi 
else
        echo -e "\e[31mFAIL:\e[0m ${nebula_name}.keys.encrypted missing"
    echo  "${keybundle_url} might be corrupted or not shared publicly"
    echo  "Use becomesecure.sh to generate keys, reupload"
    echo  "Check your Google Drive file link is \"Anyone who has link\""
    exit
fi

# create Nebula VPN config file
cat <<EOF > /etc/nebula/config.yml

pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/${nebula_name}.crt
  key: /etc/nebula/${nebula_name}.key

static_host_map:
  "${nebula_ip}": ["${public_ip}:${nebula_public_port}"]

lighthouse:
  am_lighthouse: true
  interval: 60

listen:
  host: 0.0.0.0
  port: ${nebula_public_port}

punchy:
  punch: true

relay:
  am_relay: false
  use_relays: false

tun:
  disabled: false
  dev: nebula_tun
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

logging:
  level: info
  format: text

firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m

  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: icmp
      host: any

    - port: 22 
      proto: tcp
      groups:
        - user

    - port: 445
      proto: tcp
      groups:
        - farm

    - port: 8080
      proto: tcp
      groups:
        - farm
EOF

cat <<EOF > /etc/systemd/system/nebula.service
[Unit]
Description=Nebula Launcher Service
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=30
ExecStart=/usr/local/bin/nebula -config /etc/nebula/config.yml

[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now nebula


# Install Samba
echo -e "\n\e[32mInstalling File Server ( Samba )...\e[0m"

if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
    apt -y install cifs-utils
    apt -y install samba
elif [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    dnf -y install cifs-utils
    dnf -y install samba
fi
cat <<EOF > /etc/samba/smb.conf
ntlm auth = mschapv2-and-ntlmv2-only
interfaces = 127.0.0.1 ${nebula_ip}/16
bind interfaces only = yes
disable netbios = yes
smb ports = 445

[${farm_name}]
   path = /mnt/${farm_name}
   browseable = yes 
   read only = no
   guest ok = no
   create mask = 0777
   directory mask = 0777
EOF

if [ "$os_name" == "\"Ubuntu\"" ]; then
    systemctl stop nmbd
    systemctl disable nmbd
    systemctl restart smbd
elif [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    systemctl enable --now smb

    # ***FIREWALL rules*** SECURITY HARDENING
    # adopting highly restrictive rules to protect network
    echo -e "\n\e[32mTurning up Firewall security...\e[0m"

    # Wipe all services and ports except ssh and 22/tcp, may break system
    for systemdservice in $(firewall-cmd --list-services --zone public);
    do 
       if ! [[ "$systemdservice" == "ssh" ]]; then
           firewall-cmd -q --zone public --remove-service ${systemdservice} --permanent
       fi
    done
    for systemdport in $(firewall-cmd --list-ports --zone public);
    do 
       if ! [[ "$systemdport" == "22/tcp" ]]; then
           firewall-cmd -q --zone public --remove-port ${systemdport} --permanent
       fi
    done
    firewall-cmd -q --reload

    # Allow Nebula VPN connections over internet
    firewall-cmd -q --zone=public --add-port=${nebula_public_port}/udp --permanent

    # Add Nebula zone on "nebula_tun" , not sure if this is needed since Nebula has built-in firewall
    firewall-cmd -q --new-zone nebula --permanent
    firewall-cmd -q --zone nebula --add-interface nebula_tun --permanent
    firewall-cmd -q --zone nebula --add-service ssh --permanent # Allow ssh connections over VPN
    firewall-cmd -q --zone nebula --add-port 445/tcp --permanent # Allow smb/cifs connections over VPN
    firewall-cmd -q --zone nebula --add-port 8080/tcp --permanent # Allow http sccess

    firewall-cmd -q --reload
fi  

mkdir -p /mnt/${farm_name}
mkdir -p /mnt/${farm_name}/bella
mkdir -p /mnt/${farm_name}/bella/renders
mkdir -p /mnt/${farm_name}/installers

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    chown ${user_name}:${user_name} /mnt/${farm_name}
    chown ${user_name}:${user_name} /mnt/${farm_name}/bella
    chown ${user_name}:${user_name} /mnt/${farm_name}/bella/renders
elif [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
    chown ${user_name}.${user_name} /mnt/${farm_name}
    chown ${user_name}.${user_name} /mnt/${farm_name}/bella
    chown ${user_name}.${user_name} /mnt/${farm_name}/bella/renders
fi 

# SELinux beat me again because missed chcon and could mount but not see samba shares contents
if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    chcon -R -t samba_share_t /mnt/${farm_name}/
fi

# Set password, confirm password
(echo ${linux_password}; echo ${linux_password}) | smbpasswd -a ${user_name} -s

# Cache Bella Installer for workers on farm
echo -e "\e[32mDownloading Bella path tracer ...\e[0m"
curl -O ${bella_url}
MatchFile="$(echo "${bellasha256} bella_cli-${bella_version}.tar.gz" | sha256sum --check)"
mkdir -p /mnt/${farm_name}/installers
if [ "$MatchFile" = "bella_cli-${bella_version}.tar.gz: OK" ] ; then
    cp bella_cli-${bella_version}.tar.gz /mnt/${farm_name}/installers/
    rm bella_cli-${bella_version}.tar.gz 
else
    rm bella_cli-${bella_version}.tar.gz 
    echo "\e[31mFAIL:\e[0m bella checksum failed, may be corrupted or malware"
    exit
fi

# Install Flamenco-manager
echo -e "\e[32mDownloading Flamenco-manager\e[0m"
curl -L -O "${flamenco_url}${flamenco_tar}"

MatchFile="$(echo "${flamencosha256} ${flamenco_tar}" | sha256sum --check)"
if [ "$MatchFile" = "${flamenco_tar}: OK" ] ; then
    echo -e "Extracting ${flamenco_tar}\n"
    tar --skip-old-files -xzf ${flamenco_tar}
else
    echo -e "\e[31mFAIL:\e[0m ${flamenco_tar} checksum failed, file possibly maliciously altered on github"
    exit
fi

echo flamenco-${flamenco_version}-linux-amd64/flamenco-manager /home/${user_name}/flamenco-manager
cp flamenco-${flamenco_version}-linux-amd64/flamenco-manager /home/${user_name}/flamenco-manager
cp flamenco-${flamenco_version}-linux-amd64/flamenco-worker /mnt/${farm_name}/installers
cp -r flamenco-${flamenco_version}-linux-amd64/tools /mnt/${farm_name}/installers/tools
if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    chown ${user_name}:${user_name}  /home/${user_name}/flamenco-manager
elif [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
    chown ${user_name}.${user_name}  /home/${user_name}/flamenco-manager
fi
if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    chcon -t bin_t /home/${user_name}/flamenco-manager # SELinux security clearance
fi

cat <<EOF > /etc/systemd/system/flamenco-manager.service
[Unit]
Description=flamenco-manager service
After=network.target

[Service]
User=${user_name}
WorkingDirectory=/home/${user_name}/
Type=simple
Restart=always
RestartSec=30
ExecStart=/home/${user_name}/flamenco-manager

[Install]
WantedBy=multi-user.target

EOF

cat <<EOF > /home/${user_name}/flamenco-manager.yaml
# Configuration file for Flamenco.
# For an explanation of the fields, refer to flamenco-manager-example.yaml
#
# NOTE: this file will be overwritten by Flamenco Manager's web-based configuration system.
#
# This file was written on 2025-01-23 16:05:10 -05:00 by Flamenco 3.6

_meta:
  version: 3
manager_name: Flamenco
database: flamenco-manager.sqlite
database_check_period: 10m0s
listen: :8080
autodiscoverable: true
local_manager_storage_path: ./flamenco-manager-storage
shared_storage_path: /mnt/oomerfarm/flamenco
shaman:
  enabled: true
  garbageCollect:
    period: 24h0m0s
    maxAge: 744h0m0s
    extraCheckoutPaths: []
task_timeout: 10m0s
worker_timeout: 1m0s
blocklist_threshold: 3
task_fail_after_softfail_count: 3
mqtt:
  client:
    broker: ""
    clientID: flamenco
    topic_prefix: flamenco
    username: ""
    password: ""
variables:
  blender:
    values:
    - platform: linux
      value: /home/oomerfarm/blender-${blenderversion}-linux-x64/blender
    - platform: windows
      value: blender
    - platform: darwin
      value: blender
  blenderArgs:
    values:
    - platform: all
      value: -b -y
  my_storage:
    is_twoway: true
    values:
    - platform: linux
      value: /mnt/oomerfarm/flamenco
    - platform: windows
      value: O:\flamenco
    - platform: darwin
      value: /Volumes/oomerfarm/flamenco
EOF

systemctl enable --now flamenco-manager




echo -e "\n\e[32mO${farm_name} setup completed.\e[0m"
echo -e "Remaining steps:"
echo -e "Enter \e[36m\e[5m${public_ip}\e[0m\e[0m when asked for \e[32mhub\e[0m address"
echo -e "1. \e[32m[DONE]\e[0m Made secret keys on a trusted desktop/laptop"
echo -e "2. \e[32m[YOU ARE HERE]\e[0m on this computer you ran \e[36mbash bootstraphub.sh\e[0m"
echo -e "\e[36m[TODO] Get cloud Linux machines, ssh using PKI only\e[0m"
echo -e "3. Run \e[32mbash bootstrapworker.sh\e[0m"
echo -e "4. Lastly from desktop/laptop, run \e[36mbash bridgeoomerfarm.sh\e[0m to join VPN, follow instructions"
