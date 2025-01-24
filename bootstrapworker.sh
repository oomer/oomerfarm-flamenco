#!/bin/bash

# bootstrapworker.sh
# Turns this machine into a Flamenco renderfarm worker 

# Tested on AWS, Azure, Google, Oracle, Vultr, Digital Ocaan, Linode, Heztner, Server-Factory, Crunchbits
# Cannot work on unprivilegd lxc because CIFS mounts must be made by host kernel user root 0 
# https://forum.proxmox.com/threads/tutorial-unprivileged-lxcs-mount-cifs-shares.101795/

#Helper to discover distribution
source /etc/os-release
os_name=$(awk -F= '$1=="NAME" { print $2 ;}' /etc/os-release)

worker_prefix=worker
lighthouse_internet_port="42042"
lighthouse_nebula_ip="10.88.0.1"

skip="yes"
if [[ "$1" == "bypass" ]]; then
    skip="no"
fi

if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
    echo "Detected Alma/Rocky Linux" 
elif ! [ $skip == "yes" ]; then
    if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
        echo "Detected Ubuntu/Debian Linux" 
    fi
else
    echo -e "\e[31mFAIL:\e[0m Unsupported operating system $os_name"
    exit
fi

#blender
blenderversion="4.3.2"
blenderurl="https://mirrors.ocf.berkeley.edu/blender/release/Blender4.3"
blendersha256=""

#nebula
nebula_version="v1.9.5"
nebula_tar="nebula-linux-amd64.tar.gz"
nebula_url="https://github.com/slackhq/nebula/releases/download/${nebula_version}"
nebulasha256="af57ded8f3370f0486bb24011942924b361d77fa34e3478995b196a5441dbf71"
nebula_name="farm"

#flamenco
flamencoworkersha256="f1e464b224245d73d364808d9a72bba2a5967ab59a5855963f57a5e13cc6b16d"
ffmpegsha256="024e91a47bdcdaee12edbcad106c6db9543d74b791e473f1a5bbba6d5f3a5cc5"

#bella
bella_version="24.6.1"
bellasha256="3ddcff1994dd3f13a7048472ccf7fbb48b0651b1fd627d07f35cab94475c9261"

# Linux and smb user
farm_name="oomerfarm"
user_name="oomerfarm"
linux_password="oomerfarm" 

#worker_auto_shutdown=0
worker_name_default=$(hostname)

# Security best practice #1: add non-privileged/no-shell user to run daemons/systemd units/etc
# Runs deadline systemd unit
# Matches uid/gid on remote file server to sync read/write permissions
# Security best practice #2: hide passwords as best as possible 
# [ ] never embed passwords inside scripts
# [ ] input via ( hopefully ) invisible ephemeral /dev/tty
# [ ] avoid passing password in command line args which are viewable inside /proc
# [TODO] add a force option to overwrite existing credential, otherwise delete /etc/nebula/smb_credentials to reset

echo -e "\e[32mTurns this machine into a renderfarm worker\e[0m, polls \e[32mhub\e[0m for render jobs"
echo -e "\e[31mWARNING:\e[0m Security changes will break any existing services"
echo -e " - becomes VPN node with address in \e[36m10.88.0.0/16\e[0m subnet"
echo -e " - install flamenco-worker \e[37m/home/${user_name}/\e[0m"
echo -e " - \e[37mfirewall\e[0m blocks ALL non-oomerfarm ports on Alma/Rocky"
echo -e " - enforce \e[37mSELinux\e[0m for maximal security on Alma/Rocky"
echo -e "\e[32mContinue on\e[0m \e[37m$(hostname)?\e[0m"

read -p "(Enter Yes) " accept
if [ "$accept" != "Yes" ]; then
        echo -e "\n\e[31mFAIL:\e[0m Script aborted because Yes was not entered"
        exit
fi

echo -e "\e[36m\e[5moomerfarm worker id\e[0m\e[0m"
read -p "Enter number between 1-999:" worker_id
if (( $worker_id >= 1 && $worker_id <= 999 )) ; then
    worker_name=$(printf "worker%03d" $worker_id)
    echo "Worker will be called" ${worker_name}
    hostnamectl --static --transient set-hostname ${worker_name}
else
    echo -e "\e[31mFAIL:\e[0m worker id need to be between 1 and 999 inclusive"
    exit
fi

echo -e "\n\e[36m\e[5mEnter farm server ip  address\e[0m\e[0m"
read -p "Enter: x.x.x.x:" lighthouse_internet_ip
if [ -z  $lighthouse_internet_ip ]; then
    echo "Cannot continue without public ip address of farm"
    exit
fi

# abort if selinux is not enforced
# selinux provides a os level security sandbox and is very restrictive
# especially important since renderfarm jobs can included arbitrary code execution on the workers
if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
    test_selinux=$( getenforce )
    if [ "$test_selinux" == "Disabled" ] || [ "$test_selinux" == "Permissive" ];  then
        echo -e "\n\e[31mFAIL:\e[0m Selinux is disabled, edit /etc/selinux/config"
        echo "==================================================="
        echo "Change SELINUX=disabled to SELINUX=enforcing"
        echo -e "then \e[5mREBOOT\e[0m ( SELinux chcon on boot drive takes awhile)"
        echo "=================================================="
        exit
    fi
fi

echo -e "\nENTER \e[36m\e[5mpassphrase\e[0m\e[0m to decode \e[32mworker.key.encypted\e[0m that YOU \nset with \"bolstersecurity.sh\"  \n( keystrokes hidden )"
IFS= read -rs encryption_passphrase < /dev/tty
if [ -z "$encryption_passphrase" ]; then
    echo -e "\n\e[31mFAIL:\e[0m Invalid empty passphrase"
    exit
fi

echo -e "\n\e[36m\e[5mURL\e[0m\e[0m to \e[32mworker.keys.encrypted\e[0m \nthat YOU uploaded and shared on Google Drive"
read -p "Enter: " keybundle_url
if [ -z "$keybundle_url" ]; then
    echo -e "\e[31mFAIL:\e[0m URL cannot be blank"
    exit
fi

if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
    has_getenforce=$(which getenforce)
    if ! [ -z $has_getenforce ]; then
        getenforce=$(getenforce)
    fi
    firewalld_status=$(systemctl status firewalld)
    echo -e "\e[32mDiscovered $os_name\e[0m"
    dnf -y update
    dnf -y install tar
    #dnf -y install sysstat # needed for /usr/local/bin/oomerfarm_shutdown.sh
    if [ -z "$firewalld_status" ]; then
        dnf -y install firewalld
    fi
    dnf install -y mesa-vulkan-drivers mesa-libGL
    dnf install -y cifs-utils
    #dnf install -y fuse
    systemctl enable --now firewalld
elif [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
    # [ TODO ] securiyt check apparmor 
    echo -e "\e[32mDiscovered $os_name\e[0m. Support of Ubuntu is alpha quality"
    apt -y update
    #apt -y install sysstat # needed for /usr/local/bin/oomerfarm_shutdown.sh
    apt -y install cifs-utils
    apt -y install curl
    apt -y install mesa-vulkan-drivers 
    apt -y install libgl1
else
    echo "\e[31mFAIL:\e[0m Unsupported operating system $os_name"
    exit
fi

if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
    dnf -y install tar curl initscripts
    curl -O ${blenderurl}/blender-${blenderversion}-linux-x64.tar.xz   
    dnf install -y libXrender.so.1 
    dnf install -y libXrender 
    dnf install -y libXi libSM
    #dnf install -y python3-zstd
elif ! [ $skip == "yes" ]; then
    if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
        apt -y update
        apt -y install tar curl
        apt remove -y needrestart
        apt install -y -qq libxrender1 libxi6 libxkbcommon-x11-0 libsm6
        curl -O ${blenderurl}/blender-${blenderversion}-linux-x64.tar.xz   
        #snap install blender --classic
        #apt -y install python3-zstd #required for .blend decompress
    fi
fi



#systemctl enable --now sysstat
echo -e "\e[32mStarting cifs module\e[0m"
modprobe cifs

echo -e "\e[32mDownloading worker.keys.encrypted\e[0m"

# Get Nebula credentials
# ======================
if [[ "$keybundle_url" == *"https://drive.google.com/file/d"* ]]; then
    # if find content-length, then gdrive link is not restricted, this is a guess
    head=$(curl -s --head ${keybundle_url} | grep "content-length")
    if [[ "$head" == *"content-length"* ]]; then
        # Extract Google uuid 
        googlefileid=$(echo $keybundle_url | egrep -o '(\w|-){26,}')
        echo $googlefileid
        head2=$(curl -s --head -L "https://drive.google.com/uc?export=download&id=${googlefileid}" | grep "content-length")
        if [[ "$head2" == *"content-length"* ]]; then
            echo "Downloading https://drive.google.com/uc?export=download&id=${googlefileid}"
            # Hack with set curl fails under ubuntu , not sure how it helps
            set -x
            curl -L "https://drive.google.com/uc?export=download&id=$googlefileid" -o ${worker_prefix}.keys.encrypted
            set +x
        else
            echo "FAIL: ${keybundle_url} is not public, Set General Access to Anyone with Link"
            exit
        fi
    else
        echo "FAIL: ${keybundle_url} is not a valid Google Drive link"
        exit
    fi
else
    curl -L -o worker.keys.encrypted "${keybundle_url}" 
fi

# decrypt worker.keybundle.enc
while :
do
    if openssl enc -aes-256-cbc -pbkdf2 -d -in worker.keys.encrypted -out worker.tar -pass file:<( echo -n "$encryption_passphrase" ) ; then
    rm worker.keys.encrypted
        break
    else
        echo "WRONG passphrase entered earlier for worker.keys.encrypted, try again"
        echo "Enter passphrase for worker.keys.encrypted, then hit return"
        echo "==============================================================="
        IFS= read -rs $encryption_passphrase < /dev/tty
    fi 
done  

# nebula credentials
if ! test -d /etc/nebula; then
    mkdir -p /etc/nebula
fi
tar --no-same-owner --strip-components 1 -xvf worker.tar -C /etc/nebula

if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
    chown root:root /etc/nebula/*.crt
    chown root:root /etc/nebula/*.key
else
    chown root.root /etc/nebula/*.crt
    chown root.root /etc/nebula/*.key

fi
rm worker.tar

# smb_credentials
cat <<EOF > /etc/nebula/smb_credentials
username=${user_name}
password=${linux_password}
domain=WORKGROUP
EOF
chmod go-rwx /etc/nebula/smb_credentials

if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then

    # ***FIREWALL rules***
    # adopting highly restrictive rules to protect network
    echo -e "\n\e[32mTurning up Firewall security...\e[0m"
    # Wipe all services and ports except ssh and 22/tcp, may break your system
    for systemdservice in $(firewall-cmd --list-services);
    do 
        if ! [ "$systemdservice" == "ssh" ]; then
            firewall-cmd -q --remove-service ${systemdservice} --permanent
        fi
    done
    for systemdport in $(firewall-cmd --list-ports);
    do 
        if ! [ "$systemdport" == "22/tcp" ]; then
            firewall-cmd -q --remove-port ${systemdport} --permanent
        fi
    done
    firewall-cmd --quiet --zone=public --add-port=42042/udp --permanent
    firewall-cmd -q --new-zone nebula --permanent
    firewall-cmd -q --zone nebula --add-interface nebula_tun --permanent
    firewall-cmd -q --zone nebula --add-service ssh --permanent
    firewall-cmd --quiet --reload
fi

# Create user
if id "${user_name}" &>/dev/null; then
  echo "User ${user_name} exists"
else
    echo -e "\e[32mCreating user:\e[0m ${user_name}"
    groupadd -g 3000 ${user_name}
    useradd -g 3000 -u 3000 -m ${user_name}
fi
echo "${user_name}:${linux_password}" | chpasswd

# Install Nebula
echo -e "\e[32mDownloading Nebula VPN\e[0m"
curl -s -L -O ${nebula_url}/${nebula_tar}
MatchFile="$(echo "${nebulasha256} ${nebula_tar}" | sha256sum --check)"
if [ "$MatchFile" = "${nebula_tar}: OK" ] ; then
    echo -e "Extracting ${nebula_tar}"
    tar --skip-old-files -xzf ${nebula_tar}
else
    echo "FAIL: ${nebula_tar} checksum failed, incomplete download or maliciously altered on github"
    exit
fi
mv nebula /usr/local/bin/nebula
chmod +x /usr/local/bin/nebula
mv nebula-cert /usr/local/bin/
chmod +x /usr/local/bin/nebula-cert

if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
	chcon -t bin_t /usr/local/bin/nebula # SELinux security clearance
fi

rm -f ${nebula_tar}

# Install cifs dependencies
# [TODO] fix kernel mismatch errors with Alma, works fine in Rocky
#echo -e "/nInstalling cifs (smb) client dependencies"
#dnf install -y kernel-modules

# Create Nebula systemd unit 
# at runtime decides which worker key to use based on hostname
# this requires unique exact hostnames in form workerxxxx
cat <<EOF > /etc/systemd/system/nebula.service
[Unit]
Description=Nebula Launcher Service with dynamically chosen certificates 
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=35
ExecStartPre=/bin/bash -c 'sed -i "s/cert.*/cert: \/etc\/nebula\/\$HOSTNAME.crt/g" /etc/nebula/config.yml'
ExecStartPre=/bin/bash -c 'sed -i "s/key.*/key: \/etc\/nebula\/\$HOSTNAME.key/g" /etc/nebula/config.yml'
ExecStart=/usr/local/bin/nebula -config /etc/nebula/config.yml
ExecStartPost=/bin/sleep 2

[Install]
WantedBy=multi-user.target
EOF

# Nebula config file
# Security best practices #3: strict firewall rules
# =
cat <<EOF > /etc/nebula/config.yml
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/REPLACE.crt
  key: /etc/nebula/REPLACE.key
static_host_map:
  "$lighthouse_nebula_ip": ["$lighthouse_internet_ip:${lighthouse_internet_port}"]
lighthouse:
  am_lighthouse: false
  interval: 60
  hosts: 
    - "${lighthouse_nebula_ip}"
listen:
  host: 0.0.0.0
  port: 42042
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
EOF
chmod go-rwx /etc/nebula/config.yml
systemctl enable nebula.service
systemctl restart nebula.service

# Setup cifs/smb mount point in /etc/fstab ONLY if it isn't there already
# needs sophisticated grep discovery with echo
mkdir -p /mnt/oomerfarm
grep -qxF "//$lighthouse_nebula_ip/oomerfarm /mnt/oomerfarm cifs rw,noauto,x-systemd.automount,x-systemd.device-timeout=45,nobrl,uid=3000,gid=3000,file_mode=0664,credentials=/etc/nebula/smb_credentials 0 0" /etc/fstab || echo "//$lighthouse_nebula_ip/oomerfarm /mnt/oomerfarm cifs rw,noauto,x-systemd.automount,x-systemd.device-timeout=45,nobrl,uid=3000,gid=3000,file_mode=0664,credentials=/etc/nebula/smb_credentials 0 0" >> /etc/fstab

echo "Sleeping for 10 seconds for mount to finish"
if ! ( test -f /mnt/${farm_name}/installers/bella_cli-${bella_version}.tar.gz ); then
    systemctl daemon-reload
    echo "Mounting network storage"
    mount /mnt/oomerfarm
    echo "Sleeping for 10 seconds for mount to finish"
    sleep 10
fi

# Install Bella path tracer, checksum check in case network storage is compromised
echo -e "\nInstalling bella_cli"
cp /mnt/${farm_name}/installers/bella_cli-${bella_version}.tar.gz .
MatchFile="$(echo "${bellasha256} bella_cli-${bella_version}.tar.gz" | sha256sum --check)"
if [ "$MatchFile" = "bella_cli-${bella_version}.tar.gz: OK" ] ; then
    tar -xvf bella_cli-${bella_version}.tar.gz 
    chmod +x bella_cli
    mv bella_cli /usr/local/bin
    rm bella_cli-${bella_version}.tar.gz 
else
    rm bella_cli-${bella_version}.tar.gz 
    echo "\e[31mFAIL:\e[0m bella checksum failed, may be corrupted or malware"
    exit
fi

# Install blender in home dir of oomerfarm user
tar -xvf blender-${blenderversion}-linux-x64.tar.xz --directory /home/${user_name}
if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
    chown -R ${user_name}:${user_name} /home/${user_name}/blender-${blenderversion}-linux-x64
else
    chown -R ${user_name}.${user_name} /home/${user_name}/blender-${blenderversion}-linux-x64
fi

# Install flamenco-worker, checksum check in case network storage is compromised
echo -e "\nInstalling flamenco-worker"
cp /mnt/${farm_name}/installers/flamenco-worker .
cp -r /mnt/${farm_name}/installers/tools .
MatchFile="$(echo "${flamencoworkersha256} flamenco-worker" | sha256sum --check)"
if [ "$MatchFile" = "flamenco-worker: OK" ] ; then
    mv flamenco-worker /home/${user_name}
    chmod ugo+x /home/${user_name}/flamenco-worker
    if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
        chcon -t bin_t /home/${user_name}/flamenco-worker # SELinux security clearance
    fi

cat <<EOF > /etc/systemd/system/flamenco-worker.service
[Unit]
Description=flamenco-worker service
After=network.target

[Service]
User=${user_name}
WorkingDirectory=/home/${user_name}/
Type=simple
Restart=always
RestartSec=30
ExecStart=/home/${user_name}/flamenco-worker -manager http://${lighthouse_nebula_ip}:8080

[Install]
WantedBy=multi-user.target

EOF
    systemctl enable --now flamenco-worker
else
    rm flamenco-worker
    echo "\e[31mFAIL:\e[0m flamenco-worker checksum failed, may be corrupted or malware"
    exit
fi
MatchFile="$(echo "${ffmpegsha256} tools/ffmpeg-linux-amd64" | sha256sum --check)"
if [ "$MatchFile" = "tools/ffmpeg-linux-amd64: OK" ] ; then
    mv tools /home/${user_name}
    chmod ugo+x /home/${user_name}/tools/ffmpeg-linux-amd64
    if [ "$PLATFORM_ID" == "platform:el8" ] || [ "$PLATFORM_ID" == "platform:el9" ]; then
        chcon -t bin_t /home/${user_name}/tools/ffmpeg-linux-amd64 # SELinux security clearance
    fi
else
    rm tools/ffmpeg-linux-amd64
    rmdir tools
    echo "\e[31mFAIL:\e[0m ffmpeg checksum failed, may be corrupted or malware"
    exit
fi
