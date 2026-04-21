#!/bin/bash

# bootstrapworker.sh
# Turns this machine into a Flamenco renderfarm worker 

# Tested on AWS, Azure, Google, Oracle, Vultr, Digital Ocaan, Linode, Heztner, Server-Factory, Crunchbits
# Shared storage: SMB via rclone FUSE (userspace) → /mnt/oomerfarm — no kernel CIFS/NFS mount.
# Unprivileged LXC: enable FUSE (e.g. Proxmox features: fuse=1). Hub SMB share name = oomerfarm.

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

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    echo "Detected Alma/Rocky Linux" 
elif ! [ $skip == "yes" ]; then
    if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
        echo "Detected Ubuntu/Debian Linux" 
    fi
else
    echo -e "\e[31mFAIL:\e[0m Unsupported operating system $os_name"
    exit
fi

# True if running inside an LXC guest (host SELinux applies; guest enforcing check is often wrong).
is_lxc() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        case "$(systemd-detect-virt 2>/dev/null || true)" in
            lxc|lxc-libvirt) return 0 ;;
        esac
    fi
    if tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -q '^container=lxc$'; then
        return 0
    fi
    if grep -qE '(^|/)lxc(/|\.)|lxc\.payload' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    return 1
}

### Ensure max security
# disallow ssh password authentication
sed -i -E 's/#?PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config 

#blender
blenderversion="5.1.0"
blenderurl="https://mirrors.ocf.berkeley.edu/blender/release/Blender5.1"
blendersha256="7f2475990613c8d4c7ac5697803fcf40d09541c1fd8c23936f4b07a169a920c7"

#nebula
nebula_version="v1.10.3"
nebula_tar="nebula-linux-amd64.tar.gz"
nebula_url="https://github.com/slackhq/nebula/releases/download/${nebula_version}"
nebulasha256="99ac335caeb69d02a6b6b00a3d4b5d0a36ec3971df480a1cc50e6db378342955"
nebula_name="farm"

#flamenco
flamencoworkersha256="0fa32f7d3c83db2f3f43d09b8c8148f6a50307fb6269290b0bf3be20ccd80d07"
ffmpegsha256="e7e7fb30477f717e6f55f9180a70386c62677ef8a4d4d1a5d948f4098aa3eb99"

#bella
bella_version="25.3.0"
bellasha256="6b94968d4ae039c0f1c34980e1285748fb523582fd6e11a327ea24837dc64d1c"

# Linux user (uid/gid 3000 should match hub export ownership)
farm_name="oomerfarm"
user_name="oomerfarm"
linux_password="oomerfarm"
# rclone remote name (see /etc/rclone/rclone.conf and rclone-farm.service)
rclone_remote="farmshare"

#worker_auto_shutdown=0
worker_name_default=$(hostname)

# Security best practice #1: add non-privileged/no-shell user to run daemons/systemd units/etc
# Runs deadline systemd unit
# Matches uid/gid on remote file server to sync read/write permissions
# Security best practice #2: hide passwords as best as possible 
# [ ] never embed passwords inside scripts
# [ ] input via ( hopefully ) invisible ephemeral /dev/tty
# [ ] avoid passing password in command line args which are viewable inside /proc

echo -e "\e[32mTurns this machine into a renderfarm worker\e[0m, polls \e[32mhub\e[0m for render jobs"
echo -e "\e[31mWARNING:\e[0m Security changes will break any existing services"
echo -e " - becomes VPN node with address in \e[36m10.88.0.0/16\e[0m subnet"
echo -e " - install flamenco-worker \e[37m/opt/${farm_name}/\e[0m"
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
# skip on LXC: policy/enforcement is usually host-managed; guest getenforce is not the same as bare metal
if ! is_lxc; then
    if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
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

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    test_selinux=$( getenforce )
    has_getenforce=$(which getenforce)
    if ! [ -z $has_getenforce ]; then
        getenforce=$(getenforce)
    fi
    firewalld_status=$(systemctl status firewalld)
    echo -e "\e[32mDiscovered $os_name\e[0m"
    dnf -y update
    dnf -y install tar openssl xz
    #dnf -y install sysstat # needed for /usr/local/bin/oomerfarm_shutdown.sh
    if [ -z "$firewalld_status" ]; then
        dnf -y install firewalld
    fi
    dnf install -y mesa-vulkan-drivers mesa-libGL
    dnf install libXfixes libXrender mesa-libGL libXxf86vm libxkbcommon libSM libICE libXi -y
    dnf install -y fuse3
    dnf install -y epel-release 2>/dev/null || true
    dnf install -y rclone 2>/dev/null || true
    if ! command -v rclone >/dev/null 2>&1; then
        echo -e "\e[33mInstalling rclone from rclone.org (not in repos)...\e[0m"
        dnf install -y unzip
        curl -sSL "https://downloads.rclone.org/rclone-current-linux-amd64.zip" -o /tmp/rclone.zip
        unzip -qo /tmp/rclone.zip -d /tmp
        cp /tmp/rclone-*-linux-amd64/rclone /usr/local/bin/rclone
        chmod 755 /usr/local/bin/rclone
        rm -rf /tmp/rclone.zip /tmp/rclone-*-linux-amd64
        if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
            chcon -t bin_t /usr/local/bin/rclone 2>/dev/null || true
        fi
    fi
    systemctl enable --now firewalld
elif [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
    # [ TODO ] securiyt check apparmor 
    echo -e "\e[32mDiscovered $os_name\e[0m. Support of Ubuntu is alpha quality"
    apt -y update
    #apt -y install sysstat # needed for /usr/local/bin/oomerfarm_shutdown.sh
    apt -y install fuse3 rclone
    apt -y install curl
    apt -y install mesa-vulkan-drivers 
    apt -y install libgl1
else
    echo "\e[31mFAIL:\e[0m Unsupported operating system $os_name"
    exit
fi

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    dnf -y install tar curl initscripts
    curl -O ${blenderurl}/blender-${blenderversion}-linux-x64.tar.xz   
    dnf install -y libXrender.so.1 
    dnf install -y libXrender 
    dnf install -y libXi libSM libxkbcommon
    #dnf install -y python3-zstd
elif ! [ $skip == "yes" ]; then
    if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
        apt -y update
        apt -y install tar curl
        apt remove -y needrestart
        apt install -y -qq libxrender1 libxi6 libxkbcommon-x11-0 libsm6 libgl1-mesa-dri libegl1
        curl -O ${blenderurl}/blender-${blenderversion}-linux-x64.tar.xz   
        #snap install blender --classic
        #apt -y install python3-zstd #required for .blend decompress
    fi
fi

#systemctl enable --now sysstat

echo -e "\e[32mDownloading worker.keys.encrypted\e[0m"

# Get Nebula credentials
# ======================
if [[ "$keybundle_url" == *"https://drive.google.com/file/d"* ]]; then
    # if find content-length, then gdrive link is not restricted, this is a guess
    head=$(curl -s --head ${keybundle_url} | grep "content-length")
    if [[ "$head" == *"content-length"* ]]; then
        # Extract Google uuid 
        googlefileid=$(echo $keybundle_url | grep -E -o '(\w|-){26,}')
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

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    chown root:root /etc/nebula/*.crt
    chown root:root /etc/nebula/*.key
else
    chown root.root /etc/nebula/*.crt
    chown root.root /etc/nebula/*.key

fi
rm worker.tar
rm -f /etc/nebula/smb_credentials

# FUSE: allow rclone --allow-other so uid 3000 (flamenco) sees the mount
if [ -f /etc/fuse.conf ] && ! grep -q '^user_allow_other' /etc/fuse.conf; then
    sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf || true
fi

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then

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
mkdir -p /opt/${farm_name}/bin
chown -R ${user_name}:${user_name} /opt/${farm_name}

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
mv nebula /opt/${farm_name}/bin/nebula
chmod +x /opt/${farm_name}/bin/nebula
mv nebula-cert /opt/${farm_name}/bin/
chmod +x /opt/${farm_name}/bin/nebula-cert

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
	chcon -t bin_t /opt/${farm_name}/bin/nebula # SELinux security clearance
fi

rm -f ${nebula_tar}

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
ExecStart=/opt/${farm_name}/bin/nebula -config /etc/nebula/config.yml
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

# Strip kernel NFS / CIFS fstab lines (we use rclone FUSE only)
sed -i '\| /mnt/'"${farm_name}"' nfs |d' /etc/fstab 2>/dev/null || true
sed -i '\|^//'"${lighthouse_nebula_ip}"'/'"${farm_name}"' /mnt/'"${farm_name}"' cifs|d' /etc/fstab 2>/dev/null || true

mkdir -p /mnt/${farm_name}

# rclone SMB config (same hub/share as kernel CIFS used: //10.88.0.1/oomerfarm)
mkdir -p /etc/rclone
chmod 700 /etc/rclone
export RCLONE_CONFIG=/etc/rclone/rclone.conf
rclone config delete "${rclone_remote}" 2>/dev/null || true
rclone config create "${rclone_remote}" smb host "${lighthouse_nebula_ip}" user "${user_name}" pass "${linux_password}" domain WORKGROUP --non-interactive 2>/dev/null || \
rclone config create "${rclone_remote}" smb host "${lighthouse_nebula_ip}" user "${user_name}" pass "${linux_password}" domain WORKGROUP
chmod 600 /etc/rclone/rclone.conf

RCLONE_BIN="$(command -v rclone)"
FUSERMOUNT_BIN="$(command -v fusermount3 2>/dev/null || command -v fusermount 2>/dev/null || echo fusermount3)"

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    setsebool -P virt_use_fuse 1 2>/dev/null || true
fi

cat <<EOF > /etc/systemd/system/rclone-farm.service
[Unit]
Description=rclone FUSE mount hub SMB at /mnt/${farm_name}
After=network-online.target nebula.service
Wants=network-online.target nebula.service

[Service]
Type=simple
ExecStart=${RCLONE_BIN} mount ${rclone_remote}:${farm_name} /mnt/${farm_name} --config /etc/rclone/rclone.conf --allow-other --vfs-cache-mode writes --dir-cache-time 5s --poll-interval 1m --log-level NOTICE
ExecStop=${FUSERMOUNT_BIN} -zu /mnt/${farm_name}
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rclone-farm.service
systemctl restart rclone-farm.service

# Must match the tarball name under installers/ on the hub (same as cp below).
bella_installer="bella_cli-${bella_version}-linux.tar.gz"
echo "Waiting for rclone mount of //${lighthouse_nebula_ip}/${farm_name} ..."
for _i in $(seq 1 30); do
    if test -f "/mnt/${farm_name}/installers/${bella_installer}"; then
        break
    fi
    sleep 2
done
if ! test -f "/mnt/${farm_name}/installers/${bella_installer}"; then
    echo -e "\e[31mFAIL:\e[0m rclone mount did not expose hub installers path (expected installers/${bella_installer})."
    echo "Check: systemctl status rclone-farm; journalctl -u rclone-farm -b; rclone ls ${rclone_remote}:${farm_name}/installers --config /etc/rclone/rclone.conf"
    exit 1
fi

# Install Bella path tracer, checksum check in case network storage is compromised
echo -e "\nInstalling bella_cli"
cp "/mnt/${farm_name}/installers/${bella_installer}" .
MatchFile="$(echo "${bellasha256} ${bella_installer}" | sha256sum --check)"
if [ "$MatchFile" = "${bella_installer}: OK" ] ; then
    tar -xvf "${bella_installer}"
    chmod +x bella_cli/bella_cli
    mv bella_cli/bella_cli /opt/${farm_name}/bin
    mv bella_cli/libdl_usd_ms.so /opt/${farm_name}/bin
    mv bella_cli/usd /opt/${farm_name}/bin

    rm -f "${bella_installer}"
else
    rm -f "${bella_installer}"
    echo "\e[31mFAIL:\e[0m bella checksum failed, may be corrupted or malware"
    exit
fi

# Install blender in /opt/${farm_name}
tar -xvf blender-${blenderversion}-linux-x64.tar.xz --directory /opt/${farm_name}/bin
if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    chown -R ${user_name}:${user_name} /opt/${farm_name}/blender-${blenderversion}-linux-x64
else
    chown -R ${user_name}.${user_name} /opt/${farm_name}/blender-${blenderversion}-linux-x64
fi

# Install flamenco-worker, checksum check in case network storage is compromised
echo -e "\nInstalling flamenco-worker"
cp /mnt/${farm_name}/installers/flamenco-worker .
cp -r /mnt/${farm_name}/installers/tools .
MatchFile="$(echo "${flamencoworkersha256} flamenco-worker" | sha256sum --check)"
if [ "$MatchFile" = "flamenco-worker: OK" ] ; then
    mv flamenco-worker /opt/${farm_name}
    chmod ugo+x /opt/${farm_name}/flamenco-worker
    if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
        chcon -t bin_t /opt/${farm_name}/flamenco-worker # SELinux security clearance
    fi

cat <<EOF > /etc/systemd/system/flamenco-worker.service
[Unit]
Description=flamenco-worker service
After=network.target rclone-farm.service
Wants=rclone-farm.service

[Service]
User=${user_name}
Environment=FLAMENCO_MANAGER_URL=http://10.88.0.1:8080
WorkingDirectory=/opt/${farm_name}/
Type=simple
Restart=always
RestartSec=30
ExecStart=/opt/${farm_name}/flamenco-worker -manager http://${lighthouse_nebula_ip}:8080

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
    mv tools/ffmpeg-linux-amd64 /opt/${farm_name}/bin
    chmod ugo+x /opt/${farm_name}/bin/ffmpeg-linux-amd64
    if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
        chcon -t bin_t /opt/${farm_name}/bin/ffmpeg-linux-amd64 # SELinux security clearance
    fi
    rmdir tools
else
    rm tools/ffmpeg-linux-amd64
    rmdir tools
    echo "\e[31mFAIL:\e[0m ffmpeg checksum failed, may be corrupted or malware"
    exit
fi
