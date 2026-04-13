#!/bin/bash

# joinfarm.sh
# Connects user computer to oomerfarm private network. 
# Using your own keys created with becomesecure.sh or the "i_agree_this_is_unsafe" testdrive keys embedded below, this script joins a Nebula Virtual Private Network. 
# - allows mounting network directory from oomerfarm hub
# - allows render submissions and monitoring oomerfarm workers
# - NOT for hub or worker machines.
# - Tested on MacoOS Ventura, Windows 10,11
# - when run under macos or msys windows, do a .oomer install
# - when run under linux do a /etc/nebula install


lighthouse_internet_ip_default="x.x.x.x"
lighthouse_nebula_ip="10.88.0.1"
lighthouse_internet_port="42042"
# additional lighthouses must be added manually
nebula_version="v1.10.3"
nebula_url="https://github.com/slackhq/nebula/releases/download"
nebula_config_create_path=""
nebula_config_path=""
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    nebularelease="nebula-linux-amd64.tar.gz"
    nebulasha256="af57ded8f3370f0486bb24011942924b361d77fa34e3478995b196a5441dbf71"
    nebulaexe="nebula"
    nebulaexesha256="8fc30c9b1cd102c4f406d8ece66f1f4a01e4630f724afc9cc32c2ba150fd67af"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    nebularelease="nebula-darwin.zip"
    nebulasha256="75f538a2ada19487f81d67a9d87f6db02040e6aed72f50f94a756597a0d5abbd"
    nebulaexe="nebula"
    nebulaexesha256="dd337ccc03d256ce3a7bc6f3d24f16ed9396c71c02f55977506a40f50dd41acc"
elif [[ "$OSTYPE" == "msys"* ]]; then
    nebularelease="nebula-windows-amd64.zip"
    nebulasha256="7e8f26eef9394c842d4eb73610e3e63b965a93b803e366eb42c9b548bd1a70b8"
    nebulaexe="nebula.exe"
    nebulaexesha256="ecd48bc5a17275521db98d55fdffb22be2202418ba6d9f79f9fe871a94100821"
else
    echo -e "FAIL: Operating system should either be Linux, MacOS or Windows with msys"
    exit
fi

if test -f .oomer/.last_lighthouse_internet_ip; then
    lighthouse_internet_ip_default=$(cat .oomer/.last_lighthouse_internet_ip)
fi

echo -e "\nEnter farm server ip address"
echo -e "If this machine is in the cloud, use its public internet address"
echo -e "otherwise use ip address assigned by your home router"
read -p "( default: $lighthouse_internet_ip_default): " lighthouse_internet_ip
if [ -z  $lighthouse_internet_ip ]; then
    if [[ $lighthouse_internet_ip_default == "x.x.x.x" ]]; then
        echo "Can't continue without a useable ip address..."
        exit
    else
        n='([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
        if [[ $lighthouse_internet_ip_default =~ ^$n(\.$n){3} ]]; then
            lighthouse_internet_ip=$lighthouse_internet_ip_default
        else
            echo "Can't continue, $lighthouse_internet_ip_default is NOT a useable ip address..."
            exit
        fi
    fi
fi
echo $lighthouse_internet_ip > .oomer/.last_lighthouse_internet_ip
echo $lighthouse_internet_ip

# [TODO] currently linux so will require download of encrypted keybundles
# Will also need macos and windows users that do not run becomesecure.sh to get keys
if [[ "$OSTYPE" == "linux-gnu2"* ]] ; then
    echo -e "\n\e[36m\e[5mURL\e[0m\e[0m to \e[32mxxxx.keys.encrypted\e[0m"
        read -p "Enter: " keybundle_url
        if [ -z "$keybundle_url" ]; then
                echo -e "\e[31mFAIL:\e[0m URL cannot be blank"
                exit
        fi

        echo -e "\nENTER \e[36m\e[5mpassphrase\e[0m\e[0m to decode \e[32mxxxx.key.encypted\e[0m YOU set in \"keyauthority.sh\"  ( keystrokes hidden )"
        IFS= read -rs encryption_passphrase < /dev/tty
        if [ -z "$encryption_passphrase" ]; then
                echo -e "\n\e[31mFAIL:\e[0m Invalid empty passphrase"
                exit
        fi

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
        curl -L -o xxx.keys.encrypted "${keybundle_url}" 
    fi

    # decrypt worker.keybundle.enc
    # ============================
    while :
    do
        if openssl enc -aes-256-cbc -pbkdf2 -d -in xxx.keys.encrypted -out xxx.tar -pass file:<( echo -n "$encryption_passphrase" ) ; then
        rm xxx.keys.encrypted
        break
        else
        echo "WRONG passphrase entered for worker.keys.encrypted, try again"
        echo "Enter passphrase for worker.keys.encrypted, then hit return"
        echo "==============================================================="
        IFS= read -rs $encryption_passphrase < /dev/tty
        fi 
    done  

    # nebula credentials
    # ==================
    if ! test -d /etc/nebula; then
        mkdir -p /etc/nebula
    fi
    tar --strip-components 1 -xvf xxx.tar -C /etc/nebula

    nebulakeypath="$(ls /etc/nebula/*.key)"
    nebulakeyname="${nebulakeypath##*/}"
    nebulakeybase="${nebulakeyname%.*}"
    if [ -z $nebulakeybase ]; then
        exit
    fi
    chown root.root /etc/nebula/${nebulakeybase}.crt
    chown root.root /etc/nebula/${nebulakeybase}.key
    rm xxx.tar

fi

if test -d .oomer/user; then
    existing_keys="$(ls .oomer/user) skip"

    if ! [ -z existing_keys ];then
        echo -e "\nChoose user key:"
        select user_key in $existing_keys
        do
                break
        done
        if ! [[ $existing_keys == "skip" ]]; then
                nebula_config_create_path=.oomer/user/${user_key}/config.yml
        fi
    else
        echo "Invalid state"
        exit
    fi
else
    echo "No user keys found. Copy from the machine you ran bolstersecurity.sh"
    exit
fi

if [[ "$OSTYPE" == "msys"* ]]; then
        oomerfarm_path=$(cygpath -w -p $(pwd))
        ca_path="\\.oomer\\user\\${user_key}\\ca.crt"
        crt_path="\\.oomer\\user\\${user_key}\\${user_key}.crt"
        key_path="\\.oomer\\user\\${user_key}\\${user_key}.key"

else
        oomerfarm_path="."
        ca_path="/.oomer/user/${user_key}/ca.crt"
        crt_path="/.oomer/user/${user_key}/${user_key}.crt"
        key_path="/.oomer/user/${user_key}/${user_key}.key"
fi

#Create Nebula config.yml
if ! [ -z $nebula_config_create_path ]; then


#cat <<EOF > .oomer/user/${user_key}/config.yml
cat <<EOF > $nebula_config_create_path
pki:
  ca: ${oomerfarm_path}${ca_path}
  cert: ${oomerfarm_path}${crt_path}
  key: ${oomerfarm_path}${key_path}

static_host_map:
  "${lighthouse_nebula_ip}": ["${lighthouse_internet_ip}:42042"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "${lighthouse_nebula_ip}"

listen:
  host: 0.0.0.0
  port: 0

punchy:
  punch: true

relay:
  am_relay: false
  use_relays: false

tun:
  disabled: false
  dev: nebula0
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
EOF
fi
        
nebulabindir=".oomer/bin"
mkdir -p ${nebulabindir}

# Download Nebula from github once
# Ensure integrity of executables that will run as administrator
if ! ( test -f ".oomer/bin/nebula" ); then
    echo -e "\nDownloading Nebula ${nebula_version} ..."
    curl -L ${nebula_url}/${nebula_version}/${nebularelease} -o ${nebulabindir}/${nebularelease}
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        MatchFile="$(echo "${nebulasha256} ${nebulabindir}/${nebularelease}" | sha256sum --check)"

        if [ "$MatchFile" == "${nebulabindir}/${nebularelease}: OK" ] ; then
                echo -e "Extracting https://github.com/slackhq/nebula/releases/download/${nebula_version}/${nebularelease}"
                tar -xvzf ${nebulabindir}/${nebularelease} --directory ${nebulabindir}
        else
                echo "FAIL: ${nebulabindir}/${nebularelease} checksum failed, file possibly maliciously altered on github"
                exit
        fi
    elif [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "msys"* ]]; then
        MatchFile="$(echo "${nebulasha256}  ${nebulabindir}/${nebularelease}" | shasum -a 256 --check)"
        if [ "$MatchFile" == "${nebulabindir}/${nebularelease}: OK" ] ; then
                echo -e "Extracting https://github.com/slackhq/nebula/releases/download/${nebula_version}/${nebularelease}"
                unzip ${nebulabindir}/${nebularelease} -d ${nebulabindir}
        else
                echo "FAIL: ${nebulabindir}/${nebularelease} checksum failed, file possibly maliciously altered on github"
                exit
        fi
    else
        echo -e "FAIL: unpacking ${nebulabindir}/${nebularelease}"
        exit
    fi
    chmod +x ${nebulabindir}/nebula-cert
    chmod +x ${nebulabindir}/nebula
fi

# This section double checks final hash on executable
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    MatchFile="$(echo "${nebulaexesha256}  ${nebulabindir}/${nebulaexe}" | sha256sum --check)"
    if ! [ "$MatchFile" == "${nebulabindir}/${nebulaexe}: OK" ] ; then
            echo -e "\n${nebulabindir}/${nebulaexe} has been corrupted or maliciously tampered with"
            exit
    fi
elif [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "msys"* ]]; then
    MatchFile="$(echo "${nebulaexesha256}  ${nebulabindir}/${nebulaexe}" | shasum -a 256 --check)"
    if ! [ "$MatchFile" == "${nebulabindir}/${nebulaexe}: OK" ] ; then
            echo -e "\n${nebulabindir}/${nebulaexe} has been corrupted or maliciously tampered with"
            exit
    fi
else
    exit
fi


if [[ "$OSTYPE" == "darwin"* ]] ; then
    echo -e "\n"
    echo -e "Do not run this script if it did not come from  https://github.com/oomer"
    echo "Current user, must be admin. Enter password to elevate the permissions of this script"
    sudo ${nebulabindir}/nebula -config .oomer/user/${user_key}/config.yml
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo ${nebulabindir}/nebula -config .oomer/user/${user_key}/config.yml
elif [[ "$OSTYPE" == "msys"* ]]; then
    echo $(pwd)
cat <<EOF > ~/Desktop/joinfarm.bat
${oomerfarm_path}\\.oomer\\bin\\nebula.exe -config ${oomerfarm_path}\\.oomer\\user\\${user_key}\\config.yml
EOF
    echo -e "On \e[32mdesktop\e[0m, right click \e[37m\e[5mjoinfarm.bat\e[0m\e[0m, Run as adminstrator"
    echo -e "SECURITY WARNING: Do not run this script before comparing it with the canonical version at https://github.com/oomer/oomer-flamenco"
fi
