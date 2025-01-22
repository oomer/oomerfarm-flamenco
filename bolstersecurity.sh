#!/bin/bash
# bolstersecurity.sh 
# Manage security keys of Nebula private network to secure cloud based renderfarm
# - creates repository of keys in same dir as this script under .oomer
# - cross-platform bash script, runs natively on MacOS/Linux requires git-bash on Windows
# 1. run once to generate keys for 1 farm server, 100 workers, 1 user
# 2. run again to 
nebula_version="v1.9.5"
octet0=10
octet1=88
mask=16

mkdir -p .oomer/keyauthority # Certificate Authority
mkdir -p .oomer/keysencrypted # Encrypted tar.gz's for internet deployment
mkdir -p .oomer/bin # Nebula binaries
echo -e "bolstersecurity.sh manages keys to secure your oomerfarm private network"
echo -e "========================================================================"
echo -e "\nPrivate Key Infrastructure (PKI), the internet's foundation for secure communications"
echo -e "is used for VPNs, https://, ssh"
echo -e "\n- This script downloads the open source Nebula VPN and walks you through signing all the keys"
echo -e "needed for a 100 node renderfarm , 1 farm server and 1 user"

farm_name="farm"

os_name=$(awk -F= '$1=="NAME" { print $2 ;}' /etc/os-release)

if [ "$os_name" == "\"AlmaLinux\"" ] || [ "$os_name" == "\"Rocky Linux\"" ]; then
    dnf -y install tar curl 
elif ! [ $skip == "yes" ]; then
    if [ "$os_name" == "\"Ubuntu\"" ] || [ "$os_name" == "\"Debian GNU/Linux\"" ]; then
        apt -y update
        apt -y install tar curl
    fi
else
    echo "\e[31mFAIL:\e[0m Unsupported operating system $os_name"
    exit
fi


# Download Nebula from github once
# ================================
nebula_url="https://github.com/slackhq/nebula/releases/download/"
if ! ( test -f ".oomer/bin/nebula-cert" ); then
	echo -e "\nDownloading Nebula ${nebula_version} ..."
	if [[ "$OSTYPE" == "linux-gnu"* ]]; then
		nebularelease="nebula-linux-amd64.tar.gz"
		nebulasha256="af57ded8f3370f0486bb24011942924b361d77fa34e3478995b196a5441dbf71"
	elif [[ "$OSTYPE" == "darwin"* ]]; then
		nebularelease="nebula-darwin.zip"
		nebulasha256="891584c4288e031b0787cfd5ac1da4565caf1627bd934d94b696a340ad92f0d7"
	elif [[ "$OSTYPE" == "msys"* ]]; then
		nebularelease="nebula-windows-amd64.zip"
		nebulasha256="5a42e4600e8a47db2b103c607d95509c7ae403f56e2952d05089f492e53bcebb"
	else 
		echo -e "FAIL: Operating system should either be Linux, MacOS or Windows with msys"
		exit
	fi
	echo -e "Downloading Nebula vpn ${nebula_url}/${nebula_version}/${nebularelease}"
	curl -L ${nebula_url}/${nebula_version}/${nebularelease} -o .oomer/bin/${nebularelease}
	if [[ "$OSTYPE" == "linux-gnu"* ]]; then
		MatchFile="$(echo "${nebulasha256} .oomer/bin/${nebularelease}" | sha256sum --check)"
	elif [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "msys"* ]]; then
		MatchFile="$(echo "${nebulasha256}  .oomer/bin/${nebularelease}" | shasum -a 256 --check)"
	else
		echo -e "FAIL: OS type not recognized"
		exit
	fi

	if [ "$MatchFile" == ".oomer/bin/${nebularelease}: OK" ] ; then
		echo -e "Extracting ${nebula_version}/${nebularelease}"
		if [[ "$OSTYPE" == "linux-gnu"* ]]; then
			tar -xvzf .oomer/bin/${nebularelease} --directory .oomer/bin
		elif [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "msys"* ]]; then
			unzip .oomer/bin/${nebularelease} -d .oomer/bin
		fi
	else
		echo "FAIL: .oomer/bin/${nebularelease} checksum failed, file possibly maliciously altered on github or download was corrupted"
		exit
	fi
	chmod +x .oomer/bin/nebula-cert
	chmod +x .oomer/bin/nebula
	rm .oomer/bin/${nebularelease}
fi

# Create certificate authority
if ! ( test -f ".oomer/keyauthority/ca.crt" ); then
	ca_name_default="oomerfarm"
	ca_name=$ca_name_default
	ca_duration_default="43800h0m0s"
	if [ $0 == "advanced" ]; then
		echo -e "\nExpiration date for Nebula VPN"
		read -p "(default  5 years , ${ca_duration_default}) : " ca_duration
		if [ -z $ca_duration ]; then
			ca_duration=$ca_duration_default
		fi
	else
		ca_duration=$ca_duration_default
	fi
 	.oomer/bin/nebula-cert ca -name $ca_name -duration $ca_duration -out-crt .oomer/keyauthority/ca.crt -out-key .oomer/keyauthority/ca.key
fi

# Always ask for encryption passphrase, never store
while :
do
	echo -e "\nEnter passphrase to encrypt keys ...( typing is ghosted )"
	read -rs encryption_passphrase
	if [ -z "$encryption_passphrase" ]; then
	    echo "FAIL: invalid empty passphrase"
	    exit
	fi
	echo "Verifying: re-enter passphrase"
	read -rs encryption_passphrase_check 
	    if [[ "$encryption_passphrase" == "$encryption_passphrase_check" ]]; then
		break
	    fi
	echo "Passphrase verification failed! Try again."
done
echo

# Key making loop
while :
do
	# farm is macro to generate 1 Nebula lighthouse, 100 Nebula nodes , 1 Nebula node with higher access security
	if test -f .oomer/lighthouse/farm/farm.key; then # farm single invocation ( rmdir .oomer to reset )
		echo -e "\nAdd more keys:"
		select new_key_type in user worker lighthouse quit
		do
			break
		done
	else
		echo -e "\nCreating 100 worker keys, 1 server key, 1 user key...( run this script if you need more keys )"
		new_key_type="farm"
	fi

	# Nebula lighthouses are computers that have a internet accessible udp port providing network discovery over the internet
	# For oomerfarm we want a server/lighthosue combo to offer 
	# servers for http and smb and ssh alongside the lighthousing ( and optionally relay )
	# At least one lighthouse per Nebula network is required so NAT'ed nodes can find each other
	# Multiple lighthouses can be added for redundancy
	if [[ $new_key_type == "farm" ]] ||  [[ $new_key_type == "lighthouse" ]]; then
		# get next ip address sequentially
		lighthouse_prefix="lighthouse"
		if ! test -f .oomer/.lighthouse_ips; then
			octet2=0
			octet3=1
			if [[ $new_key_type == "farm" ]]; then
				lighthouse_name_default=${farm_name}
			else
				lighthouse_name_default="lighthouse1" #first
			fi
		else
			# read text list of used ips to determine next free private ip address
			unset -v lighthouse_ip
			while IFS= read -r; do
				lighthouse_ip+=("$REPLY")
			done <.oomer/.lighthouse_ips
			[[ $REPLY ]] && lighthouse_ip+=("$REPLY")
			last_used=${lighthouse_ip[$(( ${#lighthouse_ip[@]} - 1)) ]}
			lighthouse_count=$(( ${#lighthouse_ip[@]} + 1))
			lighthouse_name_default="${lighthouse_prefix}${lighthouse_count}"
			IFS='.' read -ra octet <<< "$last_used"
			octet0=${octet[0]}
			octet1=${octet[1]}
			octet2=${octet[2]}
			octet3=${octet[3]}
			((octet3++))
			if [[ octet3 -eq 255 ]]; then
				echo "only 254 lighthouses are supported 10.88.0.1-10.88.0.254"
				exit
			fi

		fi

		if [[ $new_key_type == "farm" ]]; then
			lighthouse_name=$lighthouse_name_default
		else
			while :
			do
				echo -e "\nEnter lighthouse name ..."
				read -p "default ( $lighthouse_name_default ): " lighthouse_name
				if [ -z $lighthouse_name ]; then
					lighthouse_name=$lighthouse_name_default
				fi
				if [ -z $(grep $lighthouse_name .oomer/.lighthouse_names) ]; then
					break	
				else
					echo "${lighthouse_name} name already exists, try again"
				fi
			done
		fi

		lighthouse_nebula_ip="${octet0}.${octet1}.${octet2}.${octet3}"

		mkdir -p ".oomer/lighthouse/${lighthouse_name}"

		echo .oomer/bin/nebula-cert sign -name ${lighthouse_name} -ip "${octet0}.${octet1}.${octet2}.${octet3}/${mask}" -groups "farm,lighthouse" -out-crt ".oomer/lighthouse/${lighthouse_name}/${lighthouse_name}.crt" -out-key ".oomer/lighthouse/${lighthouse_name}/${lighthouse_name}.key" -ca-crt ".oomer/keyauthority/ca.crt" -ca-key ".oomer/keyauthority/ca.key"
		.oomer/bin/nebula-cert sign -name ${lighthouse_name} -ip "${octet0}.${octet1}.${octet2}.${octet3}/${mask}" -groups "farm,lighthouse" -out-crt ".oomer/lighthouse/${lighthouse_name}/${lighthouse_name}.crt" -out-key ".oomer/lighthouse/${lighthouse_name}/${lighthouse_name}.key" -ca-crt ".oomer/keyauthority/ca.crt" -ca-key ".oomer/keyauthority/ca.key"
		cp .oomer/keyauthority/ca.crt .oomer/lighthouse/${lighthouse_name}
		echo "${octet0}.${octet1}.${octet2}.${octet3}" >> .oomer/.lighthouse_ips
		echo "${octet0}.${octet1}.${octet2}.${octet3}" > .oomer/lighthouse/${lighthouse_name}/.nebula_ip

		origdir=$(pwd)
		if test -d .oomer/lighthouse; then
			cd .oomer/lighthouse
			find "${lighthouse_name}" -type f -exec tar -rvf temp.tar {} \;
			if [[ ${new_key_type} == "oomerfarm" ]];then
				echo "${octet0}.${octet1}.${octet2}.${octet3}" > $origdir/.oomer/.oomerfarm_lighthouse_ip
				# [TODO] support more then one lighthouse
				keybundle_name="hub"
			else
				keybundle_name=${lighthouse_name}
			fi
			openssl enc -aes-256-cbc -salt -pbkdf2 -in "temp.tar" -out $origdir/.oomer/keysencrypted/${keybundle_name}.keys.encrypted -pass stdin <<< "$encryption_passphrase"
			rm temp.tar
			cd $origdir
		else
			echo "FAIL: Something is wrong with .oomer/lighthouse"
			exit
		fi

	fi

	# [IGNORED] future use
	# servers are linux machines with roles like file server, database server
	# the nebula firewall allows 22/tcp access for ssh
	# all other firewall rules must be manually added afterwords
	# command line params like --oomerfarm will add specific firewall rules for smb, mongod and license forwarder
	# the keys are put into this directory structure
	# the 10.87.1.x folders keep track of used ip addresses
	# below this directory will human readable folder name of the server
	# subsequently this folder will be tarred and openssl encrypted to allow sharing
	# 
	# max range 1-254
	# .oomer
	# 	|
	#	->servers
	#		|
	#		->10.87.1.1
	#			|
	#			->server1
	# technically, server.crt and server.key could be the constant names
	# but this gets confusing to try to debug, therefore a user friendly name is useful
	# since ip address needs to be unique and name needs to be unique

	if [[ ${new_key_type} == "server" ]]; then
		if ! test -f .oomer/.server_ips; then
			octet2=1
			octet3=1
			server_name_default="server1"
		else
			# read text list of used ips
			unset -v server_ip
			while IFS= read -r; do
				server_ip+=("$REPLY")
			done <.oomer/.server_ips
			[[ $REPLY ]] && server_ip+=("$REPLY")
			last_used=${server_ip[$(( ${#server_ip[@]} - 1)) ]}
			server_count=$(( ${#server_ip[@]} + 1))
			server_name_default="server${server_count}"
			IFS='.' read -ra octet <<< "$last_used"
			octet0=${octet[0]}
			octet1=${octet[1]}
			octet2=${octet[2]}
			octet3=${octet[3]}
			((octet3++))
			if [[ octet3 -eq 255 ]]; then
				echo "only 254 servers are supported 10.87.1.1-10.87.1.254"
				echo "you are on your own in editing this script"
				exit
			fi

		fi

		# only server and people can be renamed, making the .oomer credentials to be human readable
		# lighthouses will be hardcode lighthouse1...
		while :
		do
			echo -e "\nEnter server name ..."
			read -p "default ( $server_name_default ): " server_name
			if [ -z $server_name ]; then
				server_name=$server_name_default
			fi
			if [ -z $(grep $server_name .oomer/.server_names) ]; then
				break	
			else
				echo "${server_name} name already exists, try again"
			fi
		done

		if test -f ".oomer/server/${server_name}/${server_name}.key"; then
			echo -e ".oomer/server/${server_name}${server_name}.key exists, skipping"
		else
			mkdir -p  ".oomer/server/${server_name}"
			echo .oomer/bin/nebula-cert sign -name ${server_name} -ip ${octet0}.${octet1}.${octet2}.${octet3}/${mask} -groups "farm,server" -out-crt ".oomer/server/${server_name}/${server_name}.crt" -out-key ".oomer/server/${server_name}/${server_name}.key" -ca-crt ".oomer/keyauthority/ca.crt" -ca-key ".oomer/keyauthority/ca.key"
			.oomer/bin/nebula-cert sign -name ${server_name} -ip ${octet0}.${octet1}.${octet2}.${octet3}/${mask} -groups "farm,server" -out-crt ".oomer/server/${server_name}/${server_name}.crt" -out-key ".oomer/server/${server_name}/${server_name}.key" -ca-crt ".oomer/keyauthority/ca.crt" -ca-key ".oomer/keyauthority/ca.key"
			cp .oomer/keyauthority/ca.crt .oomer/server/${server_name}
			echo ${octet0}.${octet1}.${octet2}.${octet3} > .oomer/server/${server_name}/.nebula_ip

			# Need to cd to get proper relative paths for tar
			origdir=$(pwd)
			# stash used ips
			echo "${octet0}.${octet1}.${octet2}.${octet3}" >> .oomer/.server_ips
			echo "$server_name" >> .oomer/.server_names
			if test -d .oomer/server; then
				cd .oomer/server
				find "${server_name}" -type f -exec tar -rvf temp.tar {} \;
				echo openssl enc -aes-256-cbc -salt -pbkdf2 -in "temp.tar" -out $origdir/.oomer/keysencrypted/${server_name}.keys.encrypted -pass stdin <<< "$encryption_passphrase"
				openssl enc -aes-256-cbc -salt -pbkdf2 -in "temp.tar" -out $origdir/.oomer/keysencrypted/${server_name}.keys.encrypted -pass stdin <<< "$encryption_passphrase"
				rm temp.tar
				cd $origdir
			else
				echo "FAIL: Something is wrong with .oomer/server"
			fi
		fi

	fi


	# worker keys are a novel store of credentials specifically for this renderfarm
	# normal render nodes would use automation scripts to spin up a cloud instance and assign keys
	# while this provides the best security, it adds complexity to spinning up resources
	# requiring tracking deployed keys using complex tools like Ansible or Puppet
	# My implementation of worker keys asserts that they are secure as a group, not as an individual node
	# if one worker is compromised, then the entire group should be revoked
	# [TODO] Add method to revoke all previously generated workers
	# this approach means that unlike server, lighthouse, and personal nebula nodes, workers do not
	# carry a unique private key, rather they carry ALL worker keys 
	# nebula's systemd unit dynamically chooses a private key based on $HOSTNAME
	# this simplification allows the end-user to create 2 undesirable situations
	# 1. Naming instance wrongname0001 with no corresponding /etc/nebula/wrongname0001.key
	# 2. Naming 2 instances with the same name worker0001 and worker0001, leading to nebula failure
	# Don't do this
	# The benefits, on Google Cloud Platform for instance, a canonical worker with all the render software 
	# could be stashed and then clones made of it with the GCP web interface or via the glcloud cli
	# and just requiring a simple rename of the host manually ofr programmatically
	# [NOTE] ideally you would scrub the keys off the workers when you are finished with them
	# Since this may not be possible , best practices for deployment is to treat these keys as
	# disposable like a password and the generate new ones every few months

	if [[ ${new_key_type} == "worker" ]] || [[ ${new_key_type} == "farm" ]] ; then
		workernum_default=100
		workernum=$workernum_default
		if ! [[ ${new_key_type} == "farm" ]] ; then
			echo -e "/nAdd additional workers ..."
			read -p "default ( $workernum_default ): " workernum
			if [ -z $workernum ]; then
				workernum=$workernum_default
			fi
		fi

		worker_prefix="worker"

		if ! test -f .oomer/.worker_ips; then
			octet2=99
			octet3=1
		else
			# read text list of used ips
			unset -v worker_ip
			while IFS= read -r; do
				worker_ip+=("$REPLY")
			done <.oomer/.worker_ips
			[[ $REPLY ]] && worker_ip+=("$REPLY")
			last_used=${worker_ip[$(( ${#worker_ip[@]} - 1)) ]}
			echo "last used$last_used"
			worker_last_count=$(( ${#worker_ip[@]} ))
			echo "worker_last_count$worker_last_count"
			IFS='.' read -ra octet <<< "$last_used"
			octet0=${octet[0]}
			octet1=${octet[1]}
			octet2=${octet[2]}
			octet3=${octet[3]}
			echo $octet3
			((octet3++))
			echo $octet3
			if [[ octet3 -eq 255 ]]; then
				((octet2++))
				octet3=1
				if [[ octet2 -eq 255 ]]; then
					echo "only a subnet mask of 16 is supported"
					echo "you have exceed number of workers supported"
					echo "you are on your own in editing this script"
					exit
				fi
			fi

		fi

		mkdir -p .oomer/worker

		# Create multiple worker keys
		# ===========================
		for ((count = 1 ; count <= "${workernum}" ; count++)); do
			worker_count=$(($worker_last_count + $count))
			worker_padded=$(printf %03d $worker_count)
			.oomer/bin/nebula-cert sign -name "${worker_prefix}${worker_padded}" -ip "${octet0}.${octet1}.${octet2}.${octet3}/${mask}" -groups "farm" -out-crt ".oomer/worker/${worker_prefix}${worker_padded}.crt" -out-key ".oomer/worker/${worker_prefix}${worker_padded}.key" -ca-crt ".oomer/keyauthority/ca.crt" -ca-key ".oomer/keyauthority/ca.key" 
			echo "${octet0}.${octet1}.${octet2}.${octet3}" >> .oomer/.worker_ips
			
			# get next unique worker nebula ip
			((octet3++))
			if [[ octet3 -eq 255 ]]; then
				((octet2++))
				octet3=1
				if [[ octet2 -eq 255 ]]; then
					((octet1++))
					## WARNING you are probably making too many certificates if you get here
					if [[ octet1 -eq 255 ]]; then
						((octet0++))
						if [[ octet0 -eq 255 ]]; then
							break
						fi
					fi
				fi
			fi
		done

		cp .oomer/keyauthority/ca.crt ".oomer/worker"
		origdir=$(pwd)
		if test -d .oomer/worker; then
			cd .oomer/worker
			find "." -type f -exec tar -rvf temp.tar {} \;
			openssl enc -aes-256-cbc -salt -pbkdf2 -in "temp.tar" -out ${origdir}/.oomer/keysencrypted/worker.keys.encrypted -pass stdin <<< "$encryption_passphrase" 
			rm temp.tar
			cd $origdir
		fi
	fi


	# user keys are different than servers, lighthouse and workers which are semi-autonomous linux members of the vpn
	# user keys are used on desktop/laptop computers

	if [[ ${new_key_type} == "user" ]] || [[ ${new_key_type} == "farm" ]]; then
		# [TODO] standard users and admins
		# worker and server nodes cannot ssh to user nodes

		if ! test -f .oomer/.user_ips; then
			octet2=10
			octet3=1
			user_name_default="user1"
		else
			# read text list of used ips
			unset -v user_ip
			while IFS= read -r; do
				user_ip+=("$REPLY")
			done <.oomer/.user_ips
			[[ $REPLY ]] && user_ip+=("$REPLY")
			last_used=${user_ip[$(( ${#user_ip[@]} - 1)) ]}
			user_count=$(( ${#user_ip[@]} + 1))
			user_name_default="user${user_count}"
			IFS='.' read -ra octet <<< "$last_used"
			octet0=${octet[0]}
			octet1=${octet[1]}
			octet2=${octet[2]}
			octet3=${octet[3]}
			((octet3++))
			if [[ octet3 -eq 255 ]]; then
				echo "only 254 user nodes are supported 10.87.1.1-10.87.1.254"
				echo "you are on your own in editing this script"
				exit
			fi
		fi

		# only server/user nodes can be renamed, making the keys easily human readable
		if [[ ${new_key_type} == "farm" ]]; then
			user_name=$user_name_default
		else
			while :
			do
				echo -e "\nEnter user name ..."
				read -p "default ( $user_name_default ): " user_name
				if [ -z $user_name ]; then
					user_name=$user_name_default
				fi
				if ! test -d .oomer/user/$user_name; then
					break	
				else
					echo ".oomer/user/${user_name} name already exists, try again"
				fi
			done
		fi

		mkdir -p .oomer/user/${user_name} 
		echo .oomer/bin/nebula-cert sign -name "${user_name}" -ip "${octet0}.${octet1}.${octet2}.${octet3}/${mask}" -groups "farm,server,user" -out-crt ".oomer/user/${user_name}/${user_name}.crt" -out-key ".oomer/user/${user_name}/${user_name}.key" -ca-crt ".oomer/keyauthority/ca.crt" -ca-key ".oomer/keyauthority/ca.key"
		.oomer/bin/nebula-cert sign -name "${user_name}" -ip "${octet0}.${octet1}.${octet2}.${octet3}/${mask}" -groups "farm,server,user" -out-crt ".oomer/user/${user_name}/${user_name}.crt" -out-key ".oomer/user/${user_name}/${user_name}.key" -ca-crt ".oomer/keyauthority/ca.crt" -ca-key ".oomer/keyauthority/ca.key"

		origdir=$(pwd)
		cp .oomer/keyauthority/ca.crt .oomer/user/${user_name}
		echo ${octet0}.${octet1}.${octet2}.${octet3} > .oomer/user/${user_name}/.nebula_ip
		echo ${octet0}.${octet1}.${octet2}.${octet3} >> .oomer/.user_ips
		echo ${user_name} >> .oomer/.user_names

		# [TODO] bypass, force user to sneakernet keys for now because this encrypted tar.gz is too hard to decrypt manually
		#cd .oomer/user
		#find "${user_name}" -type f -exec tar -rvf temp.tar {} \;
		#echo openssl enc -aes-256-cbc -salt -pbkdf2 -in temp.tar -out $origdir/.oomer/keysencrypted/${user_name}.keys.encrypted -pass stdin <<< "$encryption_passphrase" 
		#openssl enc -aes-256-cbc -salt -pbkdf2 -in temp.tar -out $origdir/.oomer/keysencrypted/${user_name}.keys.encrypted -pass stdin <<< "$encryption_passphrase" 
		#rm temp.tar
		#cd $origdir
	fi

	if [[ ${new_key_type} == "quit" ]] || [[ ${new_key_type} == "farm" ]]; then
		if [[ "$OSTYPE" == "darwin"* ]]; then
			open .oomer/keysencrypted
		elif [[ "$OSTYPE" == "msys"* ]]; then
			explorer .oomer\\keysencrypted
		fi	
		echo -e "\n=========================================="
		echo "Deployment keys are in .oomer/keysencrypted"
		echo "Protect .oomer dir like your would a .ssh dir"
		echo "Keys are valid for 5 years"
		echo -e "\n[NOTE] A hierarchy of permissions is defined in Nebula configs"
		echo "users can connect to all ports of workers and lighthouses"
		echo "workers can initiate to port 445 and 8080 of lighthouses and to no users"
		echo "lighthouses cannot initiate connections to workers or users" 
		echo "[TODO] Ideally keys should be rotated every few months and previous keys should be revoked" 
		echo -e "\nRun this script again to add more workers, lighthouses or users"
		echo "[NEXT STEP] Drop these files into Google Drive and share publicaly"
		echo "S3 or website also supported"
		exit
	fi



done
