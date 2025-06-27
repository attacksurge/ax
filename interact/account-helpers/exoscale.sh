#!/bin/bash

AXIOM_PATH="$HOME/.axiom"
source "$AXIOM_PATH/interact/includes/vars.sh"

token=""
region=""
provider=""
size=""

BASEOS="$(uname)"
case $BASEOS in
'Linux')
    BASEOS='Linux'
    ;;
'FreeBSD')
    BASEOS='FreeBSD'
    alias ls='ls -G'
    ;;
'WindowsNT')
    BASEOS='Windows'
    ;;
'Darwin')
    BASEOS='Mac'
    ;;
'SunOS')
    BASEOS='Solaris'
    ;;
'AIX') ;;
*) ;;
esac

get_region_info() {
    echo -e -n "${Green}Listing regions...\n${Color_Off}"

    zones="at-vie-1 at-vie-2 bg-sof-1 ch-dk-2 ch-gva-2 de-fra-1 de-muc-1"

    echo -e -n "${Blue}$zones${Color_Off}\n" | tr ' ' '\n'

    default_region="ch-gva-2"
    echo -e -n "${Green}Please enter your default region (you can always change this later with axiom-region select \$region): Default '$default_region', press enter \n>> ${Color_Off}"

    read region
    if [[ "$region" == "" ]]; then
        echo -e "${Blue}Using default region: '$default_region'${Color_Off}"
        region="$default_region"
    fi
}

sizes_list() {
	{
  		echo -e "InstanceType\tvCPUs\tMemory"
  		exo compute instance-type list -O json \
    	| jq -r '.[] | select(.authorized != false) | [.family, .name, .cpus, .memory] | @csv' \
    	| tr -d '"' \
    	| awk -F',' '{printf "%s.%s\t%s\t%s GB\n", $1, $2, $3, $4/1073741824}'
	} | column -t -s $'\t'
}

security_groups_list() {
	{
		echo -e "GroupName\tGroupId\tIngressRules\tEgressRules"
		for id in $(exo compute security-group list -O json | jq -r '.[].id'); do
    		exo compute security-group show "$id" -O json
		done \
		| jq -s -r '.[] | [.name, .id, (.ingress_rules | length), (.egress_rules | length)] | @tsv'
	} | column -t

}

installed_version=$(exo version 2>/dev/null | cut -d ' ' -f2)

# Check if the installed version matches the recommended version
if [[ "$(printf '%s\n' "$installed_version" "$ExoscaleCliVersion" | sort -V | head -n 1)" != "$ExoscaleCliVersion" ]]; then
    echo -e "${Yellow}exo CLI is either not installed or version is lower than the recommended version in ~/.axiom/interact/includes/vars.sh${Color_Off}"

	# Determine the OS type and handle installation accordingly
	if [[ $BASEOS == "Mac" ]]; then
		whereis brew
        if [ ! $? -eq 0 ] || [[ ! -z ${AXIOM_FORCEBREW+x} ]]; then
            echo -e "${BGreen}Installing Homebrew...${Color_Off}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            echo -e "${BGreen}Checking for Homebrew... already installed.${Color_Off}"
        fi
		echo -e "${BGreen}Installing/Updating exo CLI on macOS...${Color_Off}"
		brew tap exoscale/tap
		brew install exoscale-cli
	
	elif [[ $BASEOS == "Linux" ]]; then
		if uname -a | grep -qi "Microsoft"; then
			OS="UbuntuWSL"
		else
			OS=$(lsb_release -i 2>/dev/null | awk '{ print $3 }')
			if ! command -v lsb_release &> /dev/null; then
				OS="unknown-Linux"
				BASEOS="Linux"
			fi
		fi

        if [[ $OS == "Fedora" ]] || [[ $OS == "Ubuntu" ]] || [[ $OS == "Debian" ]] || [[ $OS == "Linuxmint" ]] || [[ $OS == "Parrot" ]] || [[ $OS == "Kali" ]] || [[ $OS == "unknown-Linux" ]] || [[ $OS == "UbuntuWSL" ]]; then
			echo -e "${BGreen}Installing/Updating exo CLI on $OS...${Color_Off}"
			curl -fsSL https://raw.githubusercontent.com/exoscale/cli/master/install-latest.sh | sh
		elif [[ $OS == "Arch" ]] || [[ $OS == "ManjaroLinux" ]]; then
			gpg --keyserver keys.openpgp.org --recv-key 7100E8BFD6199CE0374CB7F003686F8CDE378D41
			git clone https://aur.archlinux.org/exoscale-cli-bin.git
			cd exoscale-cli-bin/
			makepkg --install
		else
			echo -e "${BRed}Unsupported Linux distribution: $OS${Color_Off}"
			echo -e "${BRed}Follow instructions from https://community.exoscale.com/community/tools/exoscale-command-line-interface/#other-distributions ${Color_Off}"
		fi
	fi

	echo "exo CLI updated to version $ExoscaleCliVersion."
else
	echo "exo CLI is already at or above the recommended version $ExoscaleCliVersion."
fi

function exoscalesetup(){

	if [[ $BASEOS == "Mac" ]]; then
		mkdir -p "$HOME/Library/Application Support/exoscale"
		CONFIG_PATH="$HOME/Library/Application Support/exoscale"
	else
		mkdir -p "$HOME/.config/exoscale"
		CONFIG_PATH="$HOME/.config/exoscale"
	fi

	echo -e -n "${Green}Please enter your Exoscale Api Key (required): \n>> ${Color_Off}"
	read api_key
	while [[ "$api_key" == "" ]]; do
		echo -e "${BRed}Please provide an Exoscale Api Key, your entry contained no input.${Color_Off}"
		echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
		read api_key
	done

	echo -e -n "${Green}Please enter your Exoscale Secret Key (required): \n>> ${Color_Off}"
	read api_secret
	while [[ "$api_secret" == "" ]]; do
		echo -e "${BRed}Please provide an Exoscale Secret Key, your entry contained no input.${Color_Off}"
		echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
		read api_secret
	done

	get_region_info

	axiom_random_name="axiom-$(date +%m-%d_%H-%M-%S-%1N)"

	cat <<EOF > $(echo "$CONFIG_PATH/exoscale.toml")
defaultaccount = '${axiom_random_name}'

[[accounts]]
defaultZone = '${region}'
key = '${api_key}'
name = '${axiom_random_name}'
secret = '${api_secret}'
EOF

	# Check if credentials are valid
	if exo limits &> /dev/null; then
		echo -e "${BGreen}Exoscale account authenticated successfully.${Color_Off}"
	else
		echo -e "${Red}Exoscale account authentication failed. Please check your credentials.${Color_Off}"
	exit 1
	fi

	sizes_list
	echo -e -n "${BGreen}Please enter your default size (you can always change this later with axiom-sizes select \$size): Default 'standard.medium', press enter \n>> ${Color_Off}"
	read size
	if [[ "$size" == "" ]]; then
		echo -e "${Blue}Selected default option 'standard.medium'${Color_Off}"
		size="standard.medium"
	fi

	# Prompt for disk size
	echo -e -n "${BGreen}Please enter your default disk size in GB (you can always change this later with ax disk set \$size): Default '50', press enter \n>> ${Color_Off}"
	read disk_size
	if [[ "$disk_size" == "" ]]; then
		echo -e "${Blue}Selected default option '50'${Color_Off}"
		disk_size="50"
	fi

	# Print available security groups
	echo -e "${BGreen}Printing Available Security Groups:${Color_Off}"
	security_groups_list

	# Prompt user to enter a security group name
	echo -e -n "${Green}Please enter a security group name above or press enter to create a new security group with a random name \n>> ${Color_Off}"
	read SECURITY_GROUP

	if [[ "$SECURITY_GROUP" == "" ]]; then
  		axiom_sg_random="axiom-$(date +%m-%d_%H-%M-%S-%1N)"
  		SECURITY_GROUP=$axiom_sg_random
  		echo -e "${BGreen}No Security Group provided, will create a new one: '$SECURITY_GROUP'.${Color_Off}"

		# Create the security group
		echo -e "${BGreen}Creating Security Group '$SECURITY_GROUP'...${Color_Off}"
		create_output=$(exo compute security-group create "$SECURITY_GROUP" -O json 2>/dev/null)

		# If creation failed for any reason, log and exit
    	if [[ $? -ne 0 ]]; then
    		echo -e "${BRed}Failed to create security group.${Color_Off}"
    		exit 1
    	fi

		the_group_id=$(echo "$create_output" | jq -r '.id' 2>/dev/null)
		if [[ "$the_group_id" == "null" ]]; then
			echo -e "${BRed}Could not parse GroupId from creation output. Raw output:\n$create_output${Color_Off}"
			exit 1
		fi

	    echo -e "${BGreen}Created Security Group: $the_group_id successfully.${Color_Off}"

	else
		the_group_id=$(exo compute security-group show "$SECURITY_GROUP" -O json | jq -r '.id' 2>/dev/null)
		if [[ "$the_group_id" == "null" ]]; then
			echo -e "${BRed}Could not parse GroupId from selected group.${Color_Off}"
			exit 1
		fi
	fi

	# As of now, the Exoscale packer plugin does not offer a dedicated option to override the SSH port
	group_rule_22=$(exo compute security-group rule add \
		"$the_group_id" \
		--flow 'ingress' \
		--network '0.0.0.0/0' \
		--port '22' \
		--protocol 'tcp' \
		-O json 2>/dev/null
	)
	cmd_exit_status_22=$?

	group_rule_2266=$(exo compute security-group rule add \
		"$the_group_id" \
		--flow 'ingress' \
		--network '0.0.0.0/0' \
		--port '2266' \
		--protocol 'tcp' \
		-O json 2>/dev/null
	)
	cmd_exit_status_2266=$?

	if [[ $cmd_exit_status_2266 -ne 0 || cmd_exit_status_22 -ne 0 ]]; then
    	if echo "$group_rules" | grep -q "job failed"; then
        	echo -e "${BRed}Failed to add rules.${Color_Off}"
    	fi
	else
    	echo -e "${BGreen}Rules added successfully. Output:\n$(echo $group_rules | jq -r '.ingress_rules')${Color_Off}"
	fi

	data="$(echo "{\"api_key\":\"$api_key\",\"api_secret\":\"$api_secret\",\"security_group_name\":\"$SECURITY_GROUP\",\"security_group_id\":\"$the_group_id\",\"region\":\"$region\",\"provider\":\"exoscale\",\"default_size\":\"$size\",\"default_disk_size\":\"$disk_size\"}")"

	echo -e "${BGreen}Profile settings below: ${Color_Off}"
	echo "$data" | jq '.api_secret = "*************************************"'
	echo -e "${BWhite}Press enter if you want to save these to a new profile, type 'r' if you wish to start again.${Color_Off}"
	read ans

	if [[ "$ans" == "r" ]];
	then
	    $0
	    exit
	fi

	echo -e -n "${BWhite}Please enter your profile name (e.g 'exoscale', must be all lowercase/no specials)\n>> ${Color_Off}"
	read title

	if [[ "$title" == "" ]]; then
	    title="exoscale"
	    echo -e "${BGreen}Named profile 'exoscale'${Color_Off}"
	fi

	echo -e "${BGreen}Creating Exoscale config file in ${Color_Off}'${BGreen}$CONFIG_PATH/exoscale.toml${Color_Off}'"
	cat <<EOF > $(echo "$CONFIG_PATH/exoscale.toml")
defaultaccount = '${title}'

[[accounts]]
defaultZone = '${region}'
key = '${api_key}'
name = '${title}'
secret = '${api_secret}'
EOF
	echo "$data" | jq > "$AXIOM_PATH/accounts/$title.json"
	echo -e "${BGreen}Saved profile '$title' successfully!${Color_Off}"
	$AXIOM_PATH/interact/axiom-account "$title"

}

exoscalesetup
