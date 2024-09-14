#!/bin/bash

AXIOM_PATH="$HOME/.axiom"
source "$AXIOM_PATH/interact/includes/vars.sh"

token=""
region=""
provider=""
size=""
cpu=""
username=""
ibm_cloud_api_key=""

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

installed_version=$(ibmcloud version 2>/dev/null | cut -d ' ' -f 2 | cut -d + -f 1)

# Check if the installed version matches the recommended version
if [[ "$installed_version" != "${IBMCloudCliVersion}" ]]; then
    echo -e "${Yellow}ibmcloud cli is either not installed or version is lower than the recommended version in ~/.axiom/interact/includes/vars.sh${Color_Off}"

    if [[ $BASEOS == "Mac" ]]; then
        # macOS installation/update
        echo -e "${BGreen}Installing/updating ibmcloud-cli on macOS...${Color_Off}"
        whereis brew
        if [ ! $? -eq 0 ] || [[ ! -z ${AXIOM_FORCEBREW+x} ]]; then
            echo -e "${BGreen}Installing Homebrew...${Color_Off}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            echo -e "${BGreen}Checking for Homebrew... already installed.${Color_Off}"
        fi
        echo -e "${BGreen}Installing ibmcloud-cli...${Color_Off}"
        curl -fsSL https://clis.cloud.ibm.com/install/osx | sh
        echo -e "${BGreen}Installing ibmcloud sl (SoftLayer) plugin...${Color_Off}"
        ibmcloud plugin install sl -q -f
    elif [[ $BASEOS == "Linux" ]]; then
        if uname -a | grep -qi "Microsoft"; then
            OS="UbuntuWSL"
        else
            OS=$(lsb_release -i | awk '{ print $3 }')
            if ! command -v lsb_release &> /dev/null; then
                OS="unknown-Linux"
                BASEOS="Linux"
            fi
        fi
        if [[ $OS == "Arch" ]] || [[ $OS == "ManjaroLinux" ]]; then
            echo "Needs Conversation for Arch or ManjaroLinux"
        elif [[ $OS == "Ubuntu" ]] || [[ $OS == "Debian" ]] || [[ $OS == "Linuxmint" ]] || [[ $OS == "Parrot" ]] || [[ $OS == "Kali" ]] || [[ $OS == "unknown-Linux" ]] || [[ $OS == "UbuntuWSL" ]]; then
            echo -e "${BGreen}Installing ibmcloud-cli on Linux...${Color_Off}"
            curl -fsSL https://clis.cloud.ibm.com/install/linux | sh
            echo -e "${BGreen}Installing ibmcloud sl (SoftLayer) plugin...${Color_Off}"
            ibmcloud plugin install sl -q -f
        elif [[ $OS == "Fedora" ]]; then
            echo "Needs Conversation for Fedora"
        fi
    fi

    echo "ibmcloud-cli updated to version $IBMCloudCliVersion."
else
    echo "ibmcloud-cli is already at or above the recommended version $IBMCloudCliVersion."
fi

# Change Packer version for IBM Cloud
mkdir -p /tmp/packer-ibm/
if [[ ! -f /tmp/packer-ibm/packer ]]; then
    if [[ $BASEOS == "Linux" ]]; then
        wget -q -O /tmp/packer.zip https://releases.hashicorp.com/packer/1.5.6/packer_1.5.6_linux_amd64.zip
        cd /tmp/
        unzip packer.zip
        mv packer /tmp/packer-ibm/
        rm /tmp/packer.zip
    elif [[ $BASEOS == "Mac" ]]; then
        wget -q -O /tmp/packer.zip https://releases.hashicorp.com/packer/1.5.6/packer_1.5.6_darwin_amd64.zip
        cd /tmp/
        unzip packer.zip
        mv packer /tmp/packer-ibm/
        rm /tmp/packer.zip
    fi
fi

# Packer check for IBM Cloud plugin
if [[ ! -f "$HOME/.packer.d/plugins/packer-builder-ibmcloud" ]]; then
    echo -n -e "${BGreen}Installing IBM Cloud Packer Builder (https://github.com/IBM/packer-plugin-ibmcloud/):\n y/n >> ${Color_Off}"
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    mkdir -p ~/.packer.d/plugins/
    wget https://github.com/IBM/packer-plugin-ibmcloud/releases/download/v1.0.1/packer-builder-ibmcloud_1.0.1_linux_64-bit.tar.gz -O - | tar -xz -C ~/.packer.d/plugins/
fi

function getUsernameAPIkey {
email=$(cat ~/.bluemix/config.json  | grep Owner | cut -d '"' -f 4)
username=$(ibmcloud sl user list | grep -i $email | tr -s ' ' | cut -d ' ' -f 2)
accountnumber=$(ibmcloud sl user list | grep -i $email | tr -s ' ' | cut -d ' ' -f 1)
token=$(ibmcloud sl user detail $accountnumber --keys  | grep APIKEY | tr -s ' ' | cut -d ' ' -f 2)
if [ -z "$token" ]
then
echo -e -n "${Green}Create an IBM Cloud Classic Infrastructure (SoftLayer) API key (for Packer) here: https://cloud.ibm.com/iam/apikeys (required): \n>> ${Color_Off}"
read token
while [[ "$token" == "" ]]; do
	echo -e "${BRed}Please provide a IBM Cloud Classic API key, your entry contained no input.${Color_Off}"
	echo -e -n "${Green}Please enter your IBM Cloud Classic API key (required): \n>> ${Color_Off}"
	read token
done
fi
}


function apikeys {
echo -e -n "${Green}Create an IBM Cloud IAM API key (for ibmcloud cli) here: https://cloud.ibm.com/iam/apikeys (required): \n>> ${Color_Off}"
read ibm_cloud_api_key
while [[ "$ibm_cloud_api_key" == "" ]]; do
	echo -e "${BRed}Please provide a IBM Cloud API key, your entry contained no input.${Color_Off}"
	echo -e -n "${Green}Please enter your IBM Cloud API key (required): \n>> ${Color_Off}"
	read ibm_cloud_api_key
done
ibmcloud login --apikey=$ibm_cloud_api_key --no-region
getUsernameAPIkey
}


function create_apikey {
echo -e -n "${Green}Creating an IAM API key for this profile \n>> ${Color_Off}"
name="axiom-$(printf '%(%FT%T%z)T\n')"
key_details=$(ibmcloud iam api-key-create "$name" --output json)
echo "$key_details" | jq
ibm_cloud_api_key=$(echo "$key_details" | jq -r .apikey)
ibmcloud login --apikey=$ibm_cloud_api_key --no-region
}

function specs {
echo -e -n "${Green}Printing available regions..\n${Color_Off}"
ibmcloud sl  vs options --output json | jq .locations
echo -e -n "${BGreen}Please enter your default region (you can always change this later with axiom-region select \$region): Default 'dal13', press enter \n>> ${Color_Off}"
read region
if [[ "$region" == "" ]]; then

	echo -e "${Blue}Selected default option 'dal13'${Color_Off}"
	region="dal13"
fi
echo -e -n "${BGreen}Please enter your default RAM (you can always change this later with axiom-sizes select \$size): Default '2048', press enter \n>> ${Color_Off}"
echo -e -n "${Blue}Options: 2048, 4096, 8192, 16384, 32768, 64512\n>> ${Color_Off}"
read size
if [[ "$size" == "" ]]; then
	echo -e "${Blue}Selected default option '2048'${Color_Off}"
  size="2048"
fi
echo -e -n "${Green}Please enter amount of CPU Cores: (Default '2', press enter) \n${Color_Off}"
echo -e -n "${Blue}Options: 1, 2, 4, 8, 16, 32, 48\n>> ${Color_Off}"

read cpu
if [[ "$cpu" == "" ]]; then
  echo -e "${Blue}Selected default option '2'${Color_Off}"
  cpu="2"
fi
}


function setprofile {
data="$(echo "{\"sl_key\":\"$token\",\"ibm_cloud_api_key\":\"$ibm_cloud_api_key\",\"region\":\"$region\",\"provider\":\"ibm\",\"default_size\":\"$size\",\"cpu\":\"$cpu\",\"username\":\"$username\"}")"
echo -e "${BGreen}Profile settings below: ${Color_Off}"
echo $data | jq '.sl_key = "************************************************************************" | .ibm_cloud_api_key = "***************************************"'
echo -e "${BWhite}Press enter if you want to save these to a new profile, type 'r' if you wish to start again.${Color_Off}"
read ans
if [[ "$ans" == "r" ]];
then
    $0
    exit
fi
echo -e -n "${BWhite}Please enter your profile name (e.g 'personal', must be all lowercase/no specials)\n>> ${Color_Off}"
read title
if [[ "$title" == "" ]]; then
    title="personal"
    echo -e "${BGreen}Named profile 'personal'${Color_Off}"
fi
echo $data | jq > "$AXIOM_PATH/accounts/$title.json"
echo -e "${BGreen}Saved profile '$title' successfully!${Color_Off}"
$AXIOM_PATH/interact/axiom-account $title
}

prompt="Choose how to authenticate to IBM Cloud:"
PS3=$prompt
types=("SSO" "Username & Password" "API Keys")
 select opt in "${types[@]}"
   do
   case $opt in
   "SSO")
     echo "Attempting to authenticate with SSO!"
     ibmcloud login --no-region --sso
     getUsernameAPIkey
     create_apikey
     specs
     setprofile
     break
     ;;
  "Username & Password")
     ibmcloud login --no-region
     getUsernameAPIkey
     create_apikey
     specs
     setprofile
     break
     ;;
  "API Keys")
     apikeys
     specs
     setprofile
     break
     ;; 
   *) echo "invalid option $REPLY";;
 esac
done
