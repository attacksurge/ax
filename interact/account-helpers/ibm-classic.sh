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


installed_version=$(ibmcloud version 2>/dev/null | cut -d ' ' -f 2 | cut -d + -f 1 | head -n 1)

# Check if the installed version matches the recommended version
if [[ "$(printf '%s\n' "$installed_version" "$IBMCloudCliVersion" | sort -V | head -n 1)" != "$IBMCloudCliVersion" ]]; then
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

# Install IBM Cloud CLI SoftLayer Plugin
echo -e "${BGreen}Installing ibmcloud sl (SoftLayer) plugin...${Color_Off}"
ibmcloud plugin install sl -q -f

# Install IBM Cloud Packer Plugin
echo -e "${BGreen}Installing IBM Cloud Packer Builder Plugin${Color_Off}"
packer plugins install github.com/IBM/ibmcloud

# Functions to handle IBM Cloud API keys and configurations
function getUsernameAPIkey {
    email=$(cat ~/.bluemix/config.json  | grep Owner | cut -d '"' -f 4)
    username=$(ibmcloud sl user list | grep -i $email | tr -s ' ' | cut -d ' ' -f 2)
    accountnumber=$(ibmcloud sl user list | grep -i $email | tr -s ' ' | cut -d ' ' -f 1)
    token=$(ibmcloud sl user detail $accountnumber --keys  | grep APIKEY | tr -s ' ' | cut -d ' ' -f 2)
    if [ -z "$token" ]; then
        echo -e -n "${Green}Create an IBM Cloud Classic Infrastructure (SoftLayer) API key (for Packer) here: https://cloud.ibm.com/iam/apikeys (required): \n>> ${Color_Off}"
        read token
        while [[ "$token" == "" ]]; do
            echo -e "${BRed}Please provide a valid IBM Cloud Classic API key.${Color_Off}"
            read token
        done
    fi
}

function apikeys {
    echo -e -n "${Green}Create an IBM Cloud IAM API key (for ibmcloud cli) here: https://cloud.ibm.com/iam/apikeys (required): \n>> ${Color_Off}"
    read ibm_cloud_api_key
    while [[ "$ibm_cloud_api_key" == "" ]]; do
        echo -e "${BRed}Please provide a valid IBM Cloud API key.${Color_Off}"
        read ibm_cloud_api_key
    done
    ibmcloud login --apikey=$ibm_cloud_api_key --no-region
    getUsernameAPIkey
}

function create_apikey {
    echo -e -n "${Green}Creating an IAM API key for this profile \n>> ${Color_Off}"
    name="axiom-$(date +%FT%T%z)"
    key_details=$(ibmcloud iam api-key-create "$name" --output json)
    ibm_cloud_api_key=$(echo "$key_details" | jq -r .apikey)
    ibmcloud login --apikey=$ibm_cloud_api_key --no-region
}

function specs {
    echo -e -n "${Green}Printing available regions..\n${Color_Off}"
    ibmcloud sl vs options --output json | jq .locations
    echo -e -n "${BGreen}Please enter your default region (press enter for 'dal13'): \n>> ${Color_Off}"
    read region
    region=${region:-dal13}

    echo -e -n "${BGreen}Please enter your default RAM (press enter for '2048'): \n>> ${Color_Off}"
    echo -e -n "${Blue}Options: 2048, 4096, 8192, 16384, 32768, 64512\n>> ${Color_Off}"
    read size
    size=${size:-2048}

    echo -e -n "${Green}Please enter amount of CPU Cores (press enter for '2'): \n>> ${Color_Off}"
    echo -e -n "${Blue}Options: 1, 2, 4, 8, 16, 32, 48\n>> ${Color_Off}"
    read cpu
    cpu=${cpu:-2}
}

function setprofile {
    data="{\"sl_key\":\"$token\",\"ibm_cloud_api_key\":\"$ibm_cloud_api_key\",\"region\":\"$region\",\"provider\":\"ibm\",\"default_size\":\"$size\",\"cpu\":\"$cpu\",\"username\":\"$username\"}"
    echo -e "${BGreen}Profile settings below:${Color_Off}"
    echo $data | jq '.sl_key = "********" | .ibm_cloud_api_key = "********"'
    echo -e "${BWhite}Press enter to save these to a new profile, type 'r' to start over.${Color_Off}"
    read ans
    if [[ "$ans" == "r" ]]; then
        $0
        exit
    fi
    echo -e -n "${BWhite}Please enter your profile name (e.g. 'ibm'):\n>> ${Color_Off}"
    read title
    title=${title:-ibm}
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
        *)
            echo "Invalid option $REPLY"
            ;;
    esac
done
