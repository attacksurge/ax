#!/bin/bash

AXIOM_PATH="$HOME/.axiom"
source "$AXIOM_PATH/interact/includes/vars.sh"

client_id=""
client_secret=""
tenant_id=""
sub_id=""
token=""
region=""
provider=""
size=""
# Packer::Azure CLI auth will use the information from an active az login session to connect to Azure and set the subscription id and tenant id associated to the signed in account. 
# Packer::Azure CLI authentication will use the credential marked as isDefault
use_azure_cli_auth="true"

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

installed_version=$(az version 2>/dev/null | jq -r '."azure-cli"')

# Check if the installed version matches the recommended version
if [[ "$(printf '%s\n' "$installed_version" "$AzureCliVersion" | sort -V | head -n 1)" != "$AzureCliVersion" ]]; then
    echo -e "${Yellow}Azure CLI is either not installed or version is lower than the recommended version in ~/.axiom/interact/includes/vars.sh${Color_Off}"

    # Handle macOS installation/update
    if [[ $BASEOS == "Mac" ]]; then
        whereis brew
        if [ ! $? -eq 0 ] || [[ ! -z ${AXIOM_FORCEBREW+x} ]]; then
            echo -e "${BGreen}Installing Homebrew...${Color_Off}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            echo -e "${BGreen}Checking for Homebrew... already installed.${Color_Off}"
        fi
        if ! [ -x "$(command -v az)" ]; then
            echo -e "${BGreen}Installing Azure CLI (az)...${Color_Off}"
            brew update && brew install azure-cli
        else
            echo -e "${BGreen}Updating Azure CLI (az)...${Color_Off}"
            brew update && brew upgrade azure-cli
        fi

    # Handle Linux installation/update
    elif [[ $BASEOS == "Linux" ]]; then
        echo -e "${BGreen}Installing Azure CLI (az)...${Color_Off}"
        sudo apt-get update -qq
        sudo apt-get install ca-certificates curl apt-transport-https lsb-release gnupg -y -qq

        if uname -a | grep -qi "Microsoft"; then
            OS="UbuntuWSL"
        else
            OS=$(lsb_release -i 2>/dev/null | awk '{ print $3 }')
            if ! command -v lsb_release &> /dev/null; then
                OS="unknown-Linux"
                BASEOS="Linux"
            fi
        fi

        AZ_REPO=$(lsb_release -cs)
        if [[ $AZ_REPO == "kali-rolling" ]]; then
            check_version=$(cat /proc/version | awk '{ print $6 $7 }' | tr -d '()' | cut -d . -f 1)
            case $check_version in
                Debian10)
                    AZ_REPO="buster"
                    ;;
                Debian11)
                    AZ_REPO="bullseye"
                    ;;
                Debian12)
                    AZ_REPO="bookworm"
                    ;;
                *)
                    echo "Unknown Debian version. Exiting."
                    exit 1
                    ;;
            esac
        fi

        curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
        echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" | sudo tee /etc/apt/sources.list.d/azure-cli.list

        sudo apt-get update -qq
        sudo apt-get install azure-cli -y -qq

    elif [[ $OS == "Fedora" ]]; then
        echo "Needs Conversation for Fedora"
    fi

    echo "Azure CLI updated to version $AzureCliVersion."
else
    echo "Azure CLI is already at or above the recommended version $AzureCliVersion."
fi

###########################################################################################################
# Login and get default user email
#
default_email=$(az login --use-device-code | jq -r  '.[].user.name')

###########################################################################################################
# get the sub_id or use user provided subscription_id
#
sub_id="$(az account show --query "{ subscription_id: id }" | jq -r .subscription_id)"
echo -e -n "${Green}Please enter your subscription_id: (Default is $(echo $sub_id), press enter) \n>> ${Color_Off}"
read user_sub_id
if [[ "$user_sub_id" == "" ]]; then
    echo -e "${Blue}Selected default subscription_id $sub_id${Color_Off}"
    else
    sub_id=$user_sub_id
fi

###########################################################################################################
# get the region or use user provided region
#
echo -e -n "${Green}Please enter your default region (you can always change this later with axiom-region select \$region): Default 'eastus', press enter \n>> ${Color_Off}"
read region

if [[ "$region" == "" ]]; then
    echo -e "${Blue}Selected default option 'eastus'${Color_Off}"
    region="eastus"
fi

###########################################################################################################
# get the size of the vm to spinup or use user provded size 
#
echo -e -n "${Green}Please enter your default size (you can always change this later with axiom-sizes select \$size): Default 'Standard_B1ls', press enter \n>> ${Color_Off}"
read size

if [[ "$size" == "" ]]; then
    echo -e "${Blue}Selected default option 'Standard_B1ls'${Color_Off}"
    size="Standard_B1ls"
fi

###########################################################################################################
# get the resource name or use user provided resorce name
#
echo -e -n "${Green}Please enter your resource group name: (Default 'axiom'), press enter) \n>> ${Color_Off}"
read resource_group

if [[ "$resource_group" == "" ]]; then
    echo -e "${Blue}Selected default option 'axiom'${Color_Off}"
    resource_group="axiom"
fi

###########################################################################################################
# get the azure email account or use user provided email
#
echo -e -n "${Green}Please enter your Azure email account: (Default is $default_email, press enter) \n>> ${Color_Off}"
read email

if [[ "$email" == "" ]]; then
   email="$default_email"
fi

az account set --subscription "$sub_id" 2>/dev/null
az group create -l "$region" -n "$resource_group" 2>/dev/null
#az configure --defaults group="$resource_group" 2>/dev/null
az role assignment create --role "Owner" --assignee "$email" -g ${resource_group} 2>/dev/null
az provider register --namespace 'Microsoft.Network' --accept-terms 2>/dev/null
az provider register --namespace 'Microsoft.Compute' --accept-terms 2>/dev/null
bac=$(az ad sp create-for-rbac --role Owner --scopes "/subscriptions/$sub_id/resourcegroups/${resource_group}" --name ${resource_group} --query "{ client_id: appId, client_secret: password, tenant_id: tenant }") 2>/dev/null
client_id="$(echo $bac | jq -r '.client_id')"
client_secret="$(echo $bac | jq -r '.client_secret')"
tenant_id="$(echo $bac | jq -r '.tenant_id')"

data="$(echo "{\"client_id\":\"$client_id\",\"client_secret\":\"$client_secret\",\"tenant_id\":\"$tenant_id\",\"subscription_id\":\"$sub_id\",\"region\":\"$region\",\"resource_group\":\"$resource_group\",\"provider\":\"azure\",\"default_size\":\"$size\",\"use_azure_cli_auth\":\"$use_azure_cli_auth\"}")"

echo -e "${BGreen}Profile settings below: ${Color_Off}"
echo $data | jq '.client_secret = "*************************************"'
echo -e "${BWhite}Press enter if you want to save these to a new profile, type 'r' if you wish to start again.${Color_Off}"
read ans

if [[ "$ans" == "r" ]];
then
    $0
    exit
fi

echo -e -n "${BWhite}Please enter your profile name (e.g 'azure', must be all lowercase/no specials)\n>> ${Color_Off}"
read title

if [[ "$title" == "" ]]; then
    title="azure"
    echo -e "${BGreen}Named profile 'azure'${Color_Off}"
fi

echo $data | jq > "$AXIOM_PATH/accounts/$title.json"
echo -e "${BGreen}Saved profile '$title' successfully!${Color_Off}"
$AXIOM_PATH/interact/axiom-account $title
