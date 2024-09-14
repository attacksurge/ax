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

echo -e "${Green}Checking linode-cli version...\n${Color_Off}"

# Get the currently installed version of linode-cli
installed_version=$(linode-cli --version 2>/dev/null| grep linode-cli | cut -d ' ' -f 2 | cut -d v -f 2-)

# Check if the installed version matches the desired version
if [[ "$installed_version" != "${LinodeCliVersion}" ]]; then
    echo -e "${Yellow}linode-cli is either not installed or version is lower than the recommended version in ~/.axiom/interact/includes/vars.sh${Color_Off}"
    echo "Installing/updating linode-cli to version $LinodeCliVersion..."

    # Try to install or upgrade linode-cli and handle externally-managed-environment
    output=$(pip3 install linode-cli --upgrade 2>&1)

    if echo "$output" | grep -q "externally-managed-environment"; then
        echo "Detected an externally managed environment. Retrying with --break-system-packages..."
        pip3 install linode-cli --upgrade --break-system-packages
    else
        echo "linode-cli updated successfully or no externally managed environment detected."
    fi
else
    echo "linode-cli is already at or above the recommended version $LinodeCliVersion."
fi

if [[ $BASEOS == "Mac" ]]; then
    echo -e "${BGreen}Installing linode packer plugin...${Color_Off}"
    packer plugins install github.com/linode/linode
fi


function setuplinode(){
echo -e "${BGreen}Sign up for an account using this link for \$100 free credit: https://www.linode.com/lp/refer/?r=71f79f7e02534d6f673cbc8a17581064e12ac27d\nObtain a personal access token from: https://cloud.linode.com/profile/tokens${Color_Off}"
echo -e -n "${BGreen}Do you already have a Linode account? y/n ${Color_Off}"
read acc 

if [[ "$acc" == "n" ]]; then
    echo -e "${BGreen}Launching browser with signup page...${Color_Off}"
    if [ $BASEOS == "Mac" ]; then
    open "https://www.linode.com/lp/refer/?r=71f79f7e02534d6f673cbc8a17581064e12ac27d"
    elif [ $BASEOS == "Linux" ]; then
           OS=$(lsb_release -i 2>/dev/null | awk '{ print $3 }')
   if ! command -v lsb_release &> /dev/null; then
            OS="unknown-Linux"
            BASEOS="Linux"
   fi
       if [ $OS == "Arch" ] || [ $OS == "ManjaroLinux" ]; then
          sudo pacman -Syu xdg-utils --noconfirm
       else
          sudo apt install xdg-utils -y
       fi
    xdg-open "https://www.linode.com/lp/refer/?r=71f79f7e02534d6f673cbc8a17581064e12ac27d"
    fi
fi

echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
read token
while [[ "$token" == "" ]]; do
	echo -e "${BRed}Please provide a token, your entry contained no input.${Color_Off}"
	echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
	read token
done

echo -e -n "${BGreen}Please enter your default region (you can always change this later with axiom-region select \$region): Default 'us-east', press enter \n>> ${Color_Off}"
read region
	if [[ "$region" == "" ]]; then
	echo -e "${Blue}Selected default option 'us-east'${Color_Off}"
	region="us-east"
	fi
	echo -e -n "${BGreen}Please enter your default size (you can always change this later with axiom-sizes select \$size): Default 'g6-standard-1', press enter \n>> ${Color_Off}"
	read size
	if [[ "$size" == "" ]]; then
	echo -e "${Blue}Selected default option 'g6-standard-1'${Color_Off}"
        size="g6-standard-1"
fi

data="$(echo "{\"linode_key\":\"$token\",\"region\":\"$region\",\"provider\":\"linode\",\"default_size\":\"$size\"}")"


echo -e "${BGreen}Profile settings below: ${Color_Off}"
echo $data | jq '.linode_key = "*******************************************************"'
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
echo -e -n "${Yellow}Would you like me to open a ticket to get an image increase to 75GB for you (you only need to do this once)?${Color_Off} [y]/n >> "
read acc

if [[ "$acc" == "" ]]; then
	acc="y"
fi

if [[ "$acc" == "y" ]]; then

  curl https://api.linode.com/v4/support/tickets -H "Content-Type: application/json"  -H "Authorization: Bearer $token" -X POST -d '{ "description":  "Hello! I have recently installed the Ax Framework https://github.com/attacksurge/ax and would like to request an image increase to 75GB please for the purposes of bulding the packer image. Thank you have a great day! - This request was automatically generated by the Ax Framework", "summary": "Image increase request to 75GB for Ax" }'
  echo ""   
  echo -e "${Green}Opened a ticket with Linode support! Please wait patiently for a few hours and when you get an increase run 'axiom-build'!${Color_Off}"
	echo "View open tickets at: https://cloud.linode.com/support/tickets"
fi
}

setuplinode

