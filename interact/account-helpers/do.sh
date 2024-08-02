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


echo -e "${BGreen}Installing doctl...${Color_Off}"
if [[ $BASEOS == "Mac" ]]; then
brew install doctl
packer plugins install github.com/digitalocean/digitalocean
elif [[ $BASEOS == "Linux" ]]; then
OS=$(lsb_release -i 2>/dev/null | awk '{ print $3 }')
   if ! command -v lsb_release &> /dev/null; then
            OS="unknown-Linux"
            BASEOS="Linux"
   fi
   if [[ $OS == "Arch" ]] || [[ $OS == "ManjaroLinux" ]]; then
      sudo pacman -Syu doctl --noconfirm
   else
      wget -q -O /tmp/doctl.tar.gz https://github.com/digitalocean/doctl/releases/download/v1.66.0/doctl-1.66.0-linux-amd64.tar.gz && tar -xvzf /tmp/doctl.tar.gz && sudo mv doctl /usr/bin/doctl && rm /tmp/doctl.tar.gz
   fi
fi

function dosetup(){

echo -e "${BGreen}Sign up for an account using this link for 200\$ free credit: https://m.do.co/c/541daa5b4786\nObtain personal access token from: https://cloud.digitalocean.com/account/api/tokens${Color_Off}"
echo -e -n "${BGreen}Do you already have a DigitalOcean account? y/n ${Color_Off}"
read acc 

if [[ "$acc" == "n" ]]; then
    echo -e "${BGreen}Launching browser with signup page...${Color_Off}"
    if [ $BASEOS == "Mac" ]; then
    open "https://m.do.co/c/541daa5b4786"
    else
    sudo apt install xdg-utils -y
    xdg-open "https://m.do.co/c/541daa5b4786"
    fi
fi
	
echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
read token
while [[ "$token" == "" ]]; do
	echo -e "${BRed}Please provide a token, your entry contained no input.${Color_Off}"
	echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
	read token
done

doctl auth init -t "$token" | grep -vi "using token"

echo -e -n "${Green}Listing available regions with axiom-regions ls \n${Color_Off}"
doctl compute region list | grep -v false 

default_region=nyc1
echo -e -n "${Green}Please enter your default region: (Default '$default_region', press enter) \n>> ${Color_Off}"
read region
	if [[ "$region" == "" ]]; then
	echo -e "${Blue}Selected default option '$default_region'${Color_Off}"
	region="$default_region"
	fi
	echo -e -n "${Green}Please enter your default size: (Default 's-1vcpu-1gb', press enter) \n>> ${Color_Off}"
	read size
	if [[ "$size" == "" ]]; then
	echo -e "${Blue}Selected default option 's-1vcpu-1gb'${Color_Off}"
        size="s-1vcpu-1gb"
fi

data="$(echo "{\"do_key\":\"$token\",\"region\":\"$region\",\"provider\":\"do\",\"default_size\":\"$size\"}")"

echo -e "${BGreen}Profile settings below: ${Color_Off}"
echo $data | jq
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

dosetup
