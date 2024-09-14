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

installed_version=$(hcloud version 2>/dev/null| cut -d ' ' -f 2)

# Check if the installed version matches the recommended version
if [[ "$installed_version" != "${HetznerCliVersion}" ]]; then
    echo -e "${Yellow}hcloud-cli is either not installed or version is lower than the recommended version in ~/.axiom/interact/includes/vars.sh${Color_Off}"

    # Handle macOS installation/update
    if [[ $BASEOS == "Mac" ]]; then
        whereis brew
        if [ ! $? -eq 0 ] || [[ ! -z ${AXIOM_FORCEBREW+x} ]]; then
            echo -e "${BGreen}Installing Homebrew...${Color_Off}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            echo -e "${BGreen}Checking for Homebrew... already installed.${Color_Off}"
        fi
        if ! [ -x "$(command -v hcloud)" ]; then
            echo -e "${BGreen}Installing hetzner-cloud CLI (hcloud)...${Color_Off}"
            brew install hcloud
            echo -e "${BGreen}Installing Hetzner Packer plugin...${Color_Off}"
            packer plugins install github.com/hetznercloud/hcloud
        fi

    # Handle Linux installation/update
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

        # Install or update hcloud on different Linux distributions
        if [[ $OS == "Arch" ]] || [[ $OS == "ManjaroLinux" ]]; then
            sudo pacman -Syu hcloud --noconfirm
        elif [[ $OS == "Ubuntu" ]] || [[ $OS == "Debian" ]] || [[ $OS == "Linuxmint" ]] || [[ $OS == "Parrot" ]] || [[ $OS == "Kali" ]] || [[ $OS == "unknown-Linux" ]] || [[ $OS == "UbuntuWSL" ]]; then
            if ! [ -x "$(command -v hcloud)" ]; then
                echo -e "${BGreen}Installing hetzner-cloud CLI (hcloud)...${Color_Off}"
                wget -q -O /tmp/hetzner-cli.tar.gz https://github.com/hetznercloud/cli/releases/download/v${HetznerCliVersion}/hcloud-linux-amd64.tar.gz
                tar -xvzf /tmp/hetzner-cli.tar.gz -C /tmp
                sudo mv /tmp/hcloud /usr/bin/hcloud
                rm /tmp/hetzner-cli.tar.gz
            fi
        elif [[ $OS == "Fedora" ]]; then
            echo "Needs Conversation for Fedora"
        fi
    fi

    echo "hcloud-cli updated to version $HetznerCliVersion."
else
    echo "hcloud-cli is already at or above the recommended version $HetznerCliVersion."
fi

function hetznersetup(){
 while true; do
  echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
  read token
  while [[ "$token" == "" ]]; do
   echo -e "${BRed}Please provide a token, your entry contained no input.${Color_Off}"
   echo -e -n "${BGreen}Please enter your token (required): \n>> ${Color_Off}"
   read token
  done

  status_code=$(curl -s -o /dev/null -w "%{http_code}"  -H "Authorization: Bearer $token" https://api.hetzner.cloud/v1/servers)
  if [[ "$status_code" == "200" ]]; then
   echo -e "${BGreen}Token is valid.${Color_Off}"
   break
  else
   echo -e "${BRed}Token provided is invalid. Please enter a valid token.${Color_Off}"
  fi
done

default_region=nbg1
echo -e -n "${BGreen}Please enter your default region (you can always change this later with axiom-region select \$region): Default '$default_region', press enter \n>> ${Color_Off}"
read region
	if [[ "$region" == "" ]]; then
	echo -e "${BGreen}Selected default option '$default_region'${Color_Off}"
	region="$default_region"
	fi
	echo -e -n "${BGreen}Please enter your default size (you can always change this later with axiom-sizes select \$size): Default 'cx22', press enter \n>> ${Color_Off}"
	read size
	if [[ "$size" == "" ]]; then
	echo -e "${BGreen}Selected default option 'cx22'${Color_Off}"
        size="cx22"
fi

data="$(echo "{\"hetzner_key\":\"$token\",\"region\":\"$region\",\"provider\":\"hetzner\",\"default_size\":\"$size\"}")"

echo -e "${BGreen}Profile settings below: ${Color_Off}"
echo $data | jq '.hetzner_key =  "****************************************************************"'
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

echo -e "${BGreen}Creating hetzner context and config file in ${Color_Off}'${BGreen}$HOME/.config/hcloud/cli.toml${Color_Off}'"
mkdir -p $HOME/.config/hcloud/
cat <<EOT > $(echo "$HOME/.config/hcloud/cli.toml")
active_context = "$title"

[[contexts]]
  name = "$title"
  token = "$token"
EOT

echo $data | jq > "$AXIOM_PATH/accounts/$title.json"
echo -e "${BGreen}Saved profile '$title' successfully!${Color_Off}"
$AXIOM_PATH/interact/axiom-account $title
}

hetznersetup
