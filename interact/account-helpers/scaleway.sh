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

    zones="fr-par-1 fr-par-2 fr-par-3 nl-ams-1 nl-ams-2 pl-waw-1 pl-waw-2"

    echo -e -n "${Blue}$zones${Color_Off}\n" | tr ' ' '\n'

    default_region="fr-par-1"
    echo -e -n "${Green}Please enter your default region (you can always change this later with axiom-region select \$region): Default '$default_region', press enter \n>> ${Color_Off}"

    read region
    if [[ "$region" == "" ]]; then
        echo -e "${Blue}Using default region: '$default_region'${Color_Off}"
        region="$default_region"
    fi
    physical_region=$(echo $region | rev | cut -d '-' -f 2- | rev)

}

# Check if Scaleway CLI version is up to date
installed_version=$(scw version -o json 2>/dev/null | jq -r .version)
if [[ "$(printf '%s\n' "$installed_version" "$ScalewayCliVersion" | sort -V | head -n 1)" != "$ScalewayCliVersion" ]]; then
    if [[ $BASEOS == "Mac" ]]; then
        if ! command -v brew &> /dev/null || [[ ! -z ${AXIOM_FORCEBREW+x} ]]; then
            echo -e "${BGreen}Installing Homebrew...${Color_Off}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            echo -e "${BGreen}Homebrew is already installed.${Color_Off}"
        fi
        echo -e "${BGreen}Installing Scaleway CLI (scw)...${Color_Off}"
        brew install scw
    elif [[ $BASEOS == "Linux" ]]; then
        if uname -a | grep -qi "Microsoft"; then
            OS="UbuntuWSL"
        else
            OS=$(lsb_release -i 2>/dev/null | awk '{ print $3 }')
            if ! command -v lsb_release &> /dev/null; then
                OS="unknown-Linux"
            fi
        fi

        # Install or update Scaleway CLI for Linux
        if [[ $OS == "Arch" ]] || [[ $OS == "ManjaroLinux" ]]; then
            sudo pacman -S scaleway-cli
        elif [[ $OS == "Ubuntu" ]] || [[ $OS == "Debian" ]] || [[ $OS == "Linuxmint" ]] || [[ $OS == "Parrot" ]] || [[ $OS == "Kali" ]] || [[ $OS == "unknown-Linux" ]] || [[ $OS == "UbuntuWSL" ]]; then
            echo -e "${BGreen}Installing Scaleway Cloud CLI (scw)...${Color_Off}"
            curl -s https://raw.githubusercontent.com/scaleway/scaleway-cli/master/scripts/get.sh | sudo sh
        elif [[ $OS == "Fedora" ]]; then
            echo "Fedora installation requires additional setup."
        fi
    fi
fi

function scalewaysetup() {
    echo -e "${BGreen}Sign up for an account: https://www.scaleway.com/en/signup/\nObtain your API token from: https://console.scaleway.com/project/credentials${Color_Off}"
    echo -e -n "${BGreen}Do you already have a Scaleway account? y/n ${Color_Off}"
    read acc

    if [[ "$acc" == "n" ]]; then
        echo -e "${BGreen}Launching browser with signup page...${Color_Off}"
        if [ $BASEOS == "Mac" ]; then
            open "https://www.scaleway.com/en/signup/"
        else
            sudo apt install xdg-utils -y
            xdg-open "https://www.scaleway.com/en/signup/"
        fi
    fi

    prompt="Choose how to authenticate to Scaleway:"
    PS3=$prompt
    types=("SSO" "API Keys")
    select opt in "${types[@]}"
    do
        case $opt in
        "SSO")
            echo "Starting interactive Scaleway login..."
            yes | scw login | grep -v "unsupported shell 'y'"
            # Extract credentials from config.yaml
            access_key=$(grep -e ^access_key $HOME/.config/scw/config.yaml | cut -d ' ' -f 2)
            default_organization_id=$(grep -e ^default_organization_id $HOME/.config/scw/config.yaml | cut -d ' ' -f 2)
            default_project_id=$(grep -e ^default_project_id $HOME/.config/scw/config.yaml | cut -d ' ' -f 2)
            secret_key=$(grep -e ^secret_key $HOME/.config/scw/config.yaml | cut -d ' ' -f 2)
            get_region_info
            echo "Interactive login completed."
            break
            ;;
        "API Keys")
            echo -e "${BGreen}Go to https://console.scaleway.com/iam/api-keys and click Generate API key${Color_Off}"
            echo -e "${BGreen}After the API key is created, you need to expand 'Add API keys to your environment' to get the required information${Color_Off}"

            read -p "Enter your SCW_ACCESS_KEY: " access_key
            read -p "Enter your SCW_SECRET_KEY: " secret_key
            read -p "Enter your SCW_DEFAULT_ORGANIZATION_ID: " default_organization_id
            read -p "Enter your SCW_DEFAULT_PROJECT_ID: " default_project_id

            data=$(cat <<EOF
access-key: $access_key
secret-key: $secret_key
default_organization_id: $default_organization_id
default_project_id: $default_project_id
default_region: fr-par
default_zone: fr-par-1
EOF
            )

            get_region_info

            mkdir -p "$HOME/.config/scw/"
            echo "$data" > "$HOME/.config/scw/config.yaml"
            scw config set access-key="$access_key" secret-key="$secret_key" default-region="$physical_region" default-zone="$region"

            echo "API credentials configured successfully."
            break
            ;;
        *)
            echo "Invalid option $REPLY"
            ;;
        esac
    done

    echo -e -n "${Green}Listing instance types in $region...\n${Color_Off}"
    scw instance server-type list zone=$region
    echo -e -n "${Green}Please enter your default size (you can always change this later with axiom-sizes select \$size): Default 'DEV1-S', press enter \n>> ${Color_Off}"

    read size
    if [[ "$size" == "" ]]; then
        echo -e "${Blue}Using default size: 'DEV1-S'${Color_Off}"
        size="DEV1-S"
    fi

    data=$(cat <<EOF
{
    "access_key": "$access_key",
    "secret_key": "$secret_key",
    "region": "$region",
    "default_organization_id": "$default_organization_id",
    "default_project_id": "$default_project_id",
    "physical_region": "$physical_region",
    "provider": "scaleway",
    "default_size": "$size"
}
EOF
    )

    echo -e "${BGreen}Profile settings below: ${Color_Off}"
    echo "$data" | jq '.secret_key = "************************************"'
    echo -e "${BWhite}Press enter to save, or type 'r' to restart.${Color_Off}"
    read ans

    if [[ "$ans" == "r" ]]; then
        $0  # Restart script
        exit
    fi

    echo -e -n "${BWhite}Please enter profile name (Default: 'scaleway'): \n>> ${Color_Off}"
    read title

    if [[ "$title" == "" ]]; then
        title="scaleway"
        echo -e "${BGreen}Profile named 'scaleway'${Color_Off}"
    fi

    echo "$data" | jq > "$AXIOM_PATH/accounts/$title.json"
    echo -e "${BGreen}Saved profile '$title' successfully!${Color_Off}"
    $AXIOM_PATH/interact/axiom-account $title
}

scalewaysetup
