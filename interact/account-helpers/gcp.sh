#!/bin/bash

AXIOM_PATH="$HOME/.axiom"
source "$AXIOM_PATH/interact/includes/vars.sh"

service_account_key=""
region=""
zone=""
provider="gcp"

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

check_and_create_firewall_rule() {
    firewall_rule_name="axiom-ssh"
    expected_target_tag="axiom-ssh"

    # Check if the firewall rule exists
    rule_exists=$(gcloud compute firewall-rules list --filter="name=$firewall_rule_name" --format="value(name)")

    if [[ -z "$rule_exists" ]]; then
        echo "Firewall rule '$firewall_rule_name' does not exist. Creating it now..."

        # Create the firewall rule to allow SSH (port 2266)
        gcloud compute firewall-rules create "$firewall_rule_name" \
            --allow tcp:2266 \
            --direction INGRESS \
            --priority 1000 \
            --target-tags "$expected_target_tag" \
            --description "Allow SSH traffic" \
            --quiet

        echo "Firewall rule '$firewall_rule_name' created successfully."
    else
        echo "Firewall rule '$firewall_rule_name' already exists."

        # Check the current target tags
        current_target_tag=$(gcloud compute firewall-rules describe "$firewall_rule_name" --format="value(targetTags)")

        if [[ "$current_target_tag" != *"$expected_target_tag"* ]]; then
            echo "Target tag is not set to '$expected_target_tag'. Updating the firewall rule..."

            # Update the firewall rule to set the correct target tag
            gcloud compute firewall-rules update "$firewall_rule_name" \
                --target-tags="$expected_target_tag" \
                --quiet

            echo "Firewall rule '$firewall_rule_name' updated with the correct target tag '$expected_target_tag'."
        else
            echo "Firewall rule '$firewall_rule_name' already has the correct target tag '$expected_target_tag'."
        fi
    fi
}

# Function to clean up duplicate repository entries
function clean_gcloud_repos() {
    # Remove duplicate entries from google-cloud-sdk.list
    if [[ -f /etc/apt/sources.list.d/google-cloud-sdk.list ]]; then
        echo "Cleaning up duplicate entries in google-cloud-sdk.list..."
        sudo awk '!seen[$0]++' /etc/apt/sources.list.d/google-cloud-sdk.list > /tmp/google-cloud-sdk.list
        sudo mv /tmp/google-cloud-sdk.list /etc/apt/sources.list.d/google-cloud-sdk.list
    fi
}

# Check if gcloud CLI is installed and up to date
installed_version=$(gcloud version 2>/dev/null | grep 'Google Cloud SDK' | cut -d ' ' -f 4)
if [[ "$(printf '%s\n' "$installed_version" "$GCloudCliVersion" | sort -V | head -n 1)" != "$GCloudCliVersion" ]]; then
    echo -e "${Yellow}gcloud CLI is either not installed or version is lower than the recommended version in ~/.axiom/interact/includes/vars.sh${Color_Off}"
    echo "Installing/updating gcloud CLI to version $GCloudCliVersion..."

    sudo apt update && sudo apt-get install apt-transport-https ca-certificates gnupg curl -qq -y
    # Add the Google Cloud GPG key and fix missing GPG key issue
    echo "Adding the Google Cloud public key..."
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg

    # Add the correct repository entry for Google Cloud SDK
    echo "Adding Google Cloud SDK to sources list..."
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

    # Clean up duplicate entries
    clean_gcloud_repos

    # Update package list and install Google Cloud SDK
    sudo apt-get update -qq
    sudo apt-get install google-cloud-sdk -y -qq
    echo "Installing Packer Plugin..."
    packer plugins install github.com/hashicorp/googlecompute
fi

# Function to check billing and API enablement after authentication
function check_gcp_billing_and_apis() {
    project_id=$(gcloud config get-value project)

    echo "Checking if billing is enabled for project [$project_id]..."

    # Check if billing is enabled
    billing_info=$(gcloud beta billing projects describe "$project_id" --format="value(billingEnabled)")
    if [[ "$billing_info" != "True" ]]; then
        echo -e "${BRed}Billing is not enabled for project [$project_id]. Please enable billing to proceed.${Color_Off}"
        echo -e "Visit https://console.cloud.google.com/billing to enable billing."
        exit 1
    fi

    # Check if necessary APIs are enabled
    echo "Checking if Cloud Resource Manager, Compute and Storage APIs are enabled..."
    gcloud services enable storage-api.googleapis.com
    gcloud services enable cloudresourcemanager.googleapis.com
    gcloud services enable compute.googleapis.com

    echo "APIs have been enabled. This may take a few minutes to propagate."
}

# Function to check and set project ID
function set_project_id() {
    project_id=$(jq -r .project_id "$service_account_key")

    if [[ "$project_id" == "null" || -z "$project_id" ]]; then
        echo -e "${BRed}Project ID is missing in the service account key. Please enter the project ID manually:${Color_Off}"
        read -p "Enter Project ID: " project_id
    fi

    # Set the project ID using gcloud
    if [[ -n "$project_id" ]]; then
        echo "Setting project ID to [$project_id]..."
        gcloud config set project "$project_id"
    else
        echo -e "${BRed}No valid project ID provided. Exiting.${Color_Off}"
        exit 1
    fi
}

# Function not currently used
# TODO implement different auth options
function auth_type() {
    echo -e "${BGreen}Please select the authentication method you would like to use for GCP:${Color_Off}"
    echo "1) Service Account Key File"
    echo "2) OAuth2 User Authentication"
    echo "3) Application Default Credentials (ADC)"
    echo -n "Select (1/2/3): "
    read auth_method

    case $auth_method in
        1)
            # Service Account Key File
            echo -e -n "${Green}Please enter the path to your service account key (required): \n>> ${Color_Off}"
            read service_account_key
            while [[ ! -f "$service_account_key" ]]; do
                echo -e "${BRed}Please provide a valid service account key file path.${Color_Off}"
                echo -e -n "${Green}Please enter the path to your service account key (required): \n>> ${Color_Off}"
                read service_account_key
            done

            # Activate service account
            gcloud auth activate-service-account --key-file="$service_account_key"

            # Set the project ID using the key file
            set_project_id
            ;;
        2)
            # OAuth2 User Authentication
            echo -e "${Green}Using OAuth2 User Authentication (gcloud auth login)...${Color_Off}"
            gcloud auth login
            ;;
        3)
            # Application Default Credentials (ADC)
            echo -e "${Green}Using Application Default Credentials (gcloud auth application-default login)...${Color_Off}"
            gcloud auth application-default login
            ;;
        *)
            echo -e "${BRed}Invalid option. Please choose 1, 2, or 3.${Color_Off}"
            gcp_setup
            exit 1
            ;;
    esac
}

function gcp_setup() {
    # Service Account Key File
    echo -e -n "${Green}Please enter the path to your service account key (required): \n>> ${Color_Off}"
    read service_account_key
    service_account_key=$(realpath "$service_account_key")
      while [[ ! -f "$service_account_key" ]]; do
      echo -e "${BRed}Please provide a valid service account key file path.${Color_Off}"
      echo -e -n "${Green}Please enter the path to your service account key (required): \n>> ${Color_Off}"
      read service_account_key
    done

    # Activate service account
    gcloud auth activate-service-account --key-file="$service_account_key"

    # Set the project ID using the key file
    set_project_id

    # Check if billing is enabled and APIs are activated after authentication
    check_gcp_billing_and_apis

    # Proceed to region and zone setup
    echo -e -n "${Green}Listing available regions: \n${Color_Off}"
    gcloud compute regions list

    default_region="us-central1"
    echo -e -n "${Green}Please enter your default region (you can always change this later with axiom-region select \$region): Default '$default_region', press enter \n>> ${Color_Off}"
    read region
    if [[ "$region" == "" ]]; then
        echo -e "${Blue}Selected default option '$default_region'${Color_Off}"
        region="$default_region"
    fi

    echo -e -n "${Green}Listing available zones for region: $region \n${Color_Off}"

    zones=$(gcloud compute zones list | grep $region | cut -d ' ' -f 1 | sort)
    echo "$zones" | tr ' ' '\n'
    default_zone="$(echo $zones | tr ' ' '\n' | head -n 1)"
    echo -e -n "${Green}Please enter your default zone:  Default '$default_zone', press enter \n>> ${Color_Off}"
    read zone
    if [[ "$zone" == "" ]]; then
        echo -e "${Blue}Selected default option '${default_zone}'${Color_Off}"
        zone="${default_zone}"
    fi
    echo -e "${BGreen}Available GCP machine types for zone: $zone${Color_Off}"

    default_size_search=n1-standard-1
    # List available machine types in the selected zone
    gcloud compute machine-types list --zones $zone --format="table(name, description)" | tee /tmp/gcp-machine-types.txt

    echo -e -n "${BWhite}Please enter the machine type: Default '$default_size_search', press enter \n>> ${Color_Off}"
    read machine_type

    # Validate the machine type
    while ! grep -q "^$machine_type" /tmp/gcp-machine-types.txt; do
        echo -e "${BRed}Invalid machine type. Please select a valid machine type from the list.${Color_Off}"
        echo -e -n "${BWhite}Please enter the machine type (e.g. 'n1-standard-1'): ${Color_Off}"
        read machine_type
    done

    # Save the selected machine type in axiom.json
    if [[ "$machine_type" == "" ]]; then
        echo -e "${Blue}Selected default option 'n1-standard-1'${Color_Off}"
        machine_type="$default_size_search"
    else
        echo -e "${BGreen}Selected machine type: $machine_type${Color_Off}"
    fi

    check_and_create_firewall_rule

    # Generate the profile data with the correct keys
    data="$(echo "{\"service_account_key\":\"$service_account_key\",\"project\":\"$project_id\",\"physical_region\":\"$region\",\"default_size\":\"$machine_type\",\"region\":\"$zone\",\"provider\":\"gcp\"}")"

    echo -e "${BGreen}Profile settings below: ${Color_Off}"
    echo "$data" | jq '.gcp_service_account_key = "**********************"'
    echo -e "${BWhite}Press enter if you want to save these to a new profile, type 'r' if you wish to start again.${Color_Off}"
    read ans

    if [[ "$ans" == "r" ]]; then
        $0
        exit
    fi

    echo -e -n "${BWhite}Please enter your profile name (e.g. 'gcp', must be all lowercase/no specials)\n>> ${Color_Off}"
    read title

    if [[ "$title" == "" ]]; then
        title="gcp"
        echo -e "${BGreen}Named profile 'gcp'${Color_Off}"
    fi

    # Save the profile data in axiom.json
    echo "$data" | jq > "$AXIOM_PATH/accounts/$title.json"
    echo -e "${BGreen}Saved profile '$title' successfully!${Color_Off}"
    $AXIOM_PATH/interact/axiom-account $title
}

gcp_setup
