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

installed_version=$(aws --version 2>/dev/null | cut -d ' ' -f 1 | cut -d '/' -f 2)

# Check if the installed version matches the recommended version
if [[ "$(printf '%s\n' "$installed_version" "$AWSCliVersion" | sort -V | head -n 1)" != "$AWSCliVersion" ]]; then
    echo -e "${Yellow}AWS CLI is either not installed or version is lower than the recommended version in ~/.axiom/interact/includes/vars.sh${Color_Off}"

    # Determine the OS type and handle installation accordingly
    if [[ $BASEOS == "Mac" ]]; then
        echo -e "${BGreen}Installing/Updating AWS CLI on macOS...${Color_Off}"
        curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
        sudo installer -pkg AWSCLIV2.pkg -target /
        rm AWSCLIV2.pkg

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

        # Install AWS CLI based on specific Linux distribution
        if [[ $OS == "Ubuntu" ]] || [[ $OS == "Debian" ]] || [[ $OS == "Linuxmint" ]] || [[ $OS == "Parrot" ]] || [[ $OS == "Kali" ]] || [[ $OS == "unknown-Linux" ]] || [[ $OS == "UbuntuWSL" ]]; then
            echo -e "${BGreen}Installing/Updating AWS CLI on $OS...${Color_Off}"
            curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
            cd /tmp
            unzip awscliv2.zip
            sudo ./aws/install
            rm -rf /tmp/aws
            rm /tmp/awscliv2.zip
        elif [[ $OS == "Fedora" ]]; then
            echo -e "${BGreen}Installing/Updating AWS CLI on Fedora...${Color_Off}"
            sudo dnf install -y unzip
            curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
            cd /tmp
            unzip awscliv2.zip
            sudo ./aws/install
            rm -rf /tmp/aws
            rm /tmp/awscliv2.zip
        else
            echo -e "${BRed}Unsupported Linux distribution: $OS${Color_Off}"
        fi
    fi

    echo "AWS CLI updated to version $AWSCliVersion."
else
    echo "AWS CLI is already at or above the recommended version $AWSCliVersion."
fi

function awssetup(){

while true; do
    echo -e -n "${Green}Do you plan to authenticate using and AWS Access and Secret Keys? y/n: \n>> ${Color_Off}"
    read ACCESS_KEY_AUTH

    if [[ "$ACCESS_KEY_AUTH" == "y" ]] || [[ "$ACCESS_KEY_AUTH" == "yes" ]]; then
        
        echo -e -n "${Green}Please enter your AWS Access Key ID (required): \n>> ${Color_Off}"
        read ACCESS_KEY
        while [[ "$ACCESS_KEY" == "" ]]; do
          echo -e "${BRed}Please provide an AWS Access KEY ID, your entry contained no input.${Color_Off}"
          echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
          read ACCESS_KEY
        done

        echo -e -n "${Green}Please enter your AWS Secret Access Key (required): \n>> ${Color_Off}"
        read SECRET_KEY
        while [[ "$SECRET_KEY" == "" ]]; do
          echo -e "${BRed}Please provide an AWS Secret Access Key, your entry contained no input.${Color_Off}"
          echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
          read SECRET_KEY
        done

        aws configure set aws_access_key_id "$ACCESS_KEY"
        aws configure set aws_secret_access_key "$SECRET_KEY"
        break

    elif [[ "$ACCESS_KEY_AUTH" == "n" ]] || [[ "$ACCESS_KEY_AUTH" == "no" ]]; then
        # Print available aws profiles
        echo -e "${BGreen}Printing Available Profiles:${Color_Off}"
        (aws configure list-profiles) | column -t

        # Prompt user to choose a profile
        echo -e -n "${Green}Please choose a profile.\n>> ${Color_Off}"
        read PROFILE

        # Export so subsequent commands can use the correct profile
        export AWS_PROFILE=$PROFILE
        break
    else
        echo -e "${BRed}Invalid response. Please enter 'y' for yes or 'n' for no.${Color_Off}"
    fi
done

aws configure set output json

# Find all available VPCs
aws_vpcs="$(aws ec2 describe-vpcs)"

# Check for Default VPC
if [ "$(jq -rC '.Vpcs | any(.IsDefault == true)' <<< "$aws_vpcs")" == true ]; then
  echo -e "${Green}It appears the default VPC is available. Automatically using to build Images. ${Color_Off}"
  aws_vpc_id="$(jq -C '.Vpcs[] | select(.IsDefault == true).VpcId' <<< $aws_vpcs)"

else
  # Print available aws VPCs
  echo -e "${BGreen}Printing Available VPCs:${Color_Off}"
  (
    jq -rC '.Vpcs | map({VpcId, "Name":(.Tags | if any(.Key == "Name") then (.[] | select(.Key == "Name").Value) else "null" end), OwnerId, IsDefault, State, CidrBlock}) | (.[0] | keys_unsorted), (.[] | [.[]]) | @tsv' <<< $aws_vpcs
  ) | column -t
        
  # Prompt user to select a VPC
  echo -e -n "${Green}Please choose a VpcId to deploy instances to.\n>> ${Color_Off}"
  read aws_vpc_id
fi

# Find all available subnets within selected VPC
aws_subnets="$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$aws_vpc_id")"

# Check for Default Subnets
if [ "$(jq -rC '.Subnets | any(.DefaultForAz == true)' <<< "$aws_subnets")" == true ]; then
  echo "Found Default Subnet"
else
  # Print available aws Subnets
  echo -e "${BGreen}Printing Available Subnets:${Color_Off}"
  (
    jq -rC '.Subnets | map({SubnetId,"Name":(.Tags | if any(.Key == "Name") then (.[] | select(.Key == "Name").Value | gsub(" ";"")) else "null" end), CidrBlock, OwnerId, State})| (.[0] | keys_unsorted), (.[] | [.[]]) | @tsv' <<< $aws_subnets
  ) | column -t
        
  # Prompt user to select a Subnet
  echo -e -n "${Green}Please choose a SubnetId to build instances within.\n>> ${Color_Off}"
  read aws_subnet_id
fi

default_region="us-west-2"
echo -e -n "${Green}Please enter your default region (you can always change this later with axiom-region select \$region): Default '$default_region', press enter \n>> ${Color_Off}"
read region
	if [[ "$region" == "" ]]; then
	 echo -e "${Blue}Selected default option '$default_region'${Color_Off}"
	 region="$default_region"
        fi

echo -e -n "${Green}Please enter your default size (you can always change this later with axiom-sizes select \$size): Default 't2.micro', press enter \n>> ${Color_Off}"
read size
	if [[ "$size" == "" ]]; then
	 echo -e "${Blue}Selected default option 't2.micro'${Color_Off}"
         size="t2.micro"
        fi

echo -e -n "${Green}Please enter your default disk size in GB (you can always change this later with axiom-disks select \$disk_size): Default '20', press enter \n>> ${Color_Off}"
read disk_size
if [[ "$disk_size" == "" ]]; then
  disk_size="20"
  echo -e "${Blue}Selected default option '20'${Color_Off}"
fi

if [ -z "${PROFILE}" ]; then
  aws configure set default.region "$region"
else
  aws configure set "$PROFILE.region" "$region"
fi

# Print available security groups
echo -e "${BGreen}Printing Available Security Groups:${Color_Off}"
(
  echo -e "GroupName\tGroupId\tOwnerId\tVpcId\tFromPort\tToPort"
  aws ec2 describe-security-groups \
    --query 'SecurityGroups[*].{GroupName:GroupName,GroupId:GroupId,OwnerId:OwnerId,VpcId:VpcId,FromPort:IpPermissions[0].FromPort,ToPort:IpPermissions[0].ToPort}' \
    --output json | jq -r '.[] | [.GroupName, .GroupId, .OwnerId, .VpcId, .FromPort, .ToPort] | @tsv'
) | column -t

# Prompt user to enter a security group name
echo -e -n "${Green}Please enter a security group name above or press enter to create a new security group with a random name \n>> ${Color_Off}"
read SECURITY_GROUP

# We will track the "last" group_id and group_owner_id found or created
# so the script can still store them as before.
last_group_id=""
group_owner_id=""

# If no security group name is provided, generate one (same name will be used in all regions)
if [[ "$SECURITY_GROUP" == "" ]]; then
  axiom_sg_random="axiom-$(date +%m-%d_%H-%M-%S-%1N)"
  SECURITY_GROUP=$axiom_sg_random
  echo -e "${BGreen}No Security Group provided, will create a new one: '$SECURITY_GROUP' in each region.${Color_Off}"
fi

while true; do
    echo -e -n "${Green}Create or reuse the security group '$SECURITY_GROUP' in ALL AWS regions? y/n: \n>> ${Color_Off}"
    read REGION_SELECTION

    if [[ "$REGION_SELECTION" == "y" ]] || [[ "$REGION_SELECTION" == "yes" ]]; then
        all_regions=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)
        echo -e "${BGreen}Creating or reusing the security group '$SECURITY_GROUP' in ALL AWS regions...${Color_Off}"
        break
    elif [[ "$REGION_SELECTION" == "n" ]] || [[ "$REGION_SELECTION" == "no" ]]; then
        all_regions=$(aws ec2 describe-regions --region-names "$region" --query "Regions[].RegionName" --output text)
        echo -e "${BGreen}Creating or reusing the security group '$SECURITY_GROUP' in only the AWS $region region...${Color_Off}"
        break
    else
        echo -e "${BRed}Invalid response. Please enter 'y' for yes or 'n' for no.${Color_Off}"
    fi
done

first_group_id=""
first_owner_id=""

for r in $all_regions; do
(
  echo -e "\n${BGreen}--- Region: $r ---${Color_Off}"

  existing_group_id=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$SECURITY_GROUP" \
    --region "$r" \
    --query "SecurityGroups[*].GroupId" \
    --output text 2>/dev/null)

  if [[ "$existing_group_id" == "None" ]] || [[ -z "$existing_group_id" ]]; then
    echo -e "${BGreen}Creating Security Group '$SECURITY_GROUP' in region $r...${Color_Off}"
    create_output=$(aws ec2 create-security-group \
      --group-name "$SECURITY_GROUP" \
      --description "Axiom SG" \
      --region "$r" 2>&1)

    if [[ $? -ne 0 ]]; then
      echo -e "${BRed}Failed to create security group in region $r: $create_output${Color_Off}"
      exit 0
    fi

    new_group_id=$(echo "$create_output" | jq -r '.GroupId' 2>/dev/null)
    if [[ "$new_group_id" == "null" ]]; then
      echo -e "${BRed}Could not parse GroupId from creation output. Raw output:\n$create_output${Color_Off}"
      exit 0
    fi

    echo -e "${BGreen}Created Security Group: $new_group_id in region $r${Color_Off}"
    group_id="$new_group_id"
  else
    echo -e "${BGreen}Security Group '$SECURITY_GROUP' already exists in region $r (GroupId: $existing_group_id).${Color_Off}"
    group_id="$existing_group_id"
  fi

 # Attempt to add the rule (port 2266 for 0.0.0.0/0)
 # If it already exists, AWS will throw an error that we can catch
  group_rules=$(aws ec2 authorize-security-group-ingress \
    --group-id "$group_id" \
    --protocol tcp \
    --port 2266 \
    --cidr 0.0.0.0/0 \
    --region "$r" 2>&1)
  cmd_exit_status=$?

  if [[ $cmd_exit_status -ne 0 ]]; then
    if echo "$group_rules" | grep -q "InvalidPermission.Duplicate"; then
      echo -e "${BGreen}Ingress rule already exists in region $r.${Color_Off}"
    else
      echo -e "${BRed}Failed to add rule in region $r: $group_rules${Color_Off}"
    fi
  else
    echo -e "${BGreen}Rule added successfully in region $r.${Color_Off}"
  fi

  owner_id=$(aws ec2 describe-security-groups \
    --group-ids "$group_id" \
    --region "$r" \
    --query "SecurityGroups[*].OwnerId" \
    --output text 2>/dev/null)

  if [[ -z "$first_group_id" ]]; then
    mkdir -p "$AXIOM_PATH/tmp/"
    echo "$group_id" > "$AXIOM_PATH/tmp/sg_id"
    echo "$owner_id" > "$AXIOM_PATH/tmp/sg_owner"
  fi
) &
done
wait

# Load stored first group id and owner id
if [[ -f "$AXIOM_PATH/tmp/sg_id" ]]; then
  last_group_id=$(cat "$AXIOM_PATH/tmp/sg_id")
  group_owner_id=$(cat "$AXIOM_PATH/tmp/sg_owner")
  rm "$AXIOM_PATH/tmp/sg_id" "$AXIOM_PATH/tmp/sg_owner"
else
  echo -e "${BRed}Could not determine final group ID. No group was created successfully.${Color_Off}"
  exit 1
fi

if [ -z "${PROFILE}" ]; then
  data="{\"aws_access_key\":\"$ACCESS_KEY\",\"aws_secret_access_key\":\"$SECRET_KEY\",\"aws_vpc_id\":\"$aws_vpc_id\",\"aws_subnet_id\":\"$aws_subnet_id\",\"group_owner_id\":\"$group_owner_id\",\"security_group_name\":\"$SECURITY_GROUP\",\"security_group_id\":\"$last_group_id\",\"region\":\"$region\",\"provider\":\"aws\",\"default_size\":\"$size\",\"default_disk_size\":\"$disk_size\"}"
else
  data="{\"aws_profile\":\"$PROFILE\",\"aws_vpc_id\":\"$aws_vpc_id\",\"aws_subnet_id\":\"$aws_subnet_id\",\"group_owner_id\":\"$group_owner_id\",\"security_group_name\":\"$SECURITY_GROUP\",\"security_group_id\":\"$last_group_id\",\"region\":\"$region\",\"provider\":\"aws\",\"default_size\":\"$size\",\"default_disk_size\":\"$disk_size\"}"
fi


echo -e "${BGreen}Profile settings below: ${Color_Off}"
echo "$data" | jq 'if .aws_secret_access_key? then .aws_secret_access_key="*************************************" else . end'
echo -e "${BWhite}Press enter if you want to save these to a new profile, type 'r' if you wish to start again.${Color_Off}"
read ans

if [[ "$ans" == "r" ]];
then
    $0
    exit
fi

echo -e -n "${BWhite}Please enter your profile name (e.g 'aws', must be all lowercase/no specials)\n>> ${Color_Off}"
read title

if [[ "$title" == "" ]]; then
    title="aws"
    echo -e "${BGreen}Named profile 'aws'${Color_Off}"
fi

echo "$data" | jq > "$AXIOM_PATH/accounts/$title.json"
echo -e "${BGreen}Saved profile '$title' successfully!${Color_Off}"
$AXIOM_PATH/interact/axiom-account "$title"

}

awssetup
