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
if [[ "$installed_version" != $AWSCliVersion ]]; then
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

echo -e -n "${Green}Please enter your AWS Access Key ID (required): \n>> ${Color_Off}"
read ACCESS_KEY
while [[ "$ACCESS_KEY" == "" ]]; do
	echo -e "${BRed}Please provide a AWS Access KEY ID, your entry contained no input.${Color_Off}"
	echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
	read ACCESS_KEY
done

echo -e -n "${Green}Please enter your AWS Secret Access Key (required): \n>> ${Color_Off}"
read SECRET_KEY
while [[ "$SECRET_KEY" == "" ]]; do
	echo -e "${BRed}Please provide a AWS Secret Access Key, your entry contained no input.${Color_Off}"
	echo -e -n "${Green}Please enter your token (required): \n>> ${Color_Off}"
	read SECRET_KEY
done

aws configure set aws_access_key_id "$ACCESS_KEY"
aws configure set aws_secret_access_key "$SECRET_KEY"

default_region="us-west-2"
echo -e -n "${Green}Please enter your default region (you can always change this later with axiom-region select \$region): Default '$default_region', press enter \n>> ${Color_Off}"
read region
	if [[ "$region" == "" ]]; then
	 echo -e "${Blue}Selected default option '$default_region'${Color_Off}"
	 region="$default_region"
        fi
echo -e -n "${Green}Please enter your default size (you can always change this later with axiom-sizes select \$size): Default 't2.medium', press enter \n>> ${Color_Off}"
read size
	if [[ "$size" == "" ]]; then
	 echo -e "${Blue}Selected default option 't2.medium'${Color_Off}"
         size="t2.medium"
        fi

aws configure set default.region "$region"

# Print available security groups
echo -e "${BGreen}Printing Available Security Groups:${Color_Off}"
(echo -e "GroupName\tGroupId\tOwnerId\tVpcId\tFromPort\tToPort" && aws ec2 describe-security-groups --query 'SecurityGroups[*].{GroupName:GroupName,GroupId:GroupId,OwnerId:OwnerId,VpcId:VpcId,FromPort:IpPermissions[0].FromPort,ToPort:IpPermissions[0].ToPort}' --output json | jq -r '.[] | [.GroupName, .GroupId, .OwnerId, .VpcId, .FromPort, .ToPort] | @tsv') | column -t

# Prompt user to enter a security group name
echo -e -n "${Green}Please enter a security group name above or press enter to create a new security group with a random name \n>> ${Color_Off}"
read SECURITY_GROUP

# If no security group name is provided, create a new one with a random name
if [[ "$SECURITY_GROUP" == "" ]]; then
  axiom_sg_random="axiom-$(date +%m-%d_%H-%M-%S-%1N)"
  SECURITY_GROUP=$axiom_sg_random
  echo -e "${BGreen}Creating an Axiom Security Group: ${Color_Off}"
  aws ec2 delete-security-group --group-name "$SECURITY_GROUP" > /dev/null 2>&1
  sc=$(aws ec2 create-security-group --group-name "$SECURITY_GROUP" --description "Axiom SG")
  group_id=$(echo "$sc" | jq -r '.GroupId')
  echo -e "${BGreen}Created Security Group: $group_id ${Color_Off}"
else
  # Use the existing security group
  echo -e "${BGreen}Using Security Group: $SECURITY_GROUP ${Color_Off}"
  group_id=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SECURITY_GROUP" --query "SecurityGroups[*].GroupId" --output text)

  if [ -z "$group_id" ]; then
    echo -e "${BGreen}Security Group '$SECURITY_GROUP' not found. Exiting.${Color_Off}"
    exit 1
  fi
fi

# Attempt to add the rule
group_rules=$(aws ec2 authorize-security-group-ingress --group-id "$group_id" --protocol tcp --port 2266 --cidr 0.0.0.0/0 2>&1)

# Check if the rule already exists
if echo "$group_rules" | grep -q "InvalidPermission.Duplicate"; then
  echo -e "${BGreen}The rule already exists for Security Group ID: $group_id ${Color_Off}"

  group_owner_id=$(aws ec2 describe-security-groups --group-ids "$group_id" --query "SecurityGroups[*].OwnerId" --output text)
  echo -e "${BGreen}GroupOwnerId: $group_owner_id, GroupId: $group_id ${Color_Off}"
else
  echo -e "${BGreen}Rule added successfully to Security Group: $group_id ${Color_Off}"

  group_owner_id=$(aws ec2 describe-security-groups --group-ids "$group_id" --query "SecurityGroups[*].OwnerId" --output text)
  echo -e "${BGreen}GroupOwnerId: $group_owner_id, GroupId: $group_id ${Color_Off}"
fi

data="$(echo "{\"aws_access_key\":\"$ACCESS_KEY\",\"aws_secret_access_key\":\"$SECRET_KEY\",\"group_owner_id\":\"$group_owner_id\",\"security_group_id\":\"$group_id\",\"region\":\"$region\",\"provider\":\"aws\",\"default_size\":\"$size\"}")"

echo -e "${BGreen}Profile settings below: ${Color_Off}"
echo $data | jq '.aws_secret_access_key = "*************************************"'
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

awssetup
