#!/bin/bash

AXIOM_PATH="$HOME/.axiom"

###################################################################
#  Create Instance is likely the most important provider function :)
#  needed for init and fleet
#
create_instance() {
	name="$1"
	image_id="$2"
	size_slug="$3"
	region="$4"
	boot_script="$5"
	sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"
        security_group_id="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.security_group_id')"

	aws ec2 run-instances --image-id "$image_id" --count 1 --instance-type "$size" --region "$region" --security-group-ids "$security_group_id" --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name}]" 2>&1 >> /dev/null

	sleep 260
}

###################################################################
# deletes instances by name, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instances() {
    names="$1"
    force="$2"
    instance_ids=()
    instance_names=()

    # Convert names to an array for processing
    name_array=($names)

    # Make a single AWS CLI call to get all instances and filter by provided names
    all_instances=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId, Tags[?Key=='Name'].Value | [0]]" --output text)

    # Iterate over the AWS CLI output and filter by the provided names
    while read -r instance_id instance_name; do
        for name in "${name_array[@]}"; do
            if [[ "$instance_name" == "$name" ]]; then
                instance_ids+=("$instance_id")
                instance_names+=("$instance_name")
            fi
        done
    done <<< "$all_instances"

    # Force deletion: Delete all instances without prompting
    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting: ${instance_names[@]}...${Color_Off}"
        aws ec2 terminate-instances --instance-ids "${instance_ids[@]}" >/dev/null 2>&1

    # Prompt for each instance if force is not true
    else
        # Collect instances for deletion after user confirmation
        confirmed_instance_ids=()
        confirmed_instance_names=()

        for i in "${!instance_ids[@]}"; do
            instance_id="${instance_ids[$i]}"
            instance_name="${instance_names[$i]}"

            echo -e -n "Are you sure you want to delete instance '$instance_name' (ID: $instance_id) (y/N) - default NO: "
            read ans
            if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                confirmed_instance_ids+=("$instance_id")
                confirmed_instance_names+=("$instance_name")
            else
                echo "Deletion aborted for instance '$instance_name' (ID: $instance_id)."
            fi
        done

        # Delete confirmed instances in bulk
        if [ ${#confirmed_instance_ids[@]} -gt 0 ]; then
            echo -e "${Red}Deleting: ${confirmed_instance_names[@]}...${Color_Off}"
            aws ec2 terminate-instances --instance-ids "${confirmed_instance_ids[@]}" >/dev/null 2>&1
        fi
    fi
}

###################################################################
# Instances functions
# used by many functions in this file
instances() {
        aws ec2 describe-instances
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
        name="$1"
        instances | jq -r ".Reservations[].Instances[] | select(.Tags?[]?.Value==\"$name\") | .PublicIpAddress"
}

# used by axiom-select axiom-ls
instance_list() {
        instances | jq -r '.Reservations[].Instances[].Tags?[]?.Value?'
}

# used by axiom-ls
instance_pretty() {

	type="$(jq -r .default_size "$AXIOM_PATH/axiom.json")"    
	costs=$(curl -sL 'ec2.shop' -H 'accept: json')
	header="Instance,Primary IP,Backend IP,Region,Type,Status,\$/M"
	fields=".Reservations[].Instances[] | select(.State.Name != \"terminated\") | [.Tags?[]?.Value, .PublicIpAddress, .PrivateIpAddress, .Placement.AvailabilityZone, .InstanceType, .State.Name] | @csv"
        data=$(instances|(jq -r "$fields"|sort -k1))
	numInstances=$(echo "$data"|grep -v '^$'|wc -l)

	if [[ $numInstances -gt 0  ]];then
	 cost=$(echo "$costs"|jq ".Prices[] | select(.InstanceType == \"$type\").MonthlyPrice")
	 data=$(echo "$data" | sed "s/$/,\"$cost\" /")
	 totalCost=$(echo  "$cost * $numInstances"|bc)
	fi
	footer="_,_,_,Instances,$numInstances,Total,\$$totalCost"
	(echo "$header" && echo "$data" && echo "$footer") | sed 's/"//g' | column -t -s, 
}

###################################################################
#  Dynamically generates axiom's SSH config based on your cloud inventory
#  Choose between generating the sshconfig using private IP details, public IP details or optionally lock
#  Lock will never generate an SSH config and only used the cached config ~/.axiom/.sshconfig 
#  Used for axiom-exec axiom-fleet axiom-ssh
#
generate_sshconfig() {
accounts=$(ls -l "$AXIOM_PATH/accounts/" | grep "json" | grep -v 'total ' | awk '{ print $9 }' | sed 's/\.json//g')
current=$(readlink -f "$AXIOM_PATH/axiom.json" | rev | cut -d / -f 1 | rev | cut -d . -f 1)> /dev/null 2>&1
sshnew="$AXIOM_PATH/.sshconfig.new$RANDOM"
droplets="$(instances)"
echo -n "" > $sshnew
echo -e "\tServerAliveInterval 60\n" >> $sshnew
sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"
echo -e "IdentityFile $HOME/.ssh/$sshkey" >> $sshnew
generate_sshconfig="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.generate_sshconfig')"

if [[ "$generate_sshconfig" == "private" ]]; then

 echo -e "Warning your SSH config generation toggle is set to 'Private' for account : $(echo $current)."
 echo -e "axiom will always attempt to SSH into the instances from their private backend network interface. To revert run: axiom-ssh --just-generate"
 for name in $(echo "$droplets" | jq -r '.Reservations[].Instances[].Tags?[]?.Value')
 do
 ip=$(echo "$droplets" | jq -r ".Reservations[].Instances[] | select(.Tags?[]?.Value==\"$name\") | .PublicIpAddress")
 status=$(echo "$droplets" | jq -r ".Reservations[].Instances[] | select(.Tags?[]?.Value==\"$name\") | .State.Name")
 if [[ "$status" == "running" ]]; then
        echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew
 fi
 done
 mv $sshnew $AXIOM_PATH/.sshconfig

 elif [[ "$generate_sshconfig" == "cache" ]]; then 
 echo -e "Warning your SSH config generation toggle is set to 'Cache' for account : $(echo $current)."
 echo -e "axiom will never attempt to regenerate the SSH config. To revert run: axiom-ssh --just-generate"
        
 # If anything but "private" or "cache" is parsed from the generate_sshconfig in account.json, generate public IPs only
 #
 else
 for name in $(echo "$droplets" | jq -r '.Reservations[].Instances[].Tags?[]?.Value')
 do
 ip=$(echo "$droplets" | jq -r ".Reservations[].Instances[] | select(.Tags?[]?.Value==\"$name\") | .PublicIpAddress")
 status=$(echo "$droplets" | jq -r ".Reservations[].Instances[] | select(.Tags?[]?.Value==\"$name\") | .State.Name")
 if [[ "$status" == "running" ]]; then
        echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew
 fi
 done
 mv $sshnew $AXIOM_PATH/.sshconfig
fi
}

###################################################################
# takes any number of arguments, each argument should be an instance or a glob, say 'omnom*', returns a sorted list of instances based on query
# $ query_instances 'john*' marin39
# Resp >>  john01 john02 john03 john04 nmarin39
# used by axiom-ls axiom-select axiom-fleet axiom-rm axiom-power
#
query_instances() {
        droplets="$(instances)"
        selected=""

        for var in "$@"; do
                if [[ "$var" =~ "*" ]]
                then
                        var=$(echo "$var" | sed 's/*/.*/g')
                        selected="$selected $(echo $droplets | jq -r '.Reservations[].Instances[] | select(.State.Name != "terminated") | .Tags?[]?.Value' | grep "$var")"
                else
                        if [[ $query ]];
                        then
                                query="$query\|$var"
                        else
                                query="$var"
                        fi
                fi
        done

        if [[ "$query" ]]
        then
                selected="$selected $(echo $droplets | jq -r '.Reservations[].Instances[].Tags?[]?.Value' | grep -w "$query")"
        else
                if [[ ! "$selected" ]]
                then
                        echo -e "${Red}No instance supplied, use * if you want to delete all instances...${Color_Off}"
                        exit
                fi
        fi

        selected=$(echo "$selected" | tr ' ' '\n' | sort -u)
        echo -n $selected
}

###################################################################
#
# used by axiom-fleet axiom-init
get_image_id() {
        query="$1"
        images=$(aws ec2 describe-images --query 'Images[*]' --owners self)
        name=$(echo $images| jq -r '.[].Name' | grep -wx "$query" | tail -n 1)
        id=$(echo $images |  jq -r ".[] | select(.Name==\"$name\") | .ImageId")
        echo $id
}

###################################################################
# Manage snapshots
# used for axiom-images
#
# get JSON data for snapshots
snapshots() {
        aws ec2 describe-images --query 'Images[*]' --owners self 
}

# used by axiom-images
get_snapshots()
{
    header="Name,Creation,Image ID,Size(GB)"
    footer="_,_,_,_"
    fields=".[] | [.Name, .CreationDate, .ImageId, (.BlockDeviceMappings[] | select(.Ebs) | (.Ebs.VolumeSize | tostring))] | @csv"
    data=$(aws ec2 describe-images --query 'Images[*]' --owners self)
        (echo "$header" && echo "$data" | (jq -r "$fields"|sort -k1) && echo "$footer") | sed 's/"//g' | column -t -s, 
}

# Delete a snapshot by its name
# used by  axiom-images
delete_snapshot() {
    name="$1"
    image_id=$(get_image_id "$name")
    snapshot_id="$(aws ec2 describe-images --image-id "$image_id" --query 'Images[*].BlockDeviceMappings[*].Ebs.SnapshotId' --output text)"
    aws ec2 deregister-image --image-id "$image_id"
    aws ec2 delete-snapshot --snapshot-id "$snapshot_id"
}

# axiom-images
create_snapshot() {
        instance="$1"
        snapshot_name="$2"
	aws ec2 create-image --instance-id "$(instance_id $instance)" --name $snapshot_name
}

###################################################################
# Get data about regions
# used by axiom-regions
list_regions() {
    aws ec2 describe-regions --query "Regions[*].RegionName" | jq -r '.[]'

}

# used by axiom-regions
regions() {
    aws ec2 describe-regions --query "Regions[*].RegionName" | jq -r '.[]'
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
  instance_name="$1"
  id=$(instance_id "$instance_name")
  aws ec2 start-instances --instance-ids "$id"
}

# axiom-power 
poweroff() {
  instance_name="$1"
  id=$(instance_id "$instance_name")
  aws ec2 stop-instances --instance-ids "$id"  | jq -r '.StoppingInstances[0].CurrentState.Name'
}

# axiom-power
reboot() {
  instance_name="$1"
  id=$(instance_id "$instance_name")
  aws ec2 reboot-instances --instance-ids "$id"
}

# axiom-power axiom-images
instance_id() {
	name="$1"
	instances | jq -r ".Reservations[].Instances[] | select(.Tags?[]?.Value==\"$name\") | .InstanceId"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
(
  echo -e "InstanceType\tMemory\tVCPUS\tCost"
  curl -sL 'ec2.shop' -H 'accept: json' | jq -r '.Prices[] | [.InstanceType, .Memory, .VCPUS, .Cost] | @tsv'
) | awk '
BEGIN { 
  FS="\t"; 
  OFS="\t";
  # Define column widths
  width1 = 20; # InstanceType
  width2 = 10; # Memory
  width3 = 5;  # VCPUS
  width4 = 10; # Cost
}
{
  # Remove "GiB" from Memory column
  gsub(/GiB/, "", $2);
  printf "%-*s %-*s %-*s %-*s\n", width1, $1, width2, $2, width3, $3, width4, $4
}
' | column -t
}
