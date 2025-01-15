#!/bin/bash

AXIOM_PATH="$HOME/.axiom"

###################################################################
#  Create Instance is likely the most important provider function :)
#  needed for init and fleet
#
create_instance() {
    name="$1"
    image_id="$2"
    size="$3"
    region="$4"
    user_data="$5"
    security_group_name="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.security_group_name')"
    security_group_id="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.security_group_id')"

    # Determine whether to use security_group_name or security_group_id
    if [[ -n "$security_group_name" && "$security_group_name" != "null" ]]; then
        security_group_option="--security-groups $security_group_name"
    elif [[ -n "$security_group_id" && "$security_group_id" != "null" ]]; then
        security_group_option="--security-group-ids $security_group_id"
    else
        echo "Error: Both security_group_name and security_group_id are missing or invalid in axiom.json."
        return 1
    fi

    # Launch the instance using the determined security group option
    aws ec2 run-instances \
        --image-id "$image_id" \
        --count 1 \
        --instance-type "$size" \
        --region "$region" \
        $security_group_option \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name}]" \
        --user-data "$user_data" 2>&1 >> /dev/null

     if [[ $? -ne 0 ]]; then
        echo "Error: Failed to launch instance '$name' in region '$region'."
        return 1
     fi

    # Allow time for instance initialization if needed
    sleep 260
}

###################################################################
# deletes instance, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instance() {
    name="$1"
    id="$(instance_id "$name")"

    if [ "$force" != "true" ]; then
        read -p "Are you sure you want to delete instance '$name'? (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Instance deletion aborted."
            return 1
        fi
    fi

    aws ec2 terminate-instances --instance-ids "$id" 2>&1 >> /dev/null
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
    costs=$(curl -sL 'ec2.shop' -H 'accept: json')
    header="Instance,Primary IP,Backend IP,Region,Type,Status,\$/M"
    fields=".Reservations[].Instances[]
            | select(.State.Name != \"terminated\")
            | [.Tags?[]?.Value, .PublicIpAddress, .PrivateIpAddress,
               .Placement.AvailabilityZone, .InstanceType, .State.Name]
            | @csv"

    data=$(instances | jq -r "$fields" | sort -k1)
    numInstances=$(echo "$data" | grep -v '^$' | wc -l)

    if [[ $numInstances -gt 0 ]]; then
        types=$(echo "$data" | cut -d, -f5 | sort | uniq)
        totalCost=0
        updatedData=""

        while read -r type; do
            # Strip any extra quotes from the instance type
            type=$(echo "$type" | tr -d '"')

            # Fetch monthly cost from the JSON API, default to 0 if not found
            cost=$(echo "$costs" \
                   | jq -r ".Prices[] | select(.InstanceType == \"$type\").MonthlyPrice")
            cost=${cost:-0}

            # Match lines containing the quoted type in the CSV data
            typeData=$(echo "$data" | grep ",\"$type\",")

            # Append cost to each matching row
            while IFS= read -r row; do
                updatedData+="$row,\"$cost\"\n"
            done <<< "$typeData"

            # Update total cost based on count of matching rows
            typeCount=$(echo "$typeData" | grep -v '^$' | wc -l)
            totalCost=$(echo "$totalCost + ($cost * $typeCount)" | bc)
        done <<< "$types"

        # Replace original data with updated rows (removing any empty lines)
        data=$(echo -e "$updatedData" | sed '/^\s*$/d')
    fi

    footer="_,_,_,Instances,$numInstances,Total,\$$totalCost"
    (echo "$header"; echo "$data"; echo "$footer") \
        | sed 's/"//g' \
        | column -t -s,
}

###################################################################
#  Dynamically generates axiom's SSH config based on your cloud inventory
#  Choose between generating the sshconfig using private IP details,
#  public IP details, or optionally lock
#  Lock will never generate an SSH config and only use the cached config ~/.axiom/.sshconfig
#  Used for axiom-exec axiom-fleet axiom-ssh
#
generate_sshconfig() {
    sshnew="$AXIOM_PATH/.sshconfig.new$RANDOM"
    sshkey=$(jq -r '.sshkey' < "$AXIOM_PATH/axiom.json")
    generate_sshconfig=$(jq -r '.generate_sshconfig' < "$AXIOM_PATH/axiom.json")
    droplets="$(instances)"

    # handle lock/cache mode
    if [[ "$generate_sshconfig" == "lock" ]] || [[ "$generate_sshconfig" == "cache" ]] ; then
        echo -e "${BYellow}Using cached SSH config. No regeneration performed. To revert run:${Color_Off} ax ssh --just-generate"
        return 0
    fi

    # handle private mode
    if [[ "$generate_sshconfig" == "private" ]] ; then
        echo -e "${BYellow}Using instances private Ips for SSH config. To revert run:${Color_Off} ax ssh --just-generate"
    fi

    # create empty SSH config
    echo -n "" > "$sshnew"
    {
        echo -e "ServerAliveInterval 60"
        echo -e "IdentityFile $HOME/.ssh/$sshkey"
    } >> "$sshnew"

    name_count_str=""

    # Helper to get the current count for a given name
    get_count() {
        local key="$1"
        # Find "key:<number>" in name_count_str and echo just the number
        echo "$name_count_str" | grep -oE "$key:[0-9]+" | cut -d: -f2 | tail -n1
    }

    # Helper to set/update the current count for a given name
    set_count() {
        local key="$1"
        local new_count="$2"
        # Remove old 'key:<number>' entries
        name_count_str="$(echo "$name_count_str" | sed "s/$key:[0-9]*//g")"
        # Append updated entry
        name_count_str="$name_count_str $key:$new_count"
    }

    echo "$droplets" | jq -c '.Reservations[].Instances[]?' | while read -r instance; do
        # extract fields
        name=$(echo "$instance" | jq -r '.Tags[]? | select(.Key=="Name") | .Value // empty' 2>/dev/null | head -n 1)
        public_ip=$(echo "$instance" | jq -r '.PublicIpAddress? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$instance" | jq -r '.PrivateIpAddress? // empty' 2>/dev/null  | head -n 1)

        # skip if name is empty
        if [[ -z "$name" ]] ; then
            continue
        fi

        # select IP based on configuration mode
        if [[ "$generate_sshconfig" == "private" ]]; then
            ip="$private_ip"
        else
            ip="$public_ip"
        fi

        # skip if no IP is available
        if [[ -z "$ip" ]]; then
            continue
        fi

        current_count="$(get_count "$name")"
        if [[ -n "$current_count" ]]; then
            # If a count exists, use it as a suffix
            hostname="${name}-${current_count}"
            # Increment for the next duplicate
            new_count=$((current_count + 1))
            set_count "$name" "$new_count"
        else
            # First time we see this name
            hostname="$name"
            # Initialize its count at 2 (so the next time is -2)
            set_count "$name" 2
        fi

        # add SSH config entry
        echo -e "Host $hostname\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> "$sshnew"
    done

    # validate and apply the new SSH config
    if ssh -F "$sshnew" null -G > /dev/null 2>&1; then
        mv "$sshnew" "$AXIOM_PATH/.sshconfig"
    else
        echo -e "${BRed}Error: Generated SSH config is invalid. Details:${Color_Off}"
        ssh -F "$sshnew" null -G
        cat "$sshnew"
        rm -f "$sshnew"
        return 1
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
        if [[ "$var" == "\\*" ]]; then
            var="*"
        fi

        if [[ "$var" == *"*"* ]]; then
            var=$(echo "$var" | sed 's/*/.*/g')
            matches=$(echo "$droplets" | jq -r '.Reservations[].Instances[] | select(.State.Name != "terminated") | .Tags?[]?.Value' | grep -E "^${var}$")
        else
            matches=$(echo "$droplets" | jq -r '.Reservations[].Instances[] | select(.State.Name != "terminated") | .Tags?[]?.Value' | grep -w -E "^${var}$")
        fi

        if [[ -n "$matches" ]]; then
            selected="$selected $matches"
        fi
    done

    if [[ -z "$selected" ]]; then
        return 1
    fi

    selected=$(echo "$selected" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo -n "${selected}" | xargs
}

###################################################################
#
# used by axiom-fleet axiom-init
get_image_id() {
    query="$1"
    region="${2:-$(jq -r '.region' "$AXIOM_PATH"/axiom.json)}"

    if [[ -z "$region" || "$region" == "null" ]]; then
        echo "Error: No region specified and no default region found in axiom.json."
        return 1
    fi

    # Fetch images in the specified region
    images=$(aws ec2 describe-images --region "$region" --query 'Images[*]' --owners self)

    # Get the most recent image matching the query
    name=$(echo "$images" | jq -r '.[].Name' | grep -wx "$query" | tail -n 1)
    id=$(echo "$images" | jq -r ".[] | select(.Name==\"$name\") | .ImageId")

    echo "$id"
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

###################################################################
# experimental v2 function
# deletes multiple instances at the same time by name, if the second argument is set to "true", will not prompt
# used by axiom-rm --multi
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
# experimental v2 function
# create multiple instances at the same time
# used by axiom-fleet2
#
create_instances() {
    image_id="$1"
    size="$2"
    region="$3"
    user_data="$4"
    timeout="$5"
    shift 5
    names=("$@")  # Remaining arguments are instance names

    security_group_name="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.security_group_name')"
    security_group_id="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.security_group_id')"

    # Determine whether to use security_group_name or security_group_id
    if [[ -n "$security_group_name" && "$security_group_name" != "null" ]]; then
        security_group_option="--security-groups $security_group_name"
    elif [[ -n "$security_group_id" && "$security_group_id" != "null" ]]; then
        security_group_option="--security-group-ids $security_group_id"
    else
        echo "Error: Both security_group_name and security_group_id are missing or invalid in axiom.json."
        return 1
    fi

    count="${#names[@]}"

    # Create instances in one API call and capture output
    instance_data=$( aws ec2 run-instances \
        --image-id "$image_id" \
        --count "$count" \
        --instance-type "$size" \
        --region "$region" \
        $security_group_option \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name}]" \
        --user-data "$user_data")

    instance_ids=($(echo "$instance_data" | jq -r '.Instances[].InstanceId'))

    instance_names=()
    for i in "${!instance_ids[@]}"; do
        instance_names+=( "${names[$i]}" )
    done

    sleep 5

    # Iterate over the array of instance IDs and rename them in parallel
    for i in "${!instance_ids[@]}"; do
        instance_id="${instance_ids[$i]}"
        instance_name="${names[$i]}"

        # Use create-tags to set the Name tag
        aws ec2 create-tags \
           --resources "$instance_id" \
           --region "$region" \
           --tags Key=Name,Value="$instance_name" &

        # Pause every 20 requests for background tasks to complete
        if (( (i+1) % 20 == 0 )); then
           wait
        fi
    done

    # After the loop, wait for any remaining background jobs
    wait

    processed_file=$(mktemp)

    interval=8   # Time between status checks
    elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        all_ready=true
        current_statuses=$(
            aws ec2 describe-instances \
                --instance-ids "${instance_ids[@]}" \
                --region "$region" \
                --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,PublicIp:PublicIpAddress}' \
                --output json
        )
        for i in "${!instance_ids[@]}"; do
            id="${instance_ids[$i]}"
            name="${instance_names[$i]}"

            # Parse the state and IP from the single JSON array
            state=$(jq -r --arg id "$id" '.[] | select(.Id == $id) | .State' <<< "$current_statuses")
            ip=$(jq -r --arg id "$id" '.[] | select(.Id == $id) | .PublicIp' <<< "$current_statuses")

            if [[ "$state" == "running" ]]; then
                # If we haven't printed a success message yet, do it now
                if ! grep -q "^$name\$" "$processed_file"; then
                    echo "$name" >> "$processed_file"
                    >&2 echo -e "${BWhite}Initialized instance '${BGreen}$name${Color_Off}${BWhite}' at IP '${BGreen}${ip:-"N/A"}${BWhite}'!"
                fi
            else
                # If any instance is not in "running", we must keep waiting
                all_ready=false
            fi
        done

       # If all instances are running, we're done
       if $all_ready; then
           rm -f "$processed_file"
           sleep 30
           return 0
       fi

       # Otherwise, sleep and increment elapsed
       sleep "$interval"
       elapsed=$((elapsed + interval))

    done

    # If we get here, not all instances became running before timeout
    rm -f "$processed_file"
    return 1
}
