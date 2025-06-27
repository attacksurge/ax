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
    disk="$6"

    # Default disk size to 20 if not provided
    if [[ -z "$disk" || "$disk" == "null" ]]; then
        disk="20"
    fi

    disk_option="--block-device-mappings DeviceName=/dev/xvda,Ebs={VolumeSize=$disk,VolumeType=gp2,DeleteOnTermination=true}"

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
        --user-data "$user_data" \
        $disk_option 2>&1 >> /dev/null

     if [[ $? -ne 0 ]]; then
        echo "Error: Failed to launch instance '$name' in region '$region'."
        return 1
     fi

    # Allow time for instance initialization if needed
    sleep 260
}

###################################################################
# deletes an instance. if the second argument is "true", will not prompt.
# used by axiom-rm
#
delete_instance() {
    local name="$1"
    local force="$2"

    instance_data="$(instance_id "$name" --get-region)" || {
        echo "Instance not found."
        return 1
    }

    id=$(echo "$instance_data" | awk '{print $1}')
    region=$(echo "$instance_data" | awk '{print $2}')

    if [[ "$force" != "true" ]]; then
        read -p "Delete '$name' ($id in $region)? (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Aborted."
            return 1
        fi
    fi

    if aws ec2 terminate-instances --instance-ids "$id" --region "$region" >/dev/null 2>&1; then
        echo "Deleted '$name' ($id) in $region."
    else
        echo "Failed to delete '$name'."
    fi
}

###################################################################
# Instances functions
# used by many functions in this file
instances() {
    local tempdir
    tempdir=$(mktemp -d)
    local regions
    regions=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)

    # Fetch describe-instances for each region in parallel
    for region in $regions; do
        aws ec2 describe-instances --region "$region" --output json > "$tempdir/$region.json" &
    done
    wait

    # Merge all Reservations into one global array
    jq -s '{Reservations: map(.Reservations[]) }' "$tempdir"/*.json

    rm -rf "$tempdir"
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
        name="$1"
        instances | jq -r ".Reservations[].Instances[] | select(.Tags?[]?.Value==\"$name\") | .PublicIpAddress"
}

# used by axiom-select axiom-ls
instance_list() {
        instances | jq -r '.Reservations[].Instances[] | select(.State.Name != "terminated") | .Tags?[]? | select(.Key == "Name") | .Value'
}

# used by axiom-ls
instance_pretty() {
    local costs header fields data numInstances types totalCost updatedData footer

    costs=$(curl -sL 'https://ec2.shop' -H 'accept: json')
    header="Instance,Primary IP,Backend IP,Region,Type,Status,\$/M"
    fields='.Reservations[].Instances[]
        | select(.State.Name != "terminated")
        | [
            (.Tags?[]? | select(.Key == "Name") | .Value) // "N/A",
            (.PublicIpAddress // "N/A"),
            (.PrivateIpAddress // "N/A"),
            (.Placement.AvailabilityZone // "N/A"),
            (.InstanceType // "N/A"),
            (.State.Name // "N/A")
          ]
        | @csv'

    data=$(instances | jq -r "$fields" | sort -k1)
    data=$(echo "$data" | awk -F',' 'NF>=6')  # Filter to only rows with 6 fields
    numInstances=$(echo "$data" | grep -v '^$' | wc -l)

    if [[ $numInstances -gt 0 ]]; then
        types=$(echo "$data" | cut -d, -f5 | sort | uniq)
        totalCost=0
        updatedData=""

        while read -r type; do
            type=$(echo "$type" | tr -d '"')

            # Fetch monthly cost for this instance type
            cost=$(echo "$costs" | jq -r ".Prices[] | select(.InstanceType == \"$type\").MonthlyPrice")
            cost=${cost:-0}

            typeData=$(echo "$data" | grep ",\"$type\",")

            # Append cost to each matching row
            while IFS= read -r row; do
                updatedData+="$row,\"$cost\"\n"
            done <<< "$typeData"

            # Calculate running total cost
            typeCount=$(echo "$typeData" | grep -v '^$' | wc -l)
            totalCost=$(echo "$totalCost + ($cost * $typeCount)" | bc)
        done <<< "$types"

        # Clean final data
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
            matches=$(echo "$droplets" | jq -r '.Reservations[].Instances[] | select(.State.Name != "terminated") | .Tags?[]? | select(.Key == "Name") | .Value' | \
             grep -E "^${var}$")
        else
            matches=$(echo "$droplets" | jq -r '.Reservations[].Instances[] | select(.State.Name != "terminated") | .Tags?[]? | select(.Key == "Name") | .Value' | \
             grep -w -E "^${var}$")
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
# used by axiom-fleet, axiom-init, axiom-images
#
get_image_id() {
    local tempdir
    query="$1"
    region="${2:-$(jq -r '.region' "$AXIOM_PATH"/axiom.json)}"
    all_regions="$3"

    if [[ "$all_regions" == "--all-regions" ]]; then
        tempdir=$(mktemp -d)
        for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
            (
                aws ec2 describe-images --owners self --region "$r" \
                    --query "Images[*].[Name,ImageId]" --output json \
                | jq -r --arg query "$query" --arg region "$r" '.[] | select(.[0] | startswith($query)) | "\(. [1]) \($region)"' > "$tempdir/$r.txt"
            ) &
        done
        wait
        cat "$tempdir"/*.txt
        rm -rf "$tempdir"
    else
        if [[ -z "$region" || "$region" == "null" ]]; then
            echo "Error: No region specified and no default region found in axiom.json."
            return 1
        fi
        aws ec2 describe-images --owners self --region "$region" \
            --query "Images[*].[Name,ImageId]" --output json \
        | jq -r --arg query "$query" '.[] | select(.[0] | startswith($query)) | .[1]'
    fi
}

# Manage snapshots used for axiom-images
get_snapshots() {
    local tempdir
    tempdir=$(mktemp -d)
    printf "%-40s %-8s %-s\n" "Name" "Size(GB)" "Regions"

    for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
        (
            aws ec2 describe-images --owners self --region "$region" \
                --query "Images[*].[Name,BlockDeviceMappings[0].Ebs.VolumeSize]" --output text \
            | awk -v r="$region" '{OFS="\t"; print $1, $2, r}' > "$tempdir/$region.txt"
        ) &
    done
    wait

    awk -F'\t' '
        {
            key=$1 FS $2
            region_map[key]=(region_map[key] ? region_map[key] " " $3 : $3)
        }
        END {
            for (k in region_map) {
                split(k, f, FS)
                split(region_map[k], r, " ")
                asort(r)
                regions=""
                limit=3
                for (i=1; i<=length(r) && i<=limit; i++) regions=(regions ? regions " " : "") r[i]
                extra=(length(r)>limit) ? " (+ " (length(r)-limit) " more)" : ""
                printf "%-40s %-8s [%s%s]\n", f[1], f[2], regions, extra
            }
        }
        function asort(arr,   i,j,t) {
            for(i=1;i<=length(arr);i++) for(j=i+1;j<=length(arr);j++) if(arr[i]>arr[j]) {t=arr[i];arr[i]=arr[j];arr[j]=t}
        }
    ' "$tempdir"/*.txt | sort

    rm -rf "$tempdir"
}

# Delete snapshot(s) by name across many regions, used by axiom-images
delete_snapshot() {
    name="$1"
    tempdir=$(mktemp -d)

    get_image_id "$name" "" --all-regions > "$tempdir/images.txt"

    if [[ ! -s "$tempdir/images.txt" ]]; then
        echo "No images found matching '$name'."
        rm -rf "$tempdir"
        return 1
    fi

    while read -r image_id region; do
        (
            snapshot_id=$(aws ec2 describe-images --region "$region" --image-ids "$image_id" \
                --query 'Images[*].BlockDeviceMappings[*].Ebs.SnapshotId' --output text)

            echo -e "${Red}Deregistering image $image_id in $region...${Color_Off}"
            aws ec2 deregister-image --image-id "$image_id" --region "$region" >/dev/null 2>&1

            if [[ -n "$snapshot_id" ]]; then
                echo -e "${Red}Deleting snapshot $snapshot_id in $region...${Color_Off}"
                aws ec2 delete-snapshot --snapshot-id "$snapshot_id" --region "$region" >/dev/null 2>&1
            fi
        ) &
    done < "$tempdir/images.txt"
    wait

    rm -rf "$tempdir"
}

# axiom-images
create_snapshot() {
        instance="$1"
        snapshot_name="$2"
	aws ec2 create-image --instance-id "$(instance_id $instance)" --name $snapshot_name
}

# transfer-image to new region (init, fleet, fleet2)
transfer_snapshot() {
    local image_id="$1" image="$2" regions_string="$3"
    read -r -a regions <<< "$regions_string"
    local max_jobs=50

    [[ -z "$image_id" || -z "$image" || "${#regions[@]}" -eq 0 ]] && {
        echo -e "${BRed}Error: Missing arguments for AWS region transfer.${Color_Off}"
        return 1
    }

    local source_region
    source_region="$(jq -r '.region' "$AXIOM_PATH/axiom.json")"

    wait_for_jobs() {
        while [ "$(jobs -rp | wc -l)" -ge "$max_jobs" ]; do
            sleep 1
        done
    }

    for region in "${regions[@]}"; do
        wait_for_jobs

        (
            existing_ami_id=$(aws ec2 describe-images --region "$region" --owners self \
                --filters "Name=name,Values=$image" --query 'Images[0].ImageId' --output text) || true

            if [[ -z "$existing_ami_id" || "$existing_ami_id" == "None" ]]; then
                echo -e "${BYellow}Transferring '${BRed}$image${BYellow}' to '${BRed}$region${BYellow}'...${Color_Off}"

                copied_ami_id=$(aws ec2 copy-image \
                    --source-image-id "$image_id" --source-region "$source_region" \
                    --region "$region" --name "$image" \
                    --description "Copied from $source_region:$image_id" \
                    --query 'ImageId' --output text)

                if [[ -z "$copied_ami_id" || "$copied_ami_id" == "None" ]]; then
                    echo -e "${BRed}Failed to copy image to '$region'.${Color_Off}"
                    exit 0
                fi

                # Poll every 15 seconds for up to 10 minutes
                max_wait=600
                interval=15
                elapsed=0

                while [ "$elapsed" -lt "$max_wait" ]; do
                    state=$(aws ec2 describe-images \
                        --region "$region" \
                        --image-ids "$copied_ami_id" \
                        --query 'Images[0].State' --output text 2>/dev/null)

                    if [[ "$state" == "available" ]]; then
                        echo -e "${BGreen}Copy to '$region' succeeded.${Color_Off}"
                        exit 0
                    elif [[ "$state" == "failed" ]]; then
                        echo -e "${BRed}Copy to '$region' failed permanently.${Color_Off}"
                        exit 1
                    fi

                    sleep "$interval"
                    elapsed=$((elapsed + interval))
                done

                echo -e "${BRed}Copy to '$region' timed out after $max_wait seconds.${Color_Off}"
            fi
        ) &
    done

    wait
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
    local name="$1" mode="$2"
    local filter=".Reservations[].Instances[] | select(.State.Name != \"terminated\") | select(.Tags[]? | select(.Key == \"Name\" and .Value == \"$name\"))"

    if [[ "$mode" == "--get-region" ]]; then
        instances | jq -r "$filter | [.InstanceId, (.Placement.AvailabilityZone | sub(\"[a-z]$\"; \"\"))] | @tsv"
    else
        instances | jq -r "$filter | .InstanceId"
    fi
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
    local names="$1"
    local force="$2"
    local tempdir
    tempdir=$(mktemp -d)
    instance_info_list=()

    name_array=($names)

    local regions
    regions=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)

    # Fetch minimized instance data per region in parallel
    for region in $regions; do
        (
            aws ec2 describe-instances --region "$region" \
                --query "Reservations[].Instances[].{InstanceId: InstanceId, Name: Tags[?Key=='Name']|[0].Value, State: State.Name, AZ: Placement.AvailabilityZone}" \
                --output json > "$tempdir/$region.json" 2>/dev/null
        ) &
    done
    wait

    # Gather matching instance info into flat list
    for region in $regions; do
        if [ -s "$tempdir/$region.json" ]; then
            while IFS=$'\t' read -r instance_id instance_name state az; do
                for name in "${name_array[@]}"; do
                    if [[ "$instance_name" == "$name" && "$state" != "terminated" ]]; then
                        region_name="${az::-1}" # strip last letter of AZ to get region
                        instance_info_list+=("$instance_id|$region_name|$instance_name")
                    fi
                done
            done < <(jq -r '.[] | [.InstanceId, .Name, .State, .AZ] | @tsv' "$tempdir/$region.json")
        fi
    done

    rm -rf "$tempdir"

    if [ ${#instance_info_list[@]} -eq 0 ]; then
        echo "No matching instances found."
        return 1
    fi

    # Group and delete by region
    for region in $regions; do
        ids_to_delete=()
        for info in "${instance_info_list[@]}"; do
            instance_id=$(echo "$info" | cut -d'|' -f1)
            info_region=$(echo "$info" | cut -d'|' -f2)
            if [[ "$info_region" == "$region" ]]; then
                ids_to_delete+=("$instance_id")
            fi
        done

        if [ ${#ids_to_delete[@]} -gt 0 ]; then
            if [[ "$force" == "true" ]]; then
                echo -e "${Red}Deleting in $region: ${ids_to_delete[*]}${Color_Off}"
                aws ec2 terminate-instances --instance-ids "${ids_to_delete[@]}" --region "$region" >/dev/null 2>&1
            else
                for id in "${ids_to_delete[@]}"; do
                    echo -e -n "Delete instance $id in $region? (y/N): "
                    read ans
                    if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
                        echo -e "${Red}Deleting $id...${Color_Off}"
                        aws ec2 terminate-instances --instance-ids "$id" --region "$region" >/dev/null 2>&1
                    else
                        echo "Aborted $id."
                    fi
                done
            fi
        fi
    done
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
    disk="$6"

    # Default disk size to 20 if not provided
    if [[ -z "$disk" || "$disk" == "null" ]]; then
        disk="20"
    fi

    shift 6
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

    disk_option="--block-device-mappings DeviceName=/dev/xvda,Ebs={VolumeSize=$disk,VolumeType=gp2,DeleteOnTermination=true}"

    count="${#names[@]}"

    # Create instances in one API call and capture output
    instance_data=$( aws ec2 run-instances \
        --image-id "$image_id" \
        --count "$count" \
        --instance-type "$size" \
        --region "$region" \
        $security_group_option \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name}]" \
        $disk_option \
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
