#!/bin/bash

AXIOM_PATH="$HOME/.axiom"

###################################################################
#  Create Instance is likely the most important provider function :)
#  needed for init and fleet
#
create_instance() {
    name="$1"
    image_id="$2"
    profile="$3"
    region="$4"
    user_data="$5"

    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"

    vpc="$(jq -r '.vpc' "$AXIOM_PATH"/axiom.json)"
    security_group_name="$(jq -r '.security_group' "$AXIOM_PATH"/axiom.json)"

    ibmcloud is instance-create "$name" "$vpc" "$region" "$profile" "$vpc-subnet-$region" --image "$image_id" --pnac-vni-name "$name"-vni  --pnac-name "$name"-pnac --pnac-vni-sgs "$security_group_name" --user-data @"$user_data_file" 2>&1 >>/dev/null && \
    ibmcloud is floating-ip-reserve "$name"-ip --vni "$name"-vni --in "$name" >>/dev/null

    sleep 260
}

###################################################################
# deletes instance, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instance() {
    name="$1"
    force="$2"

    if [ "$force" != "true" ]; then
        read -p "Are you sure you want to delete instance '$name'? (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Instance deletion aborted."
            return 1
        fi
    fi

    ibmcloud is instance-delete "$name" --force >/dev/null 2>&1
    ibmcloud is floating-ip-release "$name"-ip --force >/dev/null 2>&1
}

###################################################################
# Instances functions
# used by many functions in this file
instances() {
 ibmcloud is instances --output json
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
    host="$1"
    instances | jq -r '.[] | select(.name == "'"$host"'") | (
        [
            .primary_network_attachment?.virtual_network_interface?.floating_ips[0]?.address,
            .network_interfaces[]?.floating_ips[]?.address
        ] | map(select(. != null and . != "")) | .[0] // ""
    )' | head -n 1
}

# used by axiom-select axiom-ls
instance_list() {
    instances | jq -r '.[].name'
}

# used by axiom-ls
instance_pretty() {
    data=$(instances)
    instances=$(echo "$data" | jq -r '.[]|.name' | wc -l)
    current_time=$(date +%s)
    header="Instance,Primary Ip,Backend Ip,Zone,Memory,CPU,Status,Profile,Active Hours"
    fields='.[] | [
        .name // "",
        (
            [
                .primary_network_attachment?.virtual_network_interface?.floating_ips[0]?.address,
                .network_interfaces[]?.floating_ips[]?.address
            ] | map(select(. != null and . != "")) | .[0] // ""
        ),
        .primary_network_interface?.primary_ip?.address // "",
        .zone?.name // "",
        .memory // "",
        .vcpu?.count // "",
        .status // "",
        .profile?.name // "",
        .created_at // ""
    ] | @csv'

    data=$(echo "$data" | jq -r "$fields" | sed 's/^,/0,/; :a;s/,,/,0,/g;ta')

    total_active_hours=0

    formatted_data=""
    if [ "$instances" -gt 0 ]; then
        formatted_data=$(echo "$data" | while IFS=',' read -r name primary_ip backend_ip zone memory cpu status profile created_at; do
            created_ts=$(date -d "${created_at//\"/}" +%s)
            active_hours=$(( (current_time - created_ts) / 3600 ))
            total_active_hours=$((total_active_hours + active_hours))
            echo "$name,$primary_ip,$backend_ip,$zone,$memory,$cpu,$status,$profile,$active_hours"
        done)
        total_active_hours=$(echo "$formatted_data" | awk -F, '{sum+=$9} END {print sum}')
        totals="Total Instances: $instances,_,_,_,_,_,_,_,Total Active Hours: $total_active_hours"
        (echo "$header" && echo "$formatted_data" && echo "$totals") | sed 's/"//g' | column -t -s,
    else
        echo "No instances found."
    fi
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

    echo "$droplets" | jq -c '.[]?' 2>/dev/null | while read -r droplet; do
        # extract fields
        name=$(echo "$droplet" | jq -r '.name? // empty' 2>/dev/null)

        public_primary_ip=$(echo "$droplet" | jq -r '.primary_network_attachment?.virtual_network_interface?.floating_ips[0]?.address? // empty' 2>/dev/null | head -n 1)
        public_network_ip=$(echo "$droplet" | jq -r '.network_interfaces[]?.floating_ips[]?.address? // empty' 2>/dev/null | head -n 1)
        public_ip=$(echo -e "$public_primary_ip\n$public_network_ip" | grep -v "^$" | head -n 1)

        private_primary_ip=$(echo "$droplet" | jq -r '.primary_network_attachment?.primary_ip?.address? // empty' 2>/dev/null | head -n 1)
        private_network_ip=$(echo "$droplet" | jq -r '.network_interfaces[]?.primary_ip?.address? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo -e "$private_primary_ip\n$private_network_ip" | grep -v "^$" | head -n 1)

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
            var=$(echo "$var" | sed 's/\*/.*/g')
            matches=$(echo "$droplets" | jq -r '.[].name' | grep -E "^${var}$")
        else
            matches=$(echo "$droplets" | jq -r '.[].name' | grep -w -E "^${var}$")
        fi

        if [[ -n "$matches" ]]; then
            selected="$selected $matches"
        fi
    done

    if [[ -z "$selected" ]]; then
        return 1  # Exit with non-zero code but no output
    fi

    selected=$(echo "$selected" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo -n "${selected}" | xargs
}

###################################################################
#
# used by axiom-fleet axiom-init
get_image_id() {
    query="$1"
    images=$(ibmcloud is images --visibility private --output json)
    id=$(echo "$images" | jq -r '.[] | select(.name=="'"$query"'") | .id')

    echo "$id"
}

###################################################################
# Manage snapshots
# used for axiom-images
#
get_snapshots(){
    ibmcloud is images --visibility private
}

# axiom-images
delete_snapshot() {
    name=$1
    force="$2"
    if [ "$force" == "true" ];  then
     ibmcloud is image-delete "$name" --force
    else
     ibmcloud is image-delete "$name"
    fi
}

# axiom-images
create_snapshot() {
    instance="$1"
    snapshot_name="$2"
    volume_id=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="'"$instance"'") | .volume_attachments[0].volume.id')
    echo -e "Powering off VSI $instance.. please wait"
    poweroff "$instance" true
    echo -e "sleeping for 30 seconds.."
    sleep 30
    ibmcloud is image-create "$snapshot_name"  --source-volume "$volume_id" --quiet
}

###################################################################
# Get data about regions and zones
# used by axiom-regions
#
list_regions() {

echo 'au-syd-1
au-syd-2
au-syd-3
br-sao-1
br-sao-2
br-sao-3
ca-tor-1
ca-tor-2
ca-tor-3
eu-de-1
eu-de-2
eu-de-3
eu-es-1
eu-es-2
eu-es-3
eu-gb-1
eu-gb-2
eu-gb-3
jp-osa-1
jp-osa-2
jp-osa-3
jp-tok-1
jp-tok-2
jp-tok-3
us-east-1
us-east-2
us-east-3
us-south-1
us-south-2
us-south-3'
}

regions() {
    list_regions
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
    instance_name="$1"
    instance_id=$(ibmcloud is instances --output json | jq -r ".[] | select(.name == \"$instance_name\") | .id")
    ibmcloud is instance-start "$instance_id" --quiet
}

# axiom-power
poweroff() {
    instance_name="$1"
    force="$2"
    instance_id=$(ibmcloud is instances --output json | jq -r ".[] | select(.name == \"$instance_name\") | .id")
    if [ "$force" == "true" ];
    then
     ibmcloud is instance-stop "$instance_id" --force --quiet
    else
     ibmcloud is instance-stop "$instance_id" --quiet
    fi
}

# axiom-power
reboot(){
    instance_name="$1"
    force="$2"
    instance_id=$(ibmcloud is instances --output json | jq -r ".[] | select(.name == \"$instance_name\") | .id")
    if [ "$force" == "true" ];
    then
     ibmcloud is instance-reboot "$instance_id" --force --quiet
    else
     ibmcloud is instance-reboot "$instance_id" --quiet
    fi
}

# axiom-power axiom-images
instance_id() {
    name="$1"
    ibmcloud is instances --output json | jq -r ".[] | select(.name==\"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
    (echo -e "Name\tArchitecture\tvCPUs\tMemory(GiB)\tBandwidth"; \
    ibmcloud is instance-profiles --output json | jq -r '.[] | select(.os_architecture.values[0] == "amd64") |
  [
    .name,
    .os_architecture.values[0],
    .vcpu_count.value,
    .memory.value,
    .bandwidth.value
  ] | @tsv') | column -t
}

###################################################################
# experimental v2 function
# deletes multiple instances at the same time by name, if the second argument is set to "true", will not prompt
# used by axiom-rm --multi
#
delete_instances() {
    names="$1"
    force="$2"

    # Convert names to an array for processing
    name_array=($names)

   # Initialize an empty array for the results
   ip_array=()

   # Loop through the original array and add "-ip" to each element
   for name in "${name_array[@]}"; do
    ip_array+=("${name}-ip")
   done

    # Force deletion: Delete all VSIs without prompting
    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting: ${name_array[@]}...${Color_Off}"
        ibmcloud is instance-delete -f "${name_array[@]}" >/dev/null 2>&1
        ibmcloud is floating-ip-release "${ip_array[@]}" --force >/dev/null 2>&1

    # Prompt for each names if force is not true
    else
        # Collect names for deletion after user confirmation
        confirmed_names=()

        for name in "${name_array[@]}"; do

            echo -e -n "Are you sure you want to delete VPC VSI $name y/N) - default NO: "
            read ans
            if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                confirmed_names+=("$name")
            else
                echo "Deletion aborted for $name."
            fi
        done

        confirmed_ip_array=()
        for name in "${confirmed_names[@]}"; do
         confirmed_ip_array+=("${confirmed_names}-ip")
        done

        # Delete confirmed VSIs and release floating Ips in bulk
        if [ ${#confirmed_names[@]} -gt 0 ]; then
            echo -e "${Red}Deleting: ${confirmed_names[@]}...${Color_Off}"
            ibmcloud is instance-delete -f "${confirmed_names[@]}"  >/dev/null 2>&1
            ibmcloud is floating-ip-release "${confirmed_ip_array[@]}" --force >/dev/null 2>&1

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
    profile="$2"
    region="$3"
    user_data="$4"
    timeout="$5"
    disk="$6"
    shift 6
    names=("$@")  # Remaining arguments are instance names

    # Get required config values
    vpc="$(jq -r '.vpc' "$AXIOM_PATH"/axiom.json)"
    security_group_name="$(jq -r '.security_group' "$AXIOM_PATH"/axiom.json)"

    # Create temporary user data file
    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"

    # Create a temporary file to track processed instances
    processed_file=$(mktemp)
    interval=8   # Time between status checks
    elapsed=0

   # Store created instance names
   created_instances=()

    # Create instances in parallel
    for name in "${names[@]}"; do
        # Create instance with network interface
        (ibmcloud is instance-create "$name" "$vpc" "$region" "$profile" "$vpc-subnet-$region" \
            --image "$image_id" \
            --pnac-vni-name "$name"-vni \
            --pnac-name "$name"-pnac \
            --pnac-vni-sgs "$security_group_name" \
            --user-data @"$user_data_file" \
            >/dev/null && \
        # Reserve and attach floating IP in parallel
        ibmcloud is floating-ip-reserve "$name"-ip \
            --vni "$name"-vni \
            --in "$name" \
            >/dev/null)

        if [ $? -eq 0 ]; then
            created_instances+=("$name")
        else
            >&2 echo -e "${BRed}Error creating instance '$name': $output${Color_Off}"
        fi

    done

    # Wait for background jobs to complete
    wait

    # Monitor instance statuses
    while [ "$elapsed" -lt "$timeout" ]; do
        all_ready=true

        # Get current status of all instances in one call
        current_statuses=$(ibmcloud is instances --output json)

        for name in "${created_instances[@]}"; do
            # Get instance details
            instance_data=$(echo "$current_statuses" | jq -r ".[] | select(.name==\"$name\")")
            state=$(echo "$instance_data" | jq -r '.status // empty')

            # Get floating IP
            ip=$(echo "$instance_data" | jq -r '(
                [
                    .primary_network_attachment?.virtual_network_interface?.floating_ips[0]?.address,
                    .network_interfaces[]?.floating_ips[]?.address
                ] | map(select(. != null and . != "")) | .[0] // ""
            )')

            if [[ "$state" == "running" ]]; then
                # Only announce once per instance
                if ! grep -q "^$name\$" "$processed_file"; then
                    echo "$name" >> "$processed_file"
                    >&2 echo -e "${BWhite}Initialized instance '${BGreen}$name${Color_Off}${BWhite}' at IP '${BGreen}${ip}${BWhite}'!"
                fi
            else
                all_ready=false
            fi
        done

        # If all instances are running, we're done
        if $all_ready; then
            rm -f "$processed_file" "$user_data_file"
            sleep 30
            return 0
        fi

        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    # Clean up temporary files
    rm -f "$processed_file" "$user_data_file"

    # If we get here, timeout was reached
    >&2 echo -e "${BRed}Error: Timeout reached before all instances became ready.${Color_Off}"
    return 1
}
