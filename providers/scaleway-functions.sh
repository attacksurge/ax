#!/bin/bash

AXIOM_PATH="$HOME/.axiom"

###################################################################
#  Create one instance at a time
#
#  Needed for axiom-init
create_instance() {
    name="$1"
    image_id="$2"
    size_slug="$3"
    region="$4"
    user_data="$5"

    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"


    scw instance server create name="$name" \
        image="$image_id" \
        type="$size_slug" \
        zone="$region" \
        cloud-init=@"$user_data_file" \
        ip=new >/dev/null
    sleep 260
}

###################################################################
# Deletes an instance, if the second argument is set to "true", will not prompt
# Used by axiom-rm
delete_instance() {
    name="$1"
    force="$2"

    data=$(instances)
    instance_id=$(echo $data | jq -r '.[] | select(.name=="'$name'") | .id')
    ip=$(echo $data | jq -r '.[] | select(.name=="'$name'") | .public_ip.address')

    if [ "$force" == "true" ]; then
        echo -e "${Red}...powering off and deleting $name...${Color_Off}"
        scw instance server delete "$instance_id" force-shutdown=true
        scw instance ip delete "$ip"
    else
       echo -e -n "Are you sure you want to delete $name (y/N) - default NO: "
       read ans
       if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
        echo -e "${Red}...powering off and deleting $name...${Color_Off}"
        scw instance server delete "$instance_id" force-shutdown=true
        scw instance ip delete "$ip"
       fi
    fi
}

###################################################################
# Instances functions
# Used by many functions in this file
instances() {
    scw instance server list -o json
}

# Takes one argument, name of instance, returns raw IP address
# Used by axiom-ls and axiom-init
instance_ip() {
    name="$1"
    instances | jq -r ".[]? | select(.name==\"$name\") | .public_ip.address"
}

# Used by axiom-ls and axiom-select
instance_list() {
    instances | jq -r '.[].name'
}

# Used by axiom-ls
instance_pretty() {
    data=$(instances)

    # Number of servers
    droplets=$(echo "$data" | jq -r '.[] | .name' | wc -l)

    header="Instance,Primary Ip,Backend Ip,Zone,Type,Status"

    fields=".[] | [.name, (try .public_ip.address catch \"N/A\"), \"N/A\", .zone, .commercial_type, .state] | @csv"

    totals="_,_,_,Instances,$droplets,Total"

    data=$(echo "$data" | jq -r "$fields")
    (echo "$header" && echo "$data" && echo "$totals") | sed 's/"//g' | column -t -s,
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
        name=$(echo "$droplet" | jq -r '.name // empty' 2>/dev/null)
        public_ip=$(echo "$droplet" | jq -r '.public_ip?.address? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$droplet" | jq -r '.private_ip?.address? // empty' 2>/dev/null | head -n 1)

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
# Get data about regions
# Used by axiom-regions
list_regions() {
    echo "fr-par-1 fr-par-2 fr-par-3 nl-ams-1 nl-ams-2 pl-waw-1 pl-waw-2" | tr ' ' '\n'
}

# Get a list of region slugs
regions() {
    list_regions | jq -R . | jq -s .
}

###################################################################
# Manage power state of instances
# Used for axiom-power
poweron() {
    instance_name="$1"
    scw instance server action action=poweron $(instance_id "$instance_name")
}

# axiom-power
poweroff() {
    instance_name="$1"
    scw instance server action action=poweroff $(instance_id "$instance_name")
}

# axiom-power
reboot(){
    instance_name="$1"
    scw instance server action action=reboot $(instance_id "$instance_name")
}

# axiom-power and axiom-images
instance_id() {
    name="$1"
    instances | jq -r ".[] | select(.name==\"$name\") | .id"
}

###################################################################
# List available instance sizes
# Used by ax sizes
sizes_list() {
  region="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.region')"
  scw instance  server-type list zone=$region
}

###################################################################
# Manage snapshots
# Used for axiom-images and axiom-backup
snapshots() {
    scw instance image list -o json
}

# axiom-images
get_snapshots() {
    scw instance image list
}

# axiom-images
delete_snapshot() {
    name="$1"
    image_id=$(get_image_id "$name")
    scw instance image delete "$image_id"
}

# axiom-images
create_snapshot() {
    instance="$1"
    image_name="$2"
    data=$(instances)
    snapshot_id=$(echo "$data" | jq -r '.[] | select(.name=="'$instance'") .image.root_volume.id')
    scw instance image create snapshot-id="$snapshot_id" name="$image_name" arch=x86_64
}

###################################################################
# Get an image ID by querying snapshots
# Used for axiom-init and axiom-images
get_image_id() {
    query="$1"
    images=$(scw instance image list -o json)
    name=$(echo "$images" | jq -r ".[].name" | grep -wx "$query" | tail -n 1)
    id=$(echo "$images" | jq -r ".[] | select(.name==\"$name\") | .id")
    echo $id
}

###################################################################
# experimental v2 function
# deletes multiple instances at the same time by name, if the second argument is set to "true", will not prompt
# used by axiom-rm --multi
delete_instances() {
    names="$1"
    force="$2"

    data=$(instances)

    if [ "$force" == "true" ]; then
        instance_ids=""
        ips=""

        for name in $names; do
            # Collect all matching instance IDs and IPs
            instance_ids_list=$(echo "$data" | jq -r '.[] | select(.name=="'$name'") | .id')
            for instance_id in $instance_ids_list; do
                instance_ids+="$instance_id "
                ip=$(echo "$data" | jq -r '.[] | select(.id=="'$instance_id'") | .public_ip.address')
                ips+="$ip "
            done
        done

        echo -e "${Red}Powering off and deleting: $names, please be patient (scw can be slow)...${Color_Off}"
        scw instance server delete $instance_ids force-shutdown=true >/dev/null 2>&1
        scw instance ip delete $ips >/dev/null 2>&1
    else
        for name in $names; do
            # Prompt user for each matching instance
            instance_ids_list=$(echo "$data" | jq -r '.[] | select(.name=="'$name'") | .id')
            for instance_id in $instance_ids_list; do
                ip=$(echo "$data" | jq -r '.[] | select(.id=="'$instance_id'") | .public_ip.address')

                echo -e -n "Are you sure you want to delete $name (Instance ID: $instance_id) (y/N) - default NO: "
                read ans
                if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                    echo -e "${Red}Powering off and deleting: $name (Instance ID: $instance_id), please be patient (scw can be slow)...${Color_Off}"
                    scw instance server delete "$instance_id" force-shutdown=true
                    scw instance ip delete "$ip"
                fi
            done
        done
    fi
}

###################################################################
# Create multiple instances at the same time
#
# Needed for axiom-init
create_instances() {
    image_id="$1"
    size_slug="$2"
    region="$3"
    user_data="$4"
    timeout="$5"
    shift 5
    names=("$@")  # Remaining arguments are instance names

    # Create temporary user data file
    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"

    # Track instance creation statuses
    processed_file=$(mktemp)
    interval=8   # Time between status checks
    elapsed=0

    # Store created instance names
    created_instances=()

    # Create instances in parallel
    for name in "${names[@]}"; do
        output=$(scw instance server create name="$name" \
            image="$image_id" \
            type="$size_slug" \
            zone="$region" \
            cloud-init=@"$user_data_file" \
            ip=new -o json 2>&1)

        if [ $? -eq 0 ]; then
            created_instances+=("$name")
        else
            >&2 echo -e "${BRed}Error creating instance '$name': $output${Color_Off}"
        fi
    done

    # If no instances were created successfully, exit early
    if [ ${#created_instances[@]} -eq 0 ]; then
        rm -f "$processed_file" "$user_data_file"
        return 1
    fi

    # Monitor instance statuses
    while [ "$elapsed" -lt "$timeout" ]; do
        all_ready=true

        # Get current status of all instances
        current_statuses=$(scw instance server list -o json)

        for name in "${created_instances[@]}"; do
            # Get instance details
            instance_data=$(echo "$current_statuses" | jq -r ".[] | select(.name==\"$name\")")
            state=$(echo "$instance_data" | jq -r '.state // empty')
            ip=$(echo "$instance_data" | jq -r '.public_ip.address // empty')

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
