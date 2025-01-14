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
        user_data="$5"
        domain="ax.private"
        cpu="$(jq -r '.cpu' $AXIOM_PATH/axiom.json)"

        ibmcloud sl vs create -H "$name" -D "$domain" -c "$cpu" -m "$size_slug" -n 1000 -d "$region" --image "$image_id" --userdata "$user_data" -f  2>&1 >>/dev/null

	sleep 260
}

###################################################################
# deletes instance, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instance() {
    name="$1"
    force="$2"
    id="$(instance_id $name)"
    if [ "$force" == "true" ]
        then
        ibmcloud sl vs cancel "$id" -f >/dev/null 2>&1
    else
        ibmcloud sl vs cancel "$id"
    fi
}

###################################################################
# Instances functions
# used by many functions in this file
instances() {
        ibmcloud sl vs list --column datacenter --column domain --column hostname --column id --column cpu --column memory --column public_ip --column private_ip --column power_state --column created_by --column action --output json
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
        host="$1"
        instances | jq -r ".[] | select(.hostname==\"$host\") | .primaryIpAddress"
}

# used by axiom-select axiom-ls
instance_list() {
        instances | jq -r '.[].hostname'
}

# used by axiom-ls
instance_pretty() {
    data=$(instances)
    #number of droplets
    droplets=$(echo $data|jq -r '.[]|.hostname'|wc -l )

    hour_cost=0
    for f in $(echo $data | jq -r '.[].billingItem.hourlyRecurringFee'); do new=$(bc <<< "$hour_cost + $f"); hour_cost=$new; done
    totalhourly_Price=$hour_cost

    hours_used=0
    for f in $(echo $data | jq -r '.[].billingItem.hoursUsed'); do new=$(bc <<< "$hours_used + $f"); hours_used=$new; done
    totalhours_used=$hours_used

    monthly_cost=0
    for f in $(echo $data | jq -r '.[].billingItem.orderItem.recurringAfterTaxAmount'); do new=$(bc <<< "$monthly_cost + $f"); monthly_cost=$new; done
    totalmonthly_Price=$monthly_cost

    header="Instance,Primary Ip,Backend Ip,DC,Memory,CPU,Status,Hours used,\$/H,\$/M"
    fields=".[] | [.hostname, .primaryIpAddress, .primaryBackendIpAddress, .datacenter.name, .maxMemory, .maxCpu, .powerState.name, .billingItem.hoursUsed, .billingItem.orderItem.hourlyRecurringFee, .billingItem.orderItem.recurringAfterTaxAmount ] | @csv"
    totals="_,_,_,_,Instances,$droplets,Total Hours,$totalhours_used,\$$totalhourly_Price/hr,\$$totalmonthly_Price/mo"

    #data is sorted by default by field name
    data=$(echo $data | jq  -r "$fields"| sed 's/^,/0,/; :a;s/,,/,0,/g;ta')
    (echo "$header" && echo "$data" && echo $totals) | sed 's/"//g' | column -t -s,
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
        name=$(echo "$droplet" | jq -r '.hostname? // empty' 2>/dev/null)
        public_ip=$(echo "$droplet" | jq -r '.primaryIpAddress? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$droplet" | jq -r '.primaryBackendIpAddress? // empty' 2>/dev/null | head -n 1)

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
            matches=$(echo "$droplets" | jq -r '.[].hostname' | grep -E "^${var}$")
        else
            matches=$(echo "$droplets" | jq -r '.[].hostname' | grep -w -E "^${var}$")
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
	images=$(ibmcloud sl image list --private --output json)
	name=$(echo $images | jq -r ".[].name" | grep -wx "$query" | tail -n 1)
	id=$(echo $images |  jq -r ".[] | select(.name==\"$name\") | .id")
	echo $id
}

###################################################################
# Manage snapshots
# used for axiom-images
#
get_snapshots() {
        ibmcloud sl image list --private
}

# axiom-images
delete_snapshot() {
 name=$1
 image_id=$(get_image_id "$name")
 ibmcloud sl image delete "$image_id"
}

# axiom-images
snapshots() {
        ibmcloud sl image list --output json --private
}

# axiom-images
create_snapshot() {
        instance="$1"
        snapshot_name="$2"
	ibmcloud sl vs capture "$(instance_id $instance)" --name $snapshot_name
}

###################################################################
# Get data about regions
# used by axiom-regions
#
list_regions() {
     ibmcloud sl vs options | sed -n '/datacenter/,/Size/p' | tr -s ' ' | rev | cut -d  ' ' -f 1| rev | tail -n +2 | head -n -1 | tr '\n' ','
}

regions() {
     ibmcloud sl vs options | sed -n '/datacenter/,/Size/p' | tr -s ' ' | rev | cut -d  ' ' -f 1 | rev | tail -n +2 | head -n -1 | tr '\n' ','
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
instance_name="$1"
force="$2"
if [ "$force" == "true" ]
then
 ibmcloud sl vs power-on $(instance_id $instance_name) --force
else
 ibmcloud sl vs power-on $(instance_id $instance_name)
fi
}

# axiom-power
poweroff() {
instance_name="$1"
force="$2"
if [ "$force" == "true" ]
then
 ibmcloud sl vs power-off $(instance_id $instance_name) --force
else
 ibmcloud sl vs power-off $(instance_id $instance_name)
fi
}

# axiom-power
reboot(){
instance_name="$1"
force="$2"
if [ "$force" == "true" ]
then
 ibmcloud sl vs reboot $(instance_id $instance_name) --force
else
 ibmcloud sl vs reboot $(instance_id $instance_name)
fi
}

# axiom-power axiom-images
instance_id() {
    name="$1"
    instances | jq ".[] | select(.hostname==\"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
cat << EOF
RAM: 2048, 4096, 8192, 16384, 32768, 64512
CPU: 1, 2, 4, 8, 16, 32, 48
EOF
}

###################################################################
# experimental v2 function
# deletes multiple instances at the same time by name, if the second argument is set to "true", will not prompt
# used by axiom-rm --multi
#
delete_instances() {
    names="$1"
    force="$2"

    # Declare an array to store instance IDs
    instance_ids=()

    # Get the instance IDs for the given names
    ibmcloud_cli_output=$(ibmcloud sl vs list --output JSON)
    for name in $names; do
        ids=$(echo "$ibmcloud_cli_output" | jq -r ".[] | select(.hostname==\"$name\") | .id")
        if [ -n "$ids" ]; then
            for id in $ids; do
                instance_ids+=("$id")
            done
        else
            echo -e "${BRed}Error: No IBM Cloud instance found with the given name: '$name'.${BRed}"
        fi
    done

    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting: $names...${Color_Off}"
        for id in "${instance_ids[@]}"; do
            ibmcloud sl vs cancel "$id" -f >/dev/null 2>&1 &
        done
    else
        for id in "${instance_ids[@]}"; do
            instance_name=$(echo "$ibmcloud_cli_output" | jq -r ".[] | select(.id==$id) | .hostname")
            read -p "Are you sure you want to delete instance '$instance_name' (ID: $id)? (y/N): " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo "Instance deletion aborted for instance '$instance_name' (ID: $id)."
                continue
            fi

            echo -e "${Red}Deleting: '$instance_name' (ID: $id)...${Color_Off}"
            ibmcloud sl vs cancel "$id" -f &
        done
    fi
# wait until all background jobs are finished deleting
wait
}

###################################################################
# experimental v2 function
# create multiple instances at the same time
# used by axiom-fleet
#
create_instances() {
    image_id="$1"
    size="$2"
    region="$3"
    user_data="$4"
    timeout="$5"
    shift 5
    names=("$@")  # Remaining arguments are instance names

    domain="ax.private"
    cpu="$(jq -r '.cpu' $AXIOM_PATH/axiom.json)"
    count="${#names[@]}"
    sleep 5

    # Create temporary base hostname
    base_hostname="axiom-temp-$(date +%s)"

    # Create multiple instances in one command and capture the output in JSON
    instance_data=$(ibmcloud sl vs create -H "$base_hostname" -D "$domain" -c "$cpu" -m "$size" -n 1000 -d "$region" --image "$image_id" --userdata "$user_data" --quantity "$count" -f)

    # Extract instance IDs from the creation response
    instance_ids=($(echo "$instance_data" | grep $base_hostname | awk '{print $1}'))

    # Verify we got the expected number of instances
    if [ "${#instance_ids[@]}" -ne "$count" ]; then
        echo "Error: Expected $count instances but got ${#instance_ids[@]}"
        return 1
    fi

    processed_file=$(mktemp)
    interval=10   # Time between status checks
    elapsed=0

    # Monitor instance status and rename instances-output JSON
    while [ "$elapsed" -lt "$timeout" ]; do
        all_ready=true
        current_statuses=$(ibmcloud sl vs list --column id --column public_ip --column power_state --output JSON)

        for i in "${!instance_ids[@]}"; do
            id="${instance_ids[$i]}"
            new_name="${names[$i]}"

            # Get instance details
            instance_data=$(echo "$current_statuses" | jq -r ".[] | select(.id==$id)")
            state=$(echo "$instance_data" | jq -r '.powerState.name // empty')
            ip=$(echo "$instance_data" | jq -r '.primaryIpAddress // "N/A"')

            if [[ "$state" == "Running" ]]; then
                # Rename the instance if we haven't already
                if ! grep -q "^$new_name\$" "$processed_file"; then
                    ibmcloud sl vs edit "$id" --hostname "$new_name" 2>&1 >>/dev/null
                    echo "$new_name" >> "$processed_file"
                    >&2 echo -e "${BWhite}Initialized instance '${BGreen}$new_name${Color_Off}${BWhite}' at IP '${BGreen}${ip}${BWhite}'!"
                fi
            else
                # If any instance is not ACTIVE, we must keep waitingreson
                all_ready=false
            fi
        done

        # If all instances are running and renamed, we're done
        if $all_ready; then
            rm -f "$processed_file"
            sleep 30
            return 0
        fi

        # Otherwise, sleep and increment elapsed
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    # If we get here, not all instances became active before timeout
    rm -f "$processed_file"
    return 1
}
