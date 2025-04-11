#!/bin/bash

AXIOM_PATH="$HOME/.axiom"

###################################################################
#  Create Instance is likely the most important provider function :)
#  needed for init and fleet
#
create_instance() {
    local name="$1"
    local image_id="$2"
    local size="$3"
    local region="$4"
    local user_data="$5"

    # Read security group information from axiom.json
    local security_group_name
    local security_group_id
    security_group_name="$(jq -r '.security_group_name' "$AXIOM_PATH/axiom.json")"
    security_group_id="$(jq -r '.security_group_id' "$AXIOM_PATH/axiom.json")"

    # Create a temporary file for user_data
    local user_data_file
    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"

    # Extract SSH key info from axiom.json and derive its fingerprint
    local sshkey
    local pubkey_path
    local sshkey_fingerprint
    local keyid
    sshkey="$(jq -r '.sshkey' "$AXIOM_PATH/axiom.json")"
    pubkey_path="$HOME/.ssh/$sshkey.pub"
    sshkey_fingerprint="$(
        ssh-keygen -l -E md5 -f "$pubkey_path" \
        | awk '{print $2}' \
        | cut -d':' -f2-
    )"

    # Check if this SSH key is already registered, otherwise register it
    keyid="$(
        exo compute ssh-key list \
            -O text \
            --output-template 'Name: {{.Name}} | Fingerprint: {{.Fingerprint}}' \
        | grep "$sshkey_fingerprint" \
        | awk '{print $2}'
    )"

    if [[ -z "$keyid" ]]; then
        keyid="$(
            exo compute ssh-key register "$sshkey" "$pubkey_path" \
                -O text \
                --output-template '{{.Name}}' 2>/dev/null
        )"

        # If registration fails, retry with a slightly modified key name
        if [[ $? -ne 0 ]]; then
            sshkey="$sshkey+$RANDOM"
            keyid="$(
                exo compute ssh-key register "$sshkey" "$pubkey_path" \
                    -O text \
                    --output-template '{{.Name}}' 2>/dev/null
            )"
            rm -f "$user_data_file"
            return 1
        fi
    fi

    # Determine whether to use the security group name or ID
    local security_group_option
    if [[ -n "$security_group_name" && "$security_group_name" != "null" ]]; then
        security_group_option="--security-group $security_group_name"
    elif [[ -n "$security_group_id" && "$security_group_id" != "null" ]]; then
        security_group_option="--security-group $security_group_id"
    else
        echo "Error: Both security_group_name and security_group_id are missing or invalid in axiom.json."
        rm -f "$user_data_file"
        return 1
    fi

    # Create (launch) the instance
    if ! exo compute instance create "$name" \
        --template "$image_id" \
        --template-visibility "private" \
        --instance-type "$size" \
        --zone "$region" \
        $security_group_option \
        --ssh-key "$keyid" \
        --quiet \
        --cloud-init "$user_data_file" 2>&1 >> /dev/null; then

        echo "Error: Failed to launch instance '$name' in region '$region'."
        rm -f "$user_data_file"
        return 1
    fi

    # Allow time for instance initialization
    sleep 260

    # Clean up
    rm -f "$user_data_file"
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

    exo compute instance delete "$id" -f 2>&1 >> /dev/null
}

###################################################################
# Instances functions
# used by many functions in this file
instances() {
        exo compute instance list -O json
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
        name="$1"
        instances | jq -r ".[] | select(.name == \"$name\") | .ip_address"
}

# used by axiom-select axiom-ls
instance_list() {
        instances | jq -r ' .[] | .name'
}

instance_pretty() {
    header="Instance,Primary IP,Region,Type,Status,\$/H,\$/M"
    fields=".[]
             | [.name, .ip_address, .zone, .type, .state]
             | @csv"

    data=$(instances | jq -r "$fields" | sort -t',' -k1)

    # Fetch pricing into temp file
    pricing_tmp=$(mktemp)
    curl -s https://portal.exoscale.com/api/pricing/opencompute | \
        jq -r '.usd | to_entries[] | "\(.key)=\(.value)"' > "$pricing_tmp"

    total_hourly=0
    total_monthly=0
    output=""

    while IFS=',' read -r name ip region type status; do
        [ -z "$type" ] && continue

        type_clean=$(echo "$type" | tr -d '"')
        short_type="${type_clean#standard.}"
        short_type="${short_type#cpu.}"
        short_type="${short_type#memory.}"

        # Lookup pricing manually
        hr_cost=$(grep -F "running_${short_type}=" "$pricing_tmp" | cut -d '=' -f2)
        hr_cost=${hr_cost:-0}
        mo_cost=$(echo "scale=4; $hr_cost * 730" | bc)

        total_hourly=$(echo "scale=4; $total_hourly + $hr_cost" | bc)
        total_monthly=$(echo "scale=2; $total_monthly + $mo_cost" | bc)

        hr_fmt=$(printf "%.4f" "$hr_cost")
        mo_fmt=$(printf "%.2f" "$mo_cost")

        output+="$name,$ip,$region,$type_clean,$status,\$$hr_fmt,\$$mo_fmt"$'\n'
    done <<< "$data"

    rm -f "$pricing_tmp"

    numInstances=$(echo -n "$output" | grep -c '^[^_[:space:]]')
    total_hr_fmt=$(printf "%.4f" "$total_hourly")
    total_mo_fmt=$(printf "%.2f" "$total_monthly")
    footer="_,_,_,Instances,$numInstances,\$$total_hr_fmt,\$$total_mo_fmt"

    {
        echo "$header"
        if [ -n "$output" ]; then
            echo "$output"
        fi
        echo "$footer"
    } | sed 's/"//g' | column -t -s,
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

    echo "$droplets" | jq -c '.[]?' | while read -r instance; do
        # extract fields
        name=$(echo "$instance" | jq -r '.name? // empty' 2>/dev/null | head -n 1)
        public_ip=$(echo "$instance" | jq -r '.ip_address? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$instance" | jq -r '.ip_address? // empty' 2>/dev/null  | head -n 1)

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
            matches=$(echo "$droplets" | jq -r '.[].name' | \
             grep -E "^${var}$")
        else
            matches=$(echo "$droplets" | jq -r '.[].name' | \
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
#
# used by axiom-fleet axiom-init
get_image_id() {
    query="$1"
    images=$(exo compute instance-template list -v private -O json)

    # Get the most recent image matching the query
    name=$(echo "$images" | jq -r '.[].name' | grep -wx "$query" | tail -n 1)
    id=$(echo "$images" | jq -r ".[] | select(.name==\"$name\") | .id")

    echo "$id"
}

###################################################################
# Manage snapshots
# used for axiom-images
#
# get JSON data for snapshots
snapshots() {
    exo compute instance-template list -v private -O json
}

# used by axiom-images
get_snapshots()
{
    exo compute instance-template list -v private
}

# Delete a snapshot by its name
# used by  axiom-images
delete_snapshot() {
    name="$1"
    image_id=$(get_image_id "$name")
    exo compute instance-template delete "$image_id" -f
}

# axiom-images
create_snapshot() {
    instance="$1"
    snapshot_name="$2"
    snapshot_id=$(exo compute instance snapshot create "$(instance_id $instance)" -O text --output-template '{{.ID}}' 2>/dev/null)
    exo compute instance-template register "$snapshot_name" --from-snapshot "$snapshot_id"
}

# transfer snapshot to new region
# used by ax fleet2
#transfer_snapshot() {
# TODO
#}

###################################################################
# Get data about regions
# used by axiom-regions
list_regions() {
    exo zones
}

# used by axiom-regions
regions() {
    exo zones -O json | jq -r '.[].name'
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
  instance_name="$1"
  id=$(instance_id "$instance_name")
  exo compute instance start "$id" -f
}

# axiom-power
poweroff() {
  instance_name="$1"
  id=$(instance_id "$instance_name")
  exo compute instance stop "$id" -f
}

# axiom-power
reboot() {
  instance_name="$1"
  id=$(instance_id "$instance_name")
  exo compute instance reboot "$id" -f
}

# axiom-power axiom-images
instance_id() {
  name="$1"
  instances | jq -r ".[] | select(.name == \"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
    {
        echo -e "InstanceType\tvCPUs\tMemory"
        exo compute instance-type list -O json \
            | jq -r '.[] | select(.authorized != false) | [.family, .name, .cpus, .memory] | @csv' \
            | tr -d '"' \
            | awk -F',' '{printf "%s.%s\t%s\t%.2f GB\n", $1, $2, $3, $4 / 1073741824}'
    } | column -t -s $'\t'
}

###################################################################
# experimental v2 function
# deletes multiple instances at the same time by name, if the second argument is set to "true", will not prompt
# used by axiom-rm --multi
#
delete_instances() {
    local names="$1"
    local force="$2"

    # Convert space-separated names string into array manually (portable)
    set -- $names
    name_array=("$@")

    # Retrieve all instances
    all_instances="$(instances)"

    all_instance_ids=()
    all_instance_names=()

    for name in "${name_array[@]}"; do
        instance_info="$(echo "$all_instances" | jq -r --arg name "$name" '.[] | select(.name | test($name))')"

        if [ -n "$instance_info" ]; then
            instance_id="$(echo "$instance_info" | jq -r '.id')"
            instance_name="$(echo "$instance_info" | jq -r '.name')"
            all_instance_ids+=( "$instance_id" )
            all_instance_names+=( "$instance_name" )
        else
            echo -e "${BRed}Warning: No Exoscale instance found for the name '$name'.${Color_Off}"
        fi
    done

    if [ "$force" = "true" ]; then
        echo -e "${Red}Deleting: ${all_instance_names[*]}...${Color_Off}"
        i=0
        while [ $i -lt ${#all_instance_names[@]} ]; do
            instance_name="${all_instance_names[$i]}"
            instance_id="${all_instance_ids[$i]}"
            exo compute instance delete "$instance_id" -f -Q &
            i=$((i + 1))
        done
        wait
    else
        confirmed_instance_ids=()
        confirmed_instance_names=()
        i=0
        while [ $i -lt ${#all_instance_names[@]} ]; do
            instance_name="${all_instance_names[$i]}"
            instance_id="${all_instance_ids[$i]}"
            echo -n "Are you sure you want to delete $instance_name (y/N) - default NO: "
            read -r ans
            if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                confirmed_instance_ids+=( "$instance_id" )
                confirmed_instance_names+=( "$instance_name" )
            else
                echo "Deletion aborted for $instance_name."
            fi
            i=$((i + 1))
        done

        if [ ${#confirmed_instance_ids[@]} -gt 0 ]; then
            echo -e "${Red}Deleting: ${confirmed_instance_names[*]}...${Color_Off}"
            i=0
            while [ $i -lt ${#confirmed_instance_names[@]} ]; do
                instance_name="${confirmed_instance_names[$i]}"
                instance_id="${confirmed_instance_ids[$i]}"
                exo compute instance delete "$instance_id" -f -Q &
                i=$((i + 1))
            done
            wait
        else
            echo -e "${BRed}No instances were confirmed for deletion.${Color_Off}"
        fi
    fi
}

###################################################################
# experimental v2 function
# create multiple instances at the same time
# used by axiom-fleet2
#
create_instances() {
    local image_id="$1"
    local size="$2"
    local region="$3"
    local user_data="$4"
    local timeout="$5"
    shift 5

    names=("$@")  # Remaining arguments are instance names
    pids_data=()  # Will store "pid:name:tmpfile"
    created_names=()
    notified_names=()

    # Create the user-data file
    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"

    # Ensure SSH key exists in Exoscale
    sshkey="$(jq -r '.sshkey' "$AXIOM_PATH/axiom.json")"
    pubkey_path="$HOME/.ssh/$sshkey.pub"
    if [ ! -f "$pubkey_path" ]; then
        >&2 echo -e "${BRed}Error: SSH public key not found at $pubkey_path${Color_Off}"
        rm -f "$user_data_file"
        return 1
    fi

    sshkey_fingerprint="$(ssh-keygen -l -E md5 -f "$pubkey_path" | awk '{print $2}' | cut -d':' -f2-)"
    keyid=$(exo compute ssh-key list -O text --output-template 'Name: {{.Name}} | Fingerprint: {{.Fingerprint}}' | grep "$sshkey_fingerprint" | awk '{print $2}')
    if [ -z "$keyid" ]; then
        keyid=$(exo compute ssh-key register "$sshkey" "$pubkey_path" -O text --output-template '{{.Name}}' 2>/dev/null)
        if [ -z "$keyid" ]; then
            >&2 echo -e "${BRed}Error: Failed to create SSH key in Exoscale${Color_Off}"
            rm -f "$user_data_file"
            return 1
        fi
    fi

    # Determine whether to use security_group_name or security_group_id
    security_group_name="$(jq -r '.security_group_name' "$AXIOM_PATH/axiom.json")"
    security_group_id="$(jq -r '.security_group_id' "$AXIOM_PATH/axiom.json")"
    if [[ -n "$security_group_name" && "$security_group_name" != "null" ]]; then
        security_group_option="--security-group $security_group_name"
    elif [[ -n "$security_group_id" && "$security_group_id" != "null" ]]; then
        security_group_option="--security-group $security_group_id"
    else
        echo "Error: Both security_group_name and security_group_id are missing or invalid in axiom.json."
        rm -f "$user_data_file"
        return 1
    fi

    for name in "${names[@]}"; do
        tmpfile=$(mktemp)
        (
            exo compute instance create "$name" \
                --template "$image_id" \
                --template-visibility "private" \
                --instance-type "$size" \
                --zone "$region" \
                $security_group_option \
                --ssh-key "$keyid" \
                --cloud-init "$user_data_file" \
                -O json 2>&1
        ) >"$tmpfile" 2>&1 &
        pid=$!
        pids_data+=( "$pid:$name:$tmpfile" )
    done

    total=${#pids_data[@]}
    completed=0
    success_count=0
    fail_count=0

    already_notified() {
        local x
        for x in "${notified_names[@]}"; do
            [ "$x" = "$1" ] && return 0
        done
        return 1
    }

    mark_notified() {
        notified_names+=( "$1" )
    }

    is_expected_name() {
        for expected in "${names[@]}"; do
            [ "$expected" = "$1" ] && return 0
        done
        return 1
    }

    elapsed=0
    interval=8

    # Check which creation processes finished
    while [ "$elapsed" -lt "$timeout" ]; do
        still_running=()
        for entry in "${pids_data[@]}"; do
            pid="${entry%%:*}"
            rest="${entry#*:}"
            nm="${rest%%:*}"
            file="${rest#*:}"

            if kill -0 "$pid" 2>/dev/null; then
                still_running+=( "$entry" )
            else
                wait "$pid"
                exit_code=$?
                completed=$((completed + 1))

                output="$(cat "$file" 2>/dev/null)"
                rm -f "$file"

                if [ "$exit_code" -eq 0 ]; then
                    success_count=$((success_count + 1))
                    created_names+=( "$nm" )
                else
                    fail_count=$((fail_count + 1))
                    >&2 echo -e "${BRed}Error creating instance '$nm':${Color_Off}"
                    >&2 echo "$output"
                fi
                if [ "$fail_count" -eq "$total" ]; then
                    >&2 echo -e "${BRed}Error: All $total instance(s) failed to create.${Color_Off}"
                    rm -f "$user_data_file"
                    return 1
                fi
            fi
        done
        pids_data=( "${still_running[@]}" )

        if [ "${#created_names[@]}" -gt 0 ]; then
            servers_json="$(exo compute instance list -O json 2>/dev/null)"
            server_lines="$(echo "$servers_json" | jq -c '.[] | {name: .name, status: .state, ip: .ip_address}')"

            # each line is like {"name":"host1","status":"running","ip":"X.X.X.X"}
            IFS=$'\n'
            for line in $server_lines; do
                name="$(echo "$line" | jq -r '.name')"
                status="$(echo "$line" | jq -r '.status')"
                ip="$(echo "$line" | jq -r '.ip')"

                # only handle if name is in created_names
                # and not yet "notified"
                if is_expected_name "$name" && ! already_notified "$name"; then
                    if [ "$status" = "running" ] && [ -n "$ip" ] && [ "$ip" != "null" ]; then
                        mark_notified "$name"
                        >&2 echo -e "${BWhite}Initialized instance '${BGreen}$name${Color_Off}${BWhite}' at '${BGreen}$ip${BWhite}'!${Color_Off}"
                    fi
                fi
            done
            IFS=$' \t\n'
        fi

        if [ "$completed" -eq "$total" ]; then
            all_running=true
            for name in "${names[@]}"; do
                if ! already_notified "$name"; then
                    all_running=false
                    break
                fi
            done
            $all_running && break
        fi

        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    rm -f "$user_data_file"

    if [ "$fail_count" -eq "$total" ]; then
        >&2 echo -e "${BRed}Error: All $total instance(s) failed to create.${Color_Off}"
        return 1
    fi

    if [ "$fail_count" -gt 0 ]; then
        >&2 echo -e "${BRed}Warning: $fail_count instance(s) failed, $success_count succeeded.${Color_Off}"
        return 1
    fi

    >&2 echo -e "${BGreen}Success: All $success_count instance(s) created and running!${Color_Off}"
    return 0
}
