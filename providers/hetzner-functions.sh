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

    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"

    # import pub ssh key or get ssh key fingerprint for Hetzner to avoid emails
    sshkey="$(jq -r '.sshkey' "$AXIOM_PATH/axiom.json")"
    pubkey_path="$HOME/.ssh/$sshkey.pub"
    sshkey_fingerprint="$(ssh-keygen -l -E md5 -f "$pubkey_path" | awk '{print $2}' | cut -d : -f 2-)"
    keyid=$(hcloud ssh-key list | grep "$sshkey_fingerprint" | awk '{ print $1 }')
    if [[ -z "$keyid" ]]; then
        keyid=$(hcloud ssh-key create --name "$sshkey" --public-key-from-file "$pubkey_path" 2>&1)
        # If there was a uniqueness error create a key with random name and use that
        if [[ "$keyid" == *"uniqueness_error"* ]]; then
            sshkey="$sshkey+$RANDOM"
            keyid=$(hcloud ssh-key create --name "$sshkey" --public-key-from-file "$pubkey_path" 2>&1)
            return 1
        fi
    fi

    hcloud server create --type "$size_slug" --location "$region" --image "$image_id" --name "$name" \
     --ssh-key "$keyid" --poll-interval 250s --quiet --without-ipv6 --user-data-from-file "$user_data_file" &

    sleep 260
}

###################################################################
# deletes instance, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instance() {
    name="$1"
    force="$2"
    id="$(instance_id "$name")"

    if [ "$force" != "true" ]; then
        read -p "Are you sure you want to delete instance '$name'? (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Instance deletion aborted."
            return 1
        fi
    fi

    hcloud server delete "$id" --poll-interval 30s --quiet &
    sleep 4
}

###################################################################
# Instances functions
# used by many functions in this file
#
# takes no arguments, outputs JSON object with instances
instances() {
	hcloud server list -o json
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
	name="$1"
	instances | jq -r ".[] | select(.name ==\"$name\") | .public_net.ipv4.ip"
}

# used by axiom-select axiom-ls
instance_list() {
        instances | jq -r '.[].name'
}

# used by axiom-ls
instance_pretty() {
  data=$(instances)
  #number of servers
  servers=$(echo $data | jq -r '.[]|.id' | wc -l)
  #default size from config file
  type="$(jq -r .default_size "$AXIOM_PATH/axiom.json")"
  #monthly price of server type 
  price=$(hcloud server-type list -o json | jq -r ".[] | select(.name == \"$type\") | .prices[0].price_monthly.net")
  totalPrice=$(echo "$price * $servers" | bc)
  header="Instance,Primary Ip,Region,Memory,Status,\$/M"
  totals="_,_,Instances,$servers,Total,\$$totalPrice"
  fields=".[] | [.name, .public_net.ipv4.ip, .datacenter.location.name, .server_type.memory, .status, \"$price\"] | @csv"

  # Printing part
  # sort -k1 sorts all data by label/instance/server name
  (echo "$header" && echo "$data" | jq -r "$fields" | sort -k1 && echo "$totals") | sed 's/"//g' | column -t -s,
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
        public_ip=$(echo "$droplet" | jq -r '.public_net?.ipv4?.ip? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$droplet" | jq -r '.private_net?.ipv4?.ip?  // empty' 2>/dev/null | head -n 1)

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
        images=$(hcloud image list -o json)
        if [[ $query == "$1" ]]; then
                id=$(echo $images |  jq -r ".[] | select((.description==\"$query\") and (.architecture==\"x86\")) | .id")
        else
        id=$(echo $images |  jq -r ".[] | select((.name==\"$query\") and (.architecture==\"x86\")) | .id")
        fi
        echo $id
}

###################################################################
# Manage snapshots
# used for axiom-images
#
get_snapshots()
{
        hcloud image list -t snapshot
}

# Delete a snapshot by its name
# axiom-images
delete_snapshot() {
        name="$1"
        hcloud image delete "$(get_image_id $1)"
}


# axiom-images
create_snapshot() {
        instance="$1"
	snapshot_name="$2"
        hcloud server create-image  --type snapshot $instance --description $snapshot_name
}

###################################################################
# Get data about regions
# used by axiom-regions
list_regions() {
    hcloud location list
}

# used for axiom-region
regions() {
    hcloud location list -o json | jq -r '.[].name'
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
    instance_name="$1"
    hcloud server poweron $(instance_id $instance_name)
}

# axiom-power
poweroff() {
    instance_name="$1"
    hcloud server shutdown $(instance_id $instance_name)
}

# axiom-power
reboot(){
    instance_name="$1"
    hcloud server reboot $(instance_id $instance_name)
}

# axiom-power axiom-images
instance_id() {
        name="$1"
        instances | jq ".[] | select(.name ==\"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
  hcloud server-type list --output json | jq -r '
    [
      "Name","Cores","Memory (GB)","Disk (GB)",
      "CPU Type","Architecture","Price (€/Month)",
      "Price (€/Hour)","Price per TB Traffic (€/TB)","Locations"
    ],
    (
      .[] | [
        .name, .cores, .memory, .disk,
        .cpu_type, .architecture,
        (.prices[0].price_monthly.net         | tonumber),
        (.prices[0].price_hourly.net          | tonumber),
        (.prices[0].price_per_tb_traffic.net  | tonumber),
        ([ .prices[].location ] | unique | sort | join(", "))
      ]
    )
    | @tsv
  ' | iconv -c -t UTF-8 | column -t -s $'\t'
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

    # Make a single call to get all Hetzner instances
    all_instances=$(instances)

    # Declare arrays to store server names and IDs for deletion
    all_instance_ids=()
    all_instance_names=()

    # Iterate over all instances and filter by the provided names
    for name in "${name_array[@]}"; do
        instance_info=$(echo "$all_instances" | jq -r --arg name "$name" '.[] | select(.name | test($name))')

        if [ -n "$instance_info" ]; then
            instance_id=$(echo "$instance_info" | jq -r '.id')
            instance_name=$(echo "$instance_info" | jq -r '.name')

            all_instance_ids+=("$instance_id")
            all_instance_names+=("$instance_name")
        else
            echo -e "${BRed}Warning: No Hetzner Cloud instance found for the name '$name'.${Color_Off}"
        fi
    done

    # Force deletion: Delete all instances without prompting
    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting: ${all_instance_names[@]}...${Color_Off}"
        hcloud server delete "${all_instance_ids[@]}" --poll-interval 30s --quiet >/dev/null 2>&1

    # Prompt for each instance if force is not true
    else
        # Collect instances for deletion after user confirmation
        confirmed_instance_ids=()
        confirmed_instance_names=()

        for i in "${!all_instance_names[@]}"; do
            instance_name="${all_instance_names[$i]}"
            instance_id="${all_instance_ids[$i]}"

            echo -e -n "Are you sure you want to delete $instance_name (y/N) - default NO: "
            read ans
            if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                confirmed_instance_ids+=("$instance_id")
                confirmed_instance_names+=("$instance_name")
            else
                echo "Deletion aborted for $instance_name."
            fi
        done

        # Delete confirmed instances in bulk
        if [ ${#confirmed_instance_ids[@]} -gt 0 ]; then
            echo -e "${Red}Deleting: ${confirmed_instance_names[@]}...${Color_Off}"
            hcloud server delete "${confirmed_instance_ids[@]}" --poll-interval 30s --quiet
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
    local server_type="$2"
    local location="$3"
    local user_data="$4"
    local timeout="$5"
    local disk="$6"
    shift 6

    names=("$@")
    pids_data=()   # Will store "pid:name:tmpfile"
    created_names=()
    notified_names=()

    # Create the user-data file
    user_data_file=$(mktemp)
    echo "$user_data" > "$user_data_file"

    # Ensure SSH key exists in Hetzner
    sshkey="$(jq -r '.sshkey' "$AXIOM_PATH/axiom.json")"
    pubkey_path="$HOME/.ssh/$sshkey.pub"
    if [ ! -f "$pubkey_path" ]; then
        >&2 echo -e "${BRed}Error: SSH public key not found at $pubkey_path${Color_Off}"
        rm -f "$user_data_file"
        return 1
    fi

    sshkey_fingerprint="$(ssh-keygen -l -E md5 -f "$pubkey_path" | awk '{print $2}' | cut -d : -f 2-)"
    keyid="$(hcloud ssh-key list -o json | jq -r ".[] | select(.fingerprint == \"$sshkey_fingerprint\").id")"
    if [ -z "$keyid" ]; then
        keyid="$(
            hcloud ssh-key create \
                --name "$sshkey" \
                --public-key-from-file "$pubkey_path" \
                -o json 2>/dev/null \
            | jq -r '.ssh_key.id'
        )"
        if [ -z "$keyid" ]; then
            >&2 echo -e "${BRed}Error: Failed to create SSH key in Hetzner${Color_Off}"
            rm -f "$user_data_file"
            return 1
        fi
    fi

    # Spin up each server in the background.
    for name in "${names[@]}"; do
        tmpfile=$(mktemp)

        (
            hcloud server create \
                --type "$server_type" \
                --location "$location" \
                --image "$image_id" \
                --name "$name" \
                --ssh-key "$keyid" \
                --user-data-from-file "$user_data_file" \
                --without-ipv6 \
                -o json 2>&1
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

    elapsed=0
    interval=8

    while [ "$elapsed" -lt "$timeout" ]; do

        # Check which creation processes finished
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
            fi
        done
        pids_data=( "${still_running[@]}" )


        if [ "${#created_names[@]}" -gt 0 ]; then
            servers_json="$(hcloud server list -o json 2>/dev/null)"

            # parse everything in one pass
            server_lines="$(
                echo "$servers_json" \
                | jq -c '.[] | {name: .name, status: .status, ip: .public_net.ipv4.ip}'
            )"

            # each line is like {"name":"host1","status":"running","ip":"X.X.X.X"}
            IFS=$'\n'
            for line in $server_lines; do
                IFS=$' \t\n'
                name="$(echo "$line" | jq -r '.name')"
                status="$(echo "$line" | jq -r '.status')"
                ip="$(echo "$line" | jq -r '.ip')"

                # only handle if name is in created_names
                # and not yet "notified"
                if [[ " ${created_names[*]} " == *" $name "* ]]; then
                    if ! already_notified "$name"; then
                        if [ "$status" = "running" ] && [ -n "$ip" ] && [ "$ip" != "null" ]; then
                            mark_notified "$name"
                            >&2 echo -e "${BWhite}Initialized instance '${BGreen}$name${Color_Off}${BWhite}' at '${BGreen}$ip${BWhite}'!${Color_Off}"
                        fi
                    fi
                fi
            done
            IFS=$' \t\n'
        fi

        # Check if done
        done_creating=false
        if [ "$completed" -eq "$total" ] || [ "$fail_count" -eq "$total" ]; then
            done_creating=true
        fi

        if $done_creating; then
            all_running=true
            for x in "${created_names[@]}"; do
                if ! already_notified "$x"; then
                    all_running=false
                    break
                fi
            done
            if $all_running; then
                break
            fi
        fi

        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    # If timed out but some processes still run, kill them
    if [ "$elapsed" -ge "$timeout" ] && [ "${#pids_data[@]}" -gt 0 ]; then
        >&2 echo -e "${BRed}Error: Timeout reached (${elapsed}s) before creation finished or instances ran.${Color_Off}"
        rm -f "$user_data_file"
        return 1
    fi

    # Now safe to remove the user_data_file
    rm -f "$user_data_file"

    # Final checks
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
