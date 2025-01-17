#!/bin/bash

AXIOM_PATH="$HOME/.axiom"

###################################################################
#  Create one instance at a time
#
#  needed for axiom-init
create_instance() {
        name="$1"
        image_id="$2"
        size_slug="$3"
        region="$4"
        user_data="$5"

        # import pub ssh key or get ssh key fingerprint for DO to avoid emails
        sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"
        sshkey_fingerprint="$(ssh-keygen -l -E md5 -f ~/.ssh/$sshkey.pub | awk '{print $2}' | cut -d : -f 2-)"
        keyid=$(doctl compute ssh-key import $sshkey \
         --public-key-file ~/.ssh/$sshkey.pub \
         --format ID \
         --no-header 2>/dev/null) ||
        keyid=$(doctl compute ssh-key list | grep "$sshkey_fingerprint" | awk '{ print $1 }')

        doctl compute droplet create "$name" --image "$image_id" --size "$size" --region "$region" --enable-ipv6 --ssh-keys "$keyid" --user-data "$user_data" >/dev/null
        sleep 260
}

###################################################################
# deletes instance, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instance() {
        name="$1"
        force="$2"

        if [ "$force" == "true" ]
        then
         doctl compute droplet delete -f "$name"
        else
        doctl compute droplet delete "$name"
        fi
}

###################################################################
# Instances functions
# used by many functions in this file
instances() {
        doctl compute droplet list -o json
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
        name="$1"
        instances | jq -r ".[]? | select(.name==\"$name\") | .networks.v4[]? | select(.type==\"public\") | .ip_address" | head -1
}

# used by axiom-select axiom-ls
instance_list() {
        instances | jq -r '.[].name'
}

# used by axiom-ls
instance_pretty() {
        data=$(instances)

        #number of droplets
        droplets=$(echo $data|jq -r '.[]|.name'|wc -l )

        i=0
        for f in $(echo $data | jq -r '.[].size.price_monthly'); do new=$(expr $i + $f); i=$new; done
        totalPrice=$i
        header="Instance,Primary Ip,Backend Ip,Region,Size,Status,\$/M"

	fields=".[] | [.name, (try (.networks.v4[] | select(.type==\"public\") | .ip_address) catch \"N/A\"),  (try (.networks.v4[] | select(.type==\"private\") | .ip_address) catch \"N/A\"), .region.slug, .size_slug, .status, .size.price_monthly] | @csv"

        totals="_,_,_,Instances,$droplets,Total,\$$totalPrice"
        #data is sorted by default by field name
        data=$(echo $data | jq  -r "$fields")
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
        name=$(echo "$droplet" | jq -r '.name? // empty' 2>/dev/null)
        public_ip=$(echo "$droplet" | jq -r '.networks.v4[]? | select(.type=="public") | .ip_address? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$droplet" | jq -r '.networks.v4[]? | select(.type=="private") | .ip_address? // empty' 2>/dev/null | head -n 1)

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
        images=$(doctl compute snapshot list -o json)
        name=$(echo $images | jq -r ".[].name" | grep -wx "$query" | tail -n 1)
        id=$(echo $images |  jq -r ".[] | select(.name==\"$name\") | .id")
        echo $id
}

###################################################################
# Manage snapshots
# used for axiom-images and axiom-backup
#
snapshots() {
        doctl compute snapshot list -o json
}

# axiom-images
get_snapshots()
{
        doctl compute snapshot list
}

# axiom-images
delete_snapshot() {
        name="$1"
        image_id=$(get_image_id "$name")
        doctl compute snapshot delete "$image_id" -f
}

# axiom-images
create_snapshot() {
        instance="$1"
	snapshot_name="$2"
	doctl compute droplet-action snapshot "$(instance_id $instance)" --snapshot-name "$snapshot_name"
}

###################################################################
# Get data about regions
# used by axiom-regions
list_regions() {
    doctl compute region list
}

# used by axiom-regions
regions() {
    doctl compute region list -o json | jq -r '.[].slug'
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
        instance_name="$1"
        doctl compute droplet-action power-on $(instance_id $instance_name)
}

# axiom-power
poweroff() {
        instance_name="$1"
        doctl compute droplet-action power-off $(instance_id $instance_name)
}

# axiom-power
reboot(){
        instance_name="$1"
        doctl compute droplet-action reboot $(instance_id $instance_name)
}

# axiom-power axiom-images
instance_id() {
        name="$1"
        instances | jq ".[] | select(.name==\"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
   doctl compute size list
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

    # Make a single call to get all DigitalOcean droplets
    all_droplets=$(doctl compute droplet list --format "ID,Name" --no-header)

    # Declare arrays to store droplet IDs and names for deletion
    all_droplet_ids=()
    all_droplet_names=()

    # Iterate over all droplets and filter by the provided names
    for name in "${name_array[@]}"; do
        matching_droplets=$(echo "$all_droplets" | awk -v name="$name" '$2 == name {print $1, $2}')

        if [ -n "$matching_droplets" ]; then
            while IFS=' ' read -r droplet_id droplet_name; do
                all_droplet_ids+=("$droplet_id")
                all_droplet_names+=("$droplet_name")
            done <<< "$matching_droplets"
        else
            echo -e "${BRed}Warning: No DigitalOcean droplet found with the name '$name'.${Color_Off}"
        fi
    done

    # Force deletion: Delete all droplets without prompting
    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting: ${all_droplet_names[@]}...${Color_Off}"
        doctl compute droplet delete -f "${all_droplet_ids[@]}" >/dev/null 2>&1

    # Prompt for each droplet if force is not true
    else
        # Collect droplets for deletion after user confirmation
        confirmed_droplet_ids=()
        confirmed_droplet_names=()

        for i in "${!all_droplet_ids[@]}"; do
            droplet_id="${all_droplet_ids[$i]}"
            droplet_name="${all_droplet_names[$i]}"

            echo -e -n "Are you sure you want to delete Droplet $droplet_name (Droplet ID: $droplet_id) (y/N) - default NO: "
            read ans
            if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                confirmed_droplet_ids+=("$droplet_id")
                confirmed_droplet_names+=("$droplet_name")
            else
                echo "Deletion aborted for $droplet_name."
            fi
        done

        # Delete confirmed droplets in bulk
        if [ ${#confirmed_droplet_ids[@]} -gt 0 ]; then
            echo -e "${Red}Deleting: ${confirmed_droplet_names[@]}...${Color_Off}"
            doctl compute droplet delete -f "${confirmed_droplet_ids[@]}"
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
    local all_names=("$@")

    # Retrieve SSH key info
    local sshkey
    sshkey="$(jq -r '.sshkey' < "$AXIOM_PATH/axiom.json")"

    local sshkey_fingerprint
    sshkey_fingerprint="$(ssh-keygen -l -E md5 -f ~/.ssh/"$sshkey".pub \
                          | awk '{print $2}' | cut -d : -f 2-)"

    local keyid
    keyid="$(doctl compute ssh-key import "$sshkey" \
        --public-key-file ~/.ssh/"$sshkey".pub \
        --format ID \
        --no-header 2>/dev/null)" ||
    keyid="$(doctl compute ssh-key list | grep "$sshkey_fingerprint" | awk '{print $1}')"

    get_droplet_usage_and_limit() {
        # droplet_used => how many droplets are currently running
        droplet_used="$(doctl compute droplet list --no-header 2>/dev/null | wc -l | awk '{print $1}')"
        if [ -z "$droplet_used" ]; then
            droplet_used=0
        fi

        # droplet_limit => maximum your account allows
        local acc_json
        acc_json="$(doctl account get --output json 2>/dev/null)"
        droplet_limit="$(echo "$acc_json" | jq -r '.droplet_limit // 0')"
        if [ -z "$droplet_limit" ] || [ "$droplet_limit" = "null" ]; then
            droplet_limit=0
        fi
    }

    # BATCHING
    local total=${#all_names[@]}
    local chunk_size=200
    local start=0

    local pids=()         # background PIDs
    local batch_files=()  # output files
    local parsed=()       # 0 => not parsed, 1 => parsed
    local batch_index=0

    while [ $start -lt $total ]; do
        local end=$((start + chunk_size))
        if [ $end -gt $total ]; then
            end=$total
        fi

        # This subset of names is up to 200
        local batch=("${all_names[@]:$start:$((end - start))}")

        # Check how many droplets we can still create:
        get_droplet_usage_and_limit
        local capacity=$((droplet_limit - droplet_used))

        if [ $capacity -le 0 ]; then
            # No more capacity => 0 droplet creation
            echo -e "${BRed}No capacity left. This batch #$batch_index will create 0 droplets.${Color_Off}"
            local outfile
            outfile="$(mktemp -t ax_fleet2_batch_${batch_index}.XXXX)"
            echo "No droplets created (capacity=0)" >"$outfile"

            pids+=(0)  # no real process
            batch_files+=("$outfile")
            parsed+=(0)

        else
            # If we have capacity but the batch is bigger => reduce the batch
            if [ ${#batch[@]} -gt $capacity ]; then
                echo -e  "${BYellow}Warning: Reducing droplets created by $(( ${#batch[@]} - capacity )) to avoid exceeding capacity limits.${Color_Off}"
                batch=( "${batch[@]:0:$capacity}" )
            fi

            if [ ${#batch[@]} -eq 0 ]; then
                # Means capacity was smaller than 1 => skip
                local outfile
                outfile="$(mktemp -t ax_fleet2_batch_${batch_index}.XXXX)"
                echo -e  "No droplets created (capacity=0)" >"$outfile"

                pids+=(0)
                batch_files+=("$outfile")
                parsed+=(0)

            else

                local outfile
                outfile="$(mktemp -t ax_fleet2_batch_${batch_index}.XXXX)"
                (
                    doctl compute droplet create "${batch[@]}" \
                        --image "$image_id" \
                        --size "$size" \
                        --region "$region" \
                        --enable-ipv6 \
                        --ssh-keys "$keyid" \
                        --format ID,Name \
                        --no-header \
                        --user-data "$user_data"
                ) >"$outfile" 2>&1 &

                local pid=$!
                pids+=("$pid")
                batch_files+=("$outfile")
                parsed+=(0)
            fi
        fi

        batch_index=$((batch_index + 1))
        start=$end

        # Sleep 60s before next batch
        if [ $start -lt $total ]; then
            sleep 60
        fi
    done

    local num_batches=${#pids[@]}

    # POLLING
    local all_instance_ids=()
    local all_instance_names=()
    local processed_file
    processed_file="$(mktemp -t ax_fleet2_proc.XXXX)"

    local start_time
    start_time="$(date +%s)"
    local interval=8

    # parse_doctl_output -> numeric-check to skip lines like "No droplets created"
    parse_doctl_output() {
        local file="$1"
        local count=0
        while IFS= read -r line; do
            # Example valid line: "1234567 cannon01"
            # Example invalid line: "No droplets created (capacity=0)"
            local did
            local dname
            did="$(echo "$line" | awk '{print $1}')"
            dname="$(echo "$line" | awk '{print $2}')"

            # Skip empty or partial lines
            if [ -z "$did" ] || [ -z "$dname" ]; then
                continue
            fi

            # Only proceed if first field is numeric
            if ! [[ "$did" =~ ^[0-9]+$ ]]; then
                continue
            fi

            all_instance_ids+=( "$did" )
            all_instance_names+=( "$dname" )
            count=$((count + 1))
        done < "$file"
    }

    # Main loop: check background processes, parse output, poll droplets
    while true; do
        local now
        now="$(date +%s)"
        local elapsed=$(( now - start_time ))

        # Check each batch
        local still_running=0
        local b
        for b in "${!pids[@]}"; do
            local pid="${pids[$b]}"
            if [ "$pid" -eq 0 ]; then
                # This batch created 0 => parse once if not done
                if [ "${parsed[$b]}" -eq 0 ]; then
                    parse_doctl_output "${batch_files[$b]}"
                    parsed[$b]=1
                fi
                continue
            fi

            # If pid != 0, check if it's still running
            if kill -0 "$pid" 2>/dev/null; then
                still_running=$((still_running + 1))
            else
                # If done & not parsed, parse
                if [ "${parsed[$b]}" -eq 0 ]; then
                    parse_doctl_output "${batch_files[$b]}"
                    parsed[$b]=1
                fi
            fi
        done

        # Poll all known droplets
        if [ ${#all_instance_ids[@]} -gt 0 ]; then
            local current_statuses
            current_statuses="$(doctl compute droplet list \
                --format ID,Name,Status,PublicIPv4 \
                --no-header 2>/dev/null)"
            if [ -n "$current_statuses" ]; then
                local all_ready=true
                local i
                for i in "${!all_instance_ids[@]}"; do
                    local did="${all_instance_ids[$i]}"
                    local dname="${all_instance_names[$i]}"
                    local status
                    local ip
                    status="$(echo "$current_statuses" \
                        | awk -v droplet_id="$did" '$1 == droplet_id {print $3}')"
                    ip="$(echo "$current_statuses" \
                        | awk -v droplet_id="$did" '$1 == droplet_id {print $4}')"

                    if [ "$status" = "active" ]; then
                        if ! grep -qx "$dname" "$processed_file"; then
                            echo "$dname" >> "$processed_file"
                           >&2 echo -e "${BWhite}Initialized instance '${BGreen}$dname${Color_Off}${BWhite}' at '${BGreen}$ip${BWhite}'!"
                        fi
                    else
                        all_ready=false
                    fi
                done

                # If no more processes AND all known droplets are active => done
                if [ "$still_running" -eq 0 ] && $all_ready; then
                    echo -e "${BGreen}All known droplets are active, and all batches are done! Please wait..${Color_Off}"
                    rm -f "$processed_file"
                    return 0
                fi
            fi
        else
            # No known droplets yet. If no processes running => done
            if [ "$still_running" -eq 0 ]; then
                echo "No droplets created at all. Exiting."
                return 0
            fi
        fi

        # Check timeout
        if [ "$elapsed" -ge "$timeout" ]; then
            echo "ERROR: Timed out waiting for droplets to become active."
            return 1
        fi

        # D) Sleep
        sleep "$interval"
    done
}
