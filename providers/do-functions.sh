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
#  Choose between generating the sshconfig using private IP details, public IP details or optionally lock
#  Lock will never generate an SSH config and only used the cached config ~/.axiom/.sshconfig
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

    declare -A name_counts

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

        # track hostnames in case of duplicates
        if [[ -n "${name_counts[$name]}" ]]; then
            count=${name_counts[$name]}
            hostname="${name}-${count}"
            name_counts[$name]=$((count + 1))
        else
            hostname="$name"
            name_counts[$name]=2  # Start duplicate count at 2
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
