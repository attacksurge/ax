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
        root_pass="$(jq -r .op "$AXIOM_PATH/axiom.json")"

        user_data_base64=$(mktemp)
        echo "$user_data" | base64 | tr -d '\n' > "$user_data_base64"

        linode-cli linodes create  --type "$size_slug" --region "$region" --image "$image_id" --label "$name" --root_pass "$root_pass" \
         --private_ip true --metadata.user_data "$(cat $user_data_base64)" --no-defaults 2>&1 >> /dev/null
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

    linode-cli linodes delete "$id"
}

###################################################################
# Instances functions
# used by many functions in this file
#
# takes no arguments, outputs JSON object with instances
instances() {
	linode-cli linodes list --json
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
	name="$1"
	instances | jq -r ".[] | select(.label==\"$name\") | .ipv4[0]"
}

# used by axiom-select axiom-ls
instance_list() {
	instances | jq -r '.[].label'
}

# used by axiom-ls
instance_pretty() {
  data=$(instances)
  #number of linodes
  linodes=$(echo $data|jq -r '.[]|.id'|wc -l )
  #default size from config file
  type="$(jq -r .default_size "$AXIOM_PATH/axiom.json")"
  #monthly price of linode type 
  price=$(linode-cli linodes type-view $type --json|jq -r '.[].price.monthly')
  #  totalPrice=$(( "$price * $linodes" | bc))
  totalPrice=$(awk "BEGIN {print $price * $linodes}")

  header="Instance,Primary Ip,Backend Ip,Region,Size,Status,\$/M"
  totals="_,_,_,Instances,$linodes,Total,\$$totalPrice"
  fields=".[] | [.label,.ipv4[0],.ipv4[1],.region,.type,.status, \"$price\"]| @csv"
  #printing part
  #sort -k1 sorts all data by label/instance/linode name
  (echo "$header" && echo $data|(jq -r "$fields" |sort -k1) && echo "$totals") | sed 's/"//g' | column -t -s, 
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
        name=$(echo "$droplet" | jq -r '.label? // empty' 2>/dev/null)
        public_ip=$(echo "$droplet" | jq -r '.ipv4[0]? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$droplet" | jq -r '.ipv4[1]? // empty' 2>/dev/null | head -n 1)

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
            matches=$(echo "$droplets" | jq -r '.[].label' | grep -E "^${var}$")
        else
            matches=$(echo "$droplets" | jq -r '.[].label' | grep -w -E "^${var}$")
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
	images=$(linode-cli images list --json)
	id=$(echo $images |  jq -r ".[] | select(.label==\"$query\") | .id")
	echo $id
}

###################################################################
# Manage snapshots
# used for axiom-images
#
# get JSON data for snapshots
snapshots() {
        linode-cli images list --json
}

# only displays private images
# axiom-images
get_snapshots() {
    linode-cli images list --is_public false
}


# Delete a snapshot by its name
# axiom-images
delete_snapshot() {
        name="$1"
        image_id=$(get_image_id "$name")
        linode-cli images delete "$image_id"
}

# axiom-images
create_snapshot() {
        instance="$1"
	snapshot_name="$2"
        disk_id=$(linode-cli linodes disks-list "$(instance_id $instance)" --text | grep axiom | tr '\t' ' ' | cut -d ' ' -f 1)
        linode-cli images create --disk_id "$disk_id" --text --label $snapshot_name
}

###################################################################
# Get data about regions
# used by axiom-regions
list_regions() {
    linode-cli regions list
}

# used for axiom-region
regions() {
    linode-cli regions list --json | jq -r '.[].id'
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
    instance_name="$1"
    linode-cli linodes boot $(instance_id $instance_name)
}

# axiom-power
poweroff() {
    instance_name="$1"
    linode-cli linodes shutdown $(instance_id $instance_name)
}

# axiom-power
reboot(){
    instance_name="$1"
    linode-cli linodes reboot $(instance_id $instance_name)
}

# axiom-power axiom-images
instance_id() {
        name="$1"
        instances | jq ".[] | select(.label==\"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
   linode-cli linodes types --text
}

###################################################################
# experimental v2 function
# deletes multiple instances at the same time by name, if the second argument is set to "true", will not prompt
# used by axiom-rm --multi
#
delete_instances() {
    names="$1"
    force="$2"

    declare -A linode_ids

    # create array with instance ids
    linode_cli_output=$(linode-cli linodes list --format "id,label" --no-headers --text)
    for name in $names; do
        id=$(echo "$linode_cli_output" | awk -v name="$name" '$2 == name {print $1}')
        if [ -n "$id" ]; then
            linode_ids["$name"]="$id"
        else
            echo -e "${BRed}Error: No Linode found with the given name: '$name'.${BRed}"
        fi
    done

    # iterate over names and delete instances
    for name in "${!linode_ids[@]}"; do
        id="${linode_ids[$name]}"

        if [ "$force" != "true" ]; then
            read -p "Are you sure you want to delete instance '$name' (Linode ID: $id)? (y/N): " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo "Instance deletion aborted for '$name'."
                continue
            fi
        fi

        echo -e "${Red}Deleting: '$name' (Linode ID: $id)...${Color_Off}"
        linode-cli linodes delete "$id" >/dev/null 2>&1 &
    done

# wait until all background jobs are finished deleting
wait
}
