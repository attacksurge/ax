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
        boot_script="$5"
        root_pass="$(jq -r .linode_key "$AXIOM_PATH/axiom.json")"
        linode-cli linodes create  --type "$size_slug" --region "$region" --image "$image_id" --label "$name" --root_pass "$root_pass" --private_ip true 2>&1 --no-defaults >> /dev/null
        sleep 260
}

###################################################################
# deletes instances, if the second argument is set to "true", will not prompt
# used by axiom-rm
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

###################################################################
# Instances functions
# used by many functions in this file
#
# takes no arguments, outputs JSON object with instances
instances() {
	linode-cli linodes list --json
	#linode-cli linodes list --json | jq '.[] | [.label,.ipv4[],.region,.specs.memory]'
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
# Generate SSH config specfied in generate_sshconfig key:value in account.json
#
generate_sshconfig() {
        accounts=$(ls -l "$AXIOM_PATH/accounts/" | grep "json" | grep -v 'total ' | awk '{ print $9 }' | sed 's/\.json//g')
        current=$(readlink -f "$AXIOM_PATH/axiom.json" | rev | cut -d / -f 1 | rev | cut -d . -f 1)> /dev/null 2>&1
        droplets="$(instances)"
        sshnew="$AXIOM_PATH/.sshconfig.new$RANDOM"
        echo -n "" > $sshnew 
        echo -e "\tServerAliveInterval 60\n" >> $sshnew 
        sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"
        echo -e "IdentityFile $HOME/.ssh/$sshkey" >> $sshnew 
        generate_sshconfig="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.generate_sshconfig')"

    if [[ "$generate_sshconfig" == "private" ]]; then
        echo -e "Warning your SSH config generation toggle is set to 'Private' for account : $(echo $current)."
        echo -e "axiom will always attempt to SSH into the instances from their private backend network interface. To revert: axiom-ssh --just-generate"

    for name in $(echo "$droplets" | jq -r '.[].label'); do
        ip=$(echo "$droplets" | jq -r ".[] | select(.label==\"$name\") | .ipv4[1]")
        echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew 
     done

    mv $sshnew  $AXIOM_PATH/.sshconfig

        elif [[ "$generate_sshconfig" == "cache" ]]; then
            echo -e "Warning your SSH config generation toggle is set to 'Cache' for account : $(echo $current)."
        echo -e "axiom will never attempt to regenerate the SSH config. To change edit $HOME/.axiom/account/$current.json"

    # If anything but "private" or "cache" is parsed from the generate_sshconfig in account.json, generate public IPs only
    #
        else
        for name in $(echo "$droplets" | jq -r '.[].label'); do
            ip=$(echo "$droplets" | jq -r ".[] | select(.label==\"$name\") | .ipv4[0]")
            echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew
        done
        mv $sshnew  $AXIOM_PATH/.sshconfig
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
                if [[ "$var" =~ "*" ]]; then
                        var=$(echo "$var" | sed 's/*/.*/g')
                        selected="$selected $(echo $droplets | jq -r '.[].label' | grep "$var")"
                else
                        if [[ $query ]]; then
                                query="$query\|$var"
                        else
                                query="$var"
                        fi
                fi
        done

        if [[ "$query" ]]; then
                selected="$selected $(echo $droplets | jq -r '.[].label' | grep -w "$query")"
        else
                if [[ ! "$selected" ]]; then
                        echo -e "${Red}No instance supplied, use * if you want to delete all instances...${Color_Off}"
                        exit
                fi
        fi

        selected=$(echo "$selected" | tr ' ' '\n' | sort -u)
        echo -n $selected
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
