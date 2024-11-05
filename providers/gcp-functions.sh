#!/bin/bash

AXIOM_PATH="$HOME/.axiom"

###################################################################
#  Create one instance at a time
#
#  Needed for axiom-init
create_instance() {
    name="$1"
    image_id="$2"
    machine_type="$3"
    zone="$4"
    key="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.service_account_key')"

    gcloud compute instances create "$name" \
        --image "$image_id" \
        --machine-type "$machine_type" \
        --zone "$4" \
        --tags "axiom-ssh" \
        --verbosity=error \
        --quiet 2> >(grep -v '^Created \[' >&2) > /dev/null
        sleep 260
}

###################################################################
# deletes instances by name, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instances() {
    names="$1"
    force="$2"

    # Convert names to an array for processing
    name_array=($names)

    # Make a single call to get all GCP instances with their zones
    all_instances=$(gcloud compute instances list --format="json")

    # Declare arrays to store instance names and zones for deletion
    all_instance_names=()
    all_instance_zones=()

    # Iterate over all instances and filter by the provided names
    for name in "${name_array[@]}"; do
        instance_info=$(echo "$all_instances" | jq -r --arg name "$name" '.[] | select(.name | test($name))')

        if [ -n "$instance_info" ]; then
            instance_name=$(echo "$instance_info" | jq -r '.name')
            instance_zone=$(echo "$instance_info" | jq -r '.zone' | awk -F/ '{print $NF}')

            all_instance_names+=("$instance_name")
            all_instance_zones+=("$instance_zone")
        else
            echo -e "${BRed}Warning: No GCP instance found for the name '$name'.${Color_Off}"
        fi
    done

    # Force deletion: Delete all instances without prompting
    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting: ${all_instance_names[@]}...${Color_Off}"
        # Delete instances in bulk by zone
        for zone in $(printf "%s\n" "${all_instance_zones[@]}" | sort -u); do
            instances_to_delete=()
            for i in "${!all_instance_names[@]}"; do
                if [ "${all_instance_zones[$i]}" == "$zone" ]; then
                    instances_to_delete+=("${all_instance_names[$i]}")
                fi
            done
            if [ ${#instances_to_delete[@]} -gt 0 ]; then
                gcloud compute instances delete "${instances_to_delete[@]}" --zone="$zone" --quiet >/dev/null 2>&1 &
            fi
        done

    # Prompt for each instance if force is not true
    else
        # Collect instances for deletion after user confirmation
        confirmed_instance_names=()
        confirmed_instance_zones=()

        for i in "${!all_instance_names[@]}"; do
            instance_name="${all_instance_names[$i]}"
            instance_zone="${all_instance_zones[$i]}"

            echo -e -n "Are you sure you want to delete $instance_name (y/N) - default NO: "
            read ans
            if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                confirmed_instance_names+=("$instance_name")
                confirmed_instance_zones+=("$instance_zone")
            else
                echo "Deletion aborted for $instance_name."
            fi
        done

        # Delete confirmed instances in bulk by zone
        if [ ${#confirmed_instance_names[@]} -gt 0 ]; then
            echo -e "${Red}Deleting: ${confirmed_instance_names[@]}...${Color_Off}"
            for zone in $(printf "%s\n" "${confirmed_instance_zones[@]}" | sort -u); do
                instances_to_delete=()
                for i in "${!confirmed_instance_names[@]}"; do
                    if [ "${confirmed_instance_zones[$i]}" == "$zone" ]; then
                        instances_to_delete+=("${confirmed_instance_names[$i]}")
                    fi
                done
                if [ ${#instances_to_delete[@]} -gt 0 ]; then
                    gcloud compute instances delete "${instances_to_delete[@]}" --zone="$zone" --quiet &
                fi
            done
        else
            echo -e "${BRed}No instances were confirmed for deletion.${Color_Off}"
        fi
    fi
    # wait until all background jobs are finished deleting
    wait
}

###################################################################
# Instances functions
# Used by many functions in this file
instances() {
    gcloud compute instances list --format=json
}

# Takes one argument, name of instance, returns raw IP address
# Used by axiom-ls axiom-init
instance_ip() {
    name="$1"
    instances | jq -r ".[]? | select(.name==\"$name\") | .networkInterfaces[0].accessConfigs[0].natIP"
}

# Used by axiom-select axiom-ls
instance_list() {
    instances | jq -r '.[].name'
}

# Used by axiom-ls
instance_pretty() {
    data=$(instances)

    # Number of instances
    instances_count=$(echo "$data" | jq -r '.[] | .name' | wc -l)

    totalPrice=0
    header="Instance,External IP,Internal IP,Zone,Size,Status"

    # Modify jq fields to extract just the relevant part of the zone and machine type
    fields=".[] | [.name,
                   .networkInterfaces[0].accessConfigs[0].natIP,
                   .networkInterfaces[0].networkIP,
                   (.zone | split(\"/\")[-1]),
                   (.machineType | split(\"/\")[-1]),
                   .status] | @csv"

    data=$(echo "$data" | jq -r "$fields")
    totals="_,_,_,_,Instances,$instances_count"

    (echo "$header" && echo "$data" && echo "$totals") | sed 's/"//g' | column -t -s,
}

###################################################################
#  Dynamically generates axiom's SSH config based on your cloud inventory
#  Choose between generating the sshconfig using private IP details, public IP details, or optionally lock
#  Used for axiom-exec axiom-fleet axiom-ssh
#
generate_sshconfig() {
    accounts=$(ls -l "$AXIOM_PATH/accounts/" | grep "json" | grep -v 'total ' | awk '{ print $9 }' | sed 's/\.json//g')
    current=$(readlink -f "$AXIOM_PATH/axiom.json" | rev | cut -d / -f 1 | rev | cut -d . -f 1) >/dev/null 2>&1
    sshnew="$AXIOM_PATH/.sshconfig.new$RANDOM"
    instances_data=$(instances)
    echo -n "" > $sshnew
    echo -e "\tServerAliveInterval 60\n" >> $sshnew
    sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"
    echo -e "IdentityFile $HOME/.ssh/$sshkey" >> $sshnew
    generate_sshconfig="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.generate_sshconfig')"

    if [[ "$generate_sshconfig" == "private" ]]; then
        echo -e "Warning: Generating SSH config for private IP addresses"
        for name in $(echo "$instances_data" | jq -r '.[].name'); do
            ip=$(echo "$instances_data" | jq -r ".[] | select(.name==\"$name\") | .networkInterfaces[0].networkIP")
            if [[ -n "$ip" ]]; then
                echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew
            fi
        done
        mv $sshnew $AXIOM_PATH/.sshconfig
    elif [[ "$generate_sshconfig" == "cache" ]]; then
        echo -e "Warning: SSH config is cached, no new generation"
    else
        for name in $(echo "$instances_data" | jq -r '.[].name'); do
            ip=$(echo "$instances_data" | jq -r ".[] | select(.name==\"$name\") | .networkInterfaces[0].accessConfigs[0].natIP")
            if [[ -n "$ip" ]]; then
                echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew
            fi
        done
        mv $sshnew $AXIOM_PATH/.sshconfig
    fi
}

###################################################################
# Query instances
# Used by axiom-ls axiom-select axiom-fleet axiom-rm axiom-power
#
query_instances() {
    instances_data=$(instances)
    selected=""

    for var in "$@"; do
        if [[ "$var" =~ "*" ]]; then
            var=$(echo "$var" | sed 's/*/.*/g')
            selected="$selected $(echo $instances_data | jq -r '.[].name' | grep "$var")"
        else
            if [[ $query ]]; then
                query="$query\|$var"
            else
                query="$var"
            fi
        fi
    done

    if [[ "$query" ]]; then
        selected="$selected $(echo $instances_data | jq -r '.[].name' | grep -w "$query")"
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
    images=$(gcloud compute images list --no-standard-images --format=json)
    id=$(echo "$images" | jq -r ".[] | select(((.description==\"$query\") or (.name==\"$query\")) and (.architecture==\"X86_64\")) | .id")
    # Return the image ID
    echo $id
}


###################################################################
# Manage snapshots (updated to manage images, keeping function names the same)
# Used by axiom-images and axiom-backup
#
snapshots() {
    gcloud compute images list --no-standard-images --format=json
}

get_snapshots() {
    gcloud compute images list --no-standard-images
}

delete_snapshot() {
    image_name="$1"
    gcloud compute images delete "$image_name" --quiet
}

create_snapshot() {
    instance_name="$1"
    image_name="$2"
    gcloud compute images create "$image_name" \
        --source-disk="$(instance_disk $instance_name)" \
        --source-disk-zone="$(instance_zone $instance_name)"
}

###################################################################
# Get data about regions
# Used by axiom-regions
list_regions() {
    gcloud compute zones list
}

regions() {
    gcloud compute zones list --format=json
}

###################################################################
# Manage power state of instances
# Used for axiom-power
#
poweron() {
    instance_name="$1"
    gcloud compute instances start "$instance_name"
}

poweroff() {
    instance_name="$1"
    gcloud compute instances stop "$instance_name"
}

reboot() {
    instance_name="$1"
    gcloud compute instances reset "$instance_name"
}

instance_disk() {
    instance_name="$1"
    gcloud compute instances describe "$instance_name" --format="value(disks[0].source)"
}

###################################################################
# List available instance sizes (machine types)
# Used by ax sizes
#
sizes_list() {
    region="$(jq -r '.region' "$AXIOM_PATH"/axiom.json)"
    gcloud compute machine-types list --filter="zone:($region)" --format="table(name, zone, guestCpus, memoryMb)"
}
