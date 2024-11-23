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

    hcloud server create --type "$size_slug" --location "$region" --image "$image_id" \
        --name "$name" --poll-interval 250s --quiet --without-ipv6 --user-data-from-file "$user_data_file" &

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
#  Choose between generating the sshconfig using private IP details, public IP details or optionally lock
#  Lock will never generate an SSH config and only used the cached config ~/.axiom/.sshconfig 
#  Used for axiom-exec axiom-fleet axiom-ssh
#
# Generate SSH config specfied in generate_sshconfig key:value in account.json
#
generate_sshconfig() {
accounts=$(ls -l "$AXIOM_PATH/accounts/" | grep "json" | grep -v 'total ' | awk '{ print $9 }' | sed 's/\.json//g')
current=$(ls -lh "$AXIOM_PATH/axiom.json" | awk '{ print $11 }' | tr '/' '\n' | grep json | sed 's/\.json//g') > /dev/null 2>&1
droplets="$(instances)"
sshnew="$AXIOM_PATH/.sshconfig.new$RANDOM"
echo -n "" > $sshnew
echo -e "\tServerAliveInterval 60\n" >> $sshnew
sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"
echo -e "IdentityFile $HOME/.ssh/$sshkey" >> $sshnew
generate_sshconfig="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.generate_sshconfig')"

if [[ "$generate_sshconfig" == "private" ]]; then

 echo -e "Warning your SSH config generation toggle is set to 'Private' for account : $(echo $current)."
 echo -e "axiom will always attempt to SSH into the instances from their private backend network interface. To revert run: axiom-ssh --just-generate"
 for name in $(echo "$droplets" | jq -r '.[].name')
 do
 ip=$(echo "$droplets" | jq -r ".[] | select(.name==\"$name\") | .private_net.ipv4.ip")
 if [[ -n "$ip" ]]; then
  echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew
 fi
 done
 mv $sshnew $AXIOM_PATH/.sshconfig

 elif [[ "$generate_sshconfig" == "cache" ]]; then
 echo -e "Warning your SSH config generation toggle is set to 'Cache' for account : $(echo $current)."
 echo -e "axiom will never attempt to regenerate the SSH config. To revert run: axiom-ssh --just-generate"

 # If anything but "private" or "cache" is parsed from the generate_sshconfig in account.json, generate public IPs only
 #
 else
 for name in $(echo "$droplets" | jq -r '.[].name')
 do
 ip=$(echo "$droplets" | jq -r ".[] | select(.name==\"$name\") | .public_net.ipv4.ip")
 if [[ -n "$ip" ]]; then
  echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew
 fi
 done
 mv $sshnew $AXIOM_PATH/.sshconfig
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
# get JSON data for snapshots
# axiom-images
snapshots() {
        hcloud image list -t snapshot -o json
}

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
  ["ID", "Name", "Description", "Cores", "Memory (GB)", "Disk (GB)", "Storage Type", "CPU Type", "Architecture", "Price (€/Month)", "Price (€/Hour)", "Price per TB Traffic (€/TB)"],
  (.[]
  | [
      .id,
      .name,
      .description,
      .cores,
      .memory,
      .disk,
      .storage_type,
      .cpu_type,
      .architecture,
      (.prices[0].price_monthly.net | tonumber),
      (.prices[0].price_hourly.net | tonumber),
      (.prices[0].price_per_tb_traffic.net | tonumber)
    ]) | @tsv
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
