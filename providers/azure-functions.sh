#!/bin/bash

AXIOM_PATH="$HOME/.axiom"
resource_group="$(jq -r '.resource_group' "$AXIOM_PATH"/axiom.json)"
subscription_id="$(jq -r '.subscription_id' "$AXIOM_PATH"/axiom.json)"

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
        sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"

        az vm create --resource-group $resource_group --name "$name" --image "$image_id" --location "$region" --size "$size_slug" --tags "$name"=True --os-disk-delete-option delete --data-disk-delete-option delete --nic-delete-option delete --admin-username op --ssh-key-values ~/.ssh/$sshkey.pub >/dev/null 2>&1
	az vm open-port --resource-group $resource_group --name "$name" --port 0-65535 >/dev/null 2>&1
	sleep 260
}

###################################################################
# deletes instance, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instance() {
    name="$1"
    force="$2"

    if [ "$force" == "true" ]; then
                az resource delete --ids $(az resource list --tag "$name"=True -otable --query "[].id" -otsv) >/dev/null 2>&1
                az resource delete --ids $(az network public-ip list --query '[?ipAddress==`null`].[id]' -otsv | grep $name) >/dev/null 2>&1
                az resource delete --ids $(az network nsg list --query "[?(subnets==null) && (networkInterfaces==null)].id" -o tsv | grep $name) >/dev/null 2>&1
                az resource delete --ids $(az network nic list --query '[?virtualMachine==`null` && privateEndpoint==`null`].[id]' -o tsv | grep $name) >/dev/null 2>&1

    else
                echo -e -n "Are you sure you want to delete $name (y/N) - default NO: "
                read ans
                if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                        echo -e "${Red}...deleting $name...${Color_Off}"
                        az resource delete --ids $(az resource list --tag "$name"=True -otable --query "[].id" -otsv) >/dev/null 2>&1
                fi
    fi
}

###################################################################
# Instances functions
# used by many functions in this file
# takes no arguments, outputs JSON object with instances
instances() {
        az vm list --resource-group $resource_group -d
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
        name="$1"
        az vm list --resource-group $resource_group  -d | jq -r ".[] | select(.name==\"$name\") | .publicIps"
}

# used by axiom-select axiom-ls
instance_list() {
         az vm list --resource-group $resource_group | jq -r '.[].name'
}

# used by axiom-ls
instance_pretty() {
	data=$(instances)

	(i=0
	echo '"Instance","IP","Size","Region","Status","$M"'


	echo "$data" | jq -c '.[] | select(.type=="Microsoft.Compute/virtualMachines")' | while IFS= read -r instance;
	do
		name=$(echo $instance | jq -r '.name')
		size=$(echo $instance | jq -r ". | select(.name==\"$name\") | .hardwareProfile.vmSize")
		region=$(echo $instance | jq -r ". | select(.name==\"$name\") | .location")
                power=$(echo $instance | jq -r ". | select(.name==\"$name\") | .powerState")

		csv_data=$(echo $instance | jq ".size=\"$size\"" | jq ".region=\"$region\"" | jq ".powerState=\"$power\"")
		echo $csv_data | jq -r '[.name, .publicIps, .size, .region, .powerState] | @csv'
	done

	echo "\"_\",\"_\",\"_\",\"_\",\"Total\",\"\$$i\"") | column -t -s, | tr -d '"' 

	i=0
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

    echo "$droplets" | jq -c '.[]?' 2>/dev/null | while read -r instance; do
        # extract fields
        name=$(echo "$instance" | jq -r '.name? // empty' 2>/dev/null)
        public_ip=$(echo "$instance" | jq -r '.publicIps? // empty' 2>/dev/null | head -n 1)
        private_ip=$(echo "$instance" | jq -r '.privateIps? // empty' 2>/dev/null | head -n 1)

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
            # Replace * with .* for regex and anchor the pattern to match the entire string
            var=$(echo "$var" | sed 's/*/.*/g')
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

    # Trim whitespace, sort, and remove duplicates
    selected=$(echo "$selected" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo -n "${selected}" | xargs
}

###################################################################
#
# used by axiom-fleet axiom-init
get_image_id() {
        query="$1"
        images=$(az image list --resource-group $resource_group)
        name=$(echo $images | jq -r ".[].name" | grep -wx "$query" | tail -n 1)
        id=$(echo $images |  jq -r ".[] | select(.name==\"$name\") | .id")
        echo $id
}

###################################################################
# Manage snapshots
# used for axiom-images
#
snapshots() {
        az image list --resource-group $resource_group
}

# axiom-images
get_snapshots() {
        az image list --output table --resource-group $resource_group
}

# Delete a snapshot by its name
# axiom-images
delete_snapshot() {
        name="$1"
        az image delete --name "$name" --resource-group $resource_group
}

###################################################################
# Get data about regions
# used by axiom-regions
list_regions() {
    az account list-locations | jq -r '.[].name'
}

regions() {
        az account list-locations
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
instance_name="$1"
az vm start -g ${resource_group} -name $instance_name --resource-group $resource_group
}

# axiom-power
poweroff() {
instance_name="$1"
az vm stop -g ${resource_group} --name  $instance_name --resource-group $resource_group
}

# axiom-power
reboot(){
instance_name="$1"
az vm restart -g ${resource_group} --name $instance_name --resource-group $resource_group
}

# axiom-power
instance_id() {
        name="$1"
        az vm list --resource-group $resource_group | jq -r ".[] | select(.name==\"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
region="$(jq -r '.region' "$AXIOM_PATH"/axiom.json)"
(
  # Print the headers
  echo -e "InstanceType\tCores\tMemory"

  # Fetch and process VM sizes, sort them, and output the results
  az vm list-sizes --location $region --query "[].{Name:name, Cores:numberOfCores, Memory:memoryInMB}" --output json |
    jq -r '.[] | "\(.Name)\t\(.Cores)\t\(.Memory)"' |
    sort -n -k2,2 -k3,3
) |
# Format the output with correct column alignment
awk -F'\t' '{printf "%-20s %-10s %-10s\n", $1, $2, $3}'

}

###################################################################
# experimental v2 function
# deletes multiple instances at the same time by name, if the second argument is set to "true", will not prompt
# used by axiom-rm --multi
#
delete_instances() {
    names="$1"
    force="$2"
    name_array=($names)
    tag_query=""

    # Create a tag query for Azure CLI
    for name in "${name_array[@]}"; do
        if [ -n "$tag_query" ]; then
            tag_query+=" || "
        fi
        tag_query+="tags.$name == 'True'"
    done

    # Retrieve all resources associated with the instances in one Azure CLI call
    all_resource_ids=$(az resource list --query "[?${tag_query}].id" -o tsv)

    if [ -z "$all_resource_ids" ]; then
        echo "No resources found for the given instance names."
        return 1
    fi

    # Force delete case
    if [ "$force" == "true" ]; then
        confirmed_resource_ids="$all_resource_ids"
    else
        # Non-force delete case: prompt user for each instance
        confirmed_names=()
        confirmed_resource_ids=""

        for name in "${name_array[@]}"; do
            echo -e -n "Are you sure you want to delete all resources associated with instance '$name'? (y/N) - default NO: "
            read -r ans
            if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
                confirmed_names+=("$name")
                # Append resource IDs related to this instance to the list
                for resource_id in $all_resource_ids; do
                    if [[ "$resource_id" == *"$name"* ]]; then
                        confirmed_resource_ids+="$resource_id "
                    fi
                done
            fi
        done
    fi

    # Delete confirmed resources
    if [ -n "$confirmed_resource_ids" ]; then
        if [ "$force" == "true" ]; then
            echo -e "${Red}Deleting: ${name_array[*]}${Color_Off}"
        else
            echo -e "${Red}Deleting: ${confirmed_names[*]}${Color_Off}"
        fi
        az resource delete --ids $confirmed_resource_ids --no-wait
    else
        echo "No resources were selected for deletion."
    fi
}
