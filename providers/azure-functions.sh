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
	boot_script="$5"
    sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"

	#location="$(az account list-locations | jq -r ".[] | select(.name==\"$region\") | .displayName")"
	location="$region"

  az vm create --resource-group $resource_group --name "$name" --image "$image_id" --location "$location" --size "$size_slug" --tags "$name"=True --os-disk-delete-option delete --data-disk-delete-option delete --nic-delete-option delete --admin-username op --ssh-key-values ~/.ssh/$sshkey.pub >/dev/null 2>&1
	az vm open-port --resource-group $resource_group --name "$name" --port 0-65535 >/dev/null 2>&1 
	sleep 260
}

###################################################################
# deletes instances by name, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instances() {
    names="$1"
    force="$2"
    resource_group="axiom"  # Update with the correct resource group

    # Convert names to an array for processing
    name_array=($names)

    # Make a single Azure CLI call to get all resources in the resource group
    all_resources=$(az resource list --resource-group "$resource_group" --query "[].[id, name]" -o tsv)

    # Declare an array to store all resource IDs to be deleted
    all_resource_ids=()
    deleted_names=()

    # Iterate over all resources and filter by the provided names
    while IFS=$'\t' read -r resource_id resource_name; do
        for name in "${name_array[@]}"; do
            if [[ "$resource_name" == *"$name"* ]]; then
                all_resource_ids+=("$resource_id")
            fi
        done
    done <<< "$all_resources"

    # Convert all resource IDs to a space-separated list for deletion
    resource_ids_string="${all_resource_ids[@]}"

    # Force deletion: Delete all resources without prompting
    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting Azure resources: ${names}...${Color_Off}"
        az resource delete --ids $resource_ids_string --no-wait >/dev/null 2>&1

        # Clean up leftover resources associated with the deleted names in a single step
        public_ip_ids=$(az network public-ip list --resource-group "$resource_group" --query "[?contains(name, '$(IFS="|" ; echo "${name_array[*]}")')].id" -o tsv)
        nsg_ids=$(az network nsg list --resource-group "$resource_group" --query "[?contains(name, '$(IFS="|" ; echo "${name_array[*]}")')].id" -o tsv)
        nic_ids=$(az network nic list --resource-group "$resource_group" --query "[?contains(name, '$(IFS="|" ; echo "${name_array[*]}")')].id" -o tsv)

        # Delete the related resources
        az resource delete --ids $public_ip_ids --no-wait >/dev/null 2>&1
        az resource delete --ids $nsg_ids --no-wait >/dev/null 2>&1
        az resource delete --ids $nic_ids --no-wait >/dev/null 2>&1

    # Prompt for each instance if force is not true
    else
        # Collect VMs for deletion after user confirmation
        confirmed_resource_ids=()
        confirmed_names=()

        for name in "${name_array[@]}"; do
            matching_resource_ids=()
            for resource_id in "${all_resource_ids[@]}"; do
                if [[ "$resource_id" == *"$name"* ]]; then
                    matching_resource_ids+=("$resource_id")
                fi
            done

            if [ ${#matching_resource_ids[@]} -gt 0 ]; then
                echo -e -n "Are you sure you want to delete $name (y/N) - default NO: "
                read ans
                if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                    confirmed_resource_ids+=("${matching_resource_ids[@]}")
                    confirmed_names+=("$name")
                else
                    echo "Deletion aborted for $name."
                fi
            else
                echo -e "${BRed}Warning: No resources found for the name '$name'.${Color_Off}"
            fi
        done

        # Delete confirmed VMs
        if [ ${#confirmed_resource_ids[@]} -gt 0 ]; then
            echo -e "${Red}Deleting Azure VMs ${confirmed_names[@]}...${Color_Off}"
            az resource delete --ids "${confirmed_resource_ids[@]}" --no-wait >/dev/null 2>&1

            # Clean up leftover resources for the deleted VMs in a single step
            public_ip_ids=$(az network public-ip list --resource-group "$resource_group" --query "[?contains(name, '$(IFS="|" ; echo "${confirmed_names[*]}")')].id" -o tsv)
            nsg_ids=$(az network nsg list --resource-group "$resource_group" --query "[?contains(name, '$(IFS="|" ; echo "${confirmed_names[*]}")')].id" -o tsv)
            nic_ids=$(az network nic list --resource-group "$resource_group" --query "[?contains(name, '$(IFS="|" ; echo "${confirmed_names[*]}")')].id" -o tsv)

            # Delete the related resources
            az resource delete --ids $public_ip_ids --no-wait >/dev/null 2>&1
            az resource delete --ids $nsg_ids --no-wait >/dev/null 2>&1
            az resource delete --ids $nic_ids --no-wait >/dev/null 2>&1
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
#  Choose between generating the sshconfig using private IP details, public IP details or optionally lock
#  Lock will never generate an SSH config and only used the cached config ~/.axiom/.sshconfig 
#  Used for axiom-exec axiom-fleet axiom-ssh
#
generate_sshconfig() {
        boxes="$(instances)"
        sshnew="$AXIOM_PATH/.sshconfig.new$RANDOM"
        echo -n "" > "$sshnew"
        echo -e "\tServerAliveInterval 60\n" >> $sshnew
  sshkey="$(cat "$AXIOM_PATH/axiom.json" | jq -r '.sshkey')"
  echo -e "IdentityFile $HOME/.ssh/$sshkey" >> $sshnew

    
        for name in $(echo "$boxes" | jq -r '.[].name')
        do 
                ip=$(echo "$boxes" | jq -r ".[] | select(.name==\"$name\") | .publicIps")
                echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew

        done
        mv $sshnew $AXIOM_PATH/.sshconfig
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
                if [[ "$var" =~ "*" ]]
                then
                        var=$(echo "$var" | sed 's/*/.*/g')
                        selected="$selected $(echo $droplets | jq -r '.[].name' | grep "$var")"
                else
                        if [[ $query ]];
                        then
                                query="$query\|$var"
                        else
                                query="$var"
                        fi
                fi
        done

        if [[ "$query" ]]
        then
                selected="$selected $(echo $droplets | jq -r '.[].name' | grep -w "$query")"
        else
                if [[ ! "$selected" ]]
                then
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
