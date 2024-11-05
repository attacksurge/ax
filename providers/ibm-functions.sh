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
        domain="ax.private"
        cpu="$(jq -r '.cpu' $AXIOM_PATH/axiom.json)"
        #ibmcloud sl vs create -H "$name" -D "$domain" -c 2 -m 2048 -d dal12 --image 6018238 --wait 5000 -f  2>&1 >>/dev/null &
        ibmcloud sl vs create -H "$name" -D "$domain" -c "$cpu" -m "$size_slug" -n 1000 -d "$region" --image "$image_id" -f  2>&1 >>/dev/null 
	sleep 260
}

###################################################################
# deletes instances, if the second argument is set to "true", will not prompt
# used by axiom-rm
#
delete_instances() {
    names="$1"
    force="$2"

    # Declare an array to store instance IDs
    instance_ids=()

    # Get the instance IDs for the given names
    ibmcloud_cli_output=$(ibmcloud sl vs list --output JSON)
    for name in $names; do
        ids=$(echo "$ibmcloud_cli_output" | jq -r ".[] | select(.hostname==\"$name\") | .id")
        if [ -n "$ids" ]; then
            for id in $ids; do
                instance_ids+=("$id")
            done
        else
            echo -e "${BRed}Error: No IBM Cloud instance found with the given name: '$name'.${BRed}"
        fi
    done

    if [ "$force" == "true" ]; then
        echo -e "${Red}Deleting: $names...${Color_Off}"
        for id in "${instance_ids[@]}"; do
            ibmcloud sl vs cancel "$id" -f >/dev/null 2>&1 &
        done
    else
        for id in "${instance_ids[@]}"; do
            instance_name=$(echo "$ibmcloud_cli_output" | jq -r ".[] | select(.id==$id) | .hostname")
            read -p "Are you sure you want to delete instance '$instance_name' (ID: $id)? (y/N): " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo "Instance deletion aborted for instance '$instance_name' (ID: $id)."
                continue
            fi

            echo -e "${Red}Deleting: '$instance_name' (ID: $id)...${Color_Off}"
            ibmcloud sl vs cancel "$id" -f &
        done
    fi
# wait until all background jobs are finished deleting
wait
}

###################################################################
# Instances functions
# used by many functions in this file
instances() {
ibmcloud sl vs list --column datacenter --column domain --column hostname --column id --column cpu --column memory --column public_ip --column private_ip --column power_state --column created_by --column action --output json
	#ibmcloud  sl vs list --output json
}

# takes one argument, name of instance, returns raw IP address
# used by axiom-ls axiom-init
instance_ip() {
        host="$1"
        instances | jq -r ".[] | select(.hostname==\"$host\") | .primaryIpAddress"
}

# used by axiom-select axiom-ls
instance_list() {
        instances | jq -r '.[].hostname'
}

# used by axiom-ls
instance_pretty() {
    data=$(instances)
    #number of droplets
    droplets=$(echo $data|jq -r '.[]|.hostname'|wc -l )

    hour_cost=0
    for f in $(echo $data | jq -r '.[].billingItem.hourlyRecurringFee'); do new=$(bc <<< "$hour_cost + $f"); hour_cost=$new; done
    totalhourly_Price=$hour_cost

    hours_used=0
    for f in $(echo $data | jq -r '.[].billingItem.hoursUsed'); do new=$(bc <<< "$hours_used + $f"); hours_used=$new; done
    totalhours_used=$hours_used

    monthly_cost=0
    for f in $(echo $data | jq -r '.[].billingItem.orderItem.recurringAfterTaxAmount'); do new=$(bc <<< "$monthly_cost + $f"); monthly_cost=$new; done
    totalmonthly_Price=$monthly_cost

    header="Instance,Primary Ip,Backend Ip,DC,Memory,CPU,Status,Hours used,\$/H,\$/M"
    fields=".[] | [.hostname, .primaryIpAddress, .primaryBackendIpAddress, .datacenter.name, .maxMemory, .maxCpu, .powerState.name, .billingItem.hoursUsed, .billingItem.orderItem.hourlyRecurringFee, .billingItem.orderItem.recurringAfterTaxAmount ] | @csv"
    totals="_,_,_,_,Instances,$droplets,Total Hours,$totalhours_used,\$$totalhourly_Price/hr,\$$totalmonthly_Price/mo" 

    #data is sorted by default by field name    
    data=$(echo $data | jq  -r "$fields"| sed 's/^,/0,/; :a;s/,,/,0,/g;ta')
    (echo "$header" && echo "$data" && echo $totals) | sed 's/"//g' | column -t -s, 
}

###################################################################
#  Dynamically generates axiom's SSH config based on your cloud inventory
#  Choose between generating the sshconfig using private IP details, public IP details or optionally lock
#  Lock will never generate an SSH config and only used the cached config ~/.axiom/.sshconfig 
#  Used for axiom-exec axiom-fleet axiom-ssh
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
  echo -e "axiom will always attempt to SSH into the instances from their private backend network interface. To revert run: axiom-ssh --just-generate"
  for name in $(echo "$droplets" | jq -r '.[].hostname')
  do 
  ip=$(echo "$droplets" | jq -r ".[] | select(.hostname==\"$name\") | .primaryBackendIpAddress")
  echo -e "Host $name\n\tHostName $ip\n\tUser op\n\tPort 2266\n" >> $sshnew 
  done
  mv $sshnew  $AXIOM_PATH/.sshconfig

	elif [[ "$generate_sshconfig" == "cache" ]]; then
	echo -e "Warning your SSH config generation toggle is set to 'Cache' for account : $(echo $current)."
	echo -e "axiom will never attempt to regenerate the SSH config. To revert run: axiom-ssh --just-generate"
	
  # If anything but "private" or "cache" is parsed from the generate_sshconfig in account.json, generate public IPs only
  #
	else 
  for name in $(echo "$droplets" | jq -r '.[].hostname')
	do 
	ip=$(echo "$droplets" | jq -r ".[] | select(.hostname==\"$name\") | .primaryIpAddress")
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
		if [[ "$var" =~ "*" ]]
		then
			var=$(echo "$var" | sed 's/*/.*/g')
			selected="$selected $(echo $droplets | jq -r '.[].hostname' | grep "$var")"
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
		selected="$selected $(echo $droplets | jq -r '.[].hostname' | grep -w "$query")"
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
	images=$(ibmcloud sl image list --private --output json)
	name=$(echo $images | jq -r ".[].name" | grep -wx "$query" | tail -n 1)
	id=$(echo $images |  jq -r ".[] | select(.name==\"$name\") | .id")

	echo $id
}

###################################################################
# Manage snapshots
# used for axiom-images
#
get_snapshots() {
        ibmcloud sl image list --private
}

# axiom-images
delete_snapshot() {
 name=$1
 image_id=$(get_image_id "$name")       
 ibmcloud sl image delete "$image_id"
}

# axiom-images
snapshots() {
        ibmcloud sl image list --output json --private
}

# axiom-images
create_snapshot() {
        instance="$1"
        snapshot_name="$2"
	ibmcloud sl vs capture "$(instance_id $instance)" --name $snapshot_name
}

###################################################################
# Get data about regions
# used by axiom-regions
#
list_regions() {
      ibmcloud sl vs options | sed -n '/datacenter/,/Size/p' | tr -s ' ' | rev | cut -d  ' ' -f 1| rev | tail -n +2 | head -n -1 | tr '\n' ','
}

regions() {
     ibmcloud sl vs options | sed -n '/datacenter/,/Size/p' | tr -s ' ' | rev | cut -d  ' ' -f 1 | rev | tail -n +2 | head -n -1 | tr '\n' ','
}

###################################################################
#  Manage power state of instances
#  Used for axiom-power
#
poweron() {
instance_name="$1"
force="$2"
if [ "$force" == "true" ]
then
ibmcloud sl vs power-on $(instance_id $instance_name) --force
else
ibmcloud sl vs power-on $(instance_id $instance_name)
fi
}

# axiom-power
poweroff() {
instance_name="$1"
force="$2"
if [ "$force" == "true" ]
then
ibmcloud sl vs power-off $(instance_id $instance_name) --force
else
ibmcloud sl vs power-off $(instance_id $instance_name) 
fi
}

# axiom-power
reboot(){
instance_name="$1"
force="$2"
if [ "$force" == "true" ]
then
ibmcloud sl vs reboot $(instance_id $instance_name) --force
else
ibmcloud sl vs reboot $(instance_id $instance_name) 
fi
}

# axiom-power axiom-images
instance_id() {
    name="$1"
	instances | jq ".[] | select(.hostname==\"$name\") | .id"
}

###################################################################
#  List available instance sizes
#  Used by ax sizes
#
sizes_list() {
cat << EOF
RAM: 2048, 4096, 8192, 16384, 32768, 64512
CPU: 1, 2, 4, 8, 16, 32, 48
EOF
}
