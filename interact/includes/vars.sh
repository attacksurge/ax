AXIOM_PATH="$HOME/.axiom"

# Random Names to Use for Fleet and Init
names=("amir" "aspen" "austin" "bango" "banzai" "bartik" "bassi" "batman" "beaver" "bell" "benz" "borg" "bose" "buck" "cannon" "cerf" "chell" "clarke" "codingo" "cori" "cray" "ctbb" "darwin" "dawgyg" "diffie" "dirac" "elion" "ellis" "euler" "failopen" "fire" "fisher" "fox" "gates" "gauss" "ghost" "gould" "haddix" "haibt" "hakluke" "hertz" "hickey" "hunt" "iambouali" "jang" "jarvis" "jepsen" "jobs" "joliot" "jones" "kalam" "kare" "keller" "kepler" "kilby" "kirch" "knox" "knuth" "lamar" "lamp" "lande" "leaky" "leder" "leman" "lewin" "liskov" "loka" "lupin" "martho" "mato" "max" "mayer" "mclean" "medin" "mendel" "merkle" "mog" "moore" "morse" "moser" "murdo" "nagli" "nahamsec" "napier" "nash" "nat" "neum" "newton" "nishant" "nobel" "noyce" "octavian" "ofjaaah" "omnom" "pani" "pare" "pasa" "payne" "pdelteil" "pdteam" "perl" "pikpikcu" "poba" "pry" "raman" "rez" "rhodes" "rich" "ride" "robin" "rubin" "rt-bast" "saha" "sammet" "sandeep" "samogod" "securibee" "six2dez" "sml555" "snyder" "stok" "stone" "sumgr0" "tesla" "theo" "thl" "thomp" "todayisnew" "tu" "turing" "victoni" "vince" "wright" "wu" "xpn" "zonduu")

# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
export Black='\033[0;30m'        # Black
export Red='\033[0;31m'          # Red
export Green='\033[0;32m'        # Green
export Yellow='\033[0;33m'       # Yellow
export Blue='\033[0;34m'         # Blue
export Purple='\033[0;35m'       # Purple
export Cyan='\033[0;36m'         # Cyan
export White='\033[0;37m'        # White

# Bold
export BBlack='\033[1;30m'       # Black
export BRed='\033[1;31m'         # Red
export BGreen='\033[1;32m'       # Green
export BYellow='\033[1;33m'      # Yellow
export BBlue='\033[1;34m'        # Blue
export BPurple='\033[1;35m'      # Purple
export BCyan='\033[1;36m'        # Cyan
export BWhite='\033[1;37m'       # White

# Required Go Version - gets interpolated during axiom-build and axiom-configure
export GolangVersion='1.23.0'

# Recommended Cloud provider CLI versions
# Only updates if the installed version is lower than recommended version
export DoctlVersion='1.112.0'
export LinodeCliVersion='5.51.0'
export IBMCloudCliVersion='2.27.0'
export HetznerCliVersion='1.47.0'
export AzureCliVersion="2.64.0"
export AWSCliVersion="2.17.45"
export GCloudCliVersion="493.0.0"
export PackerVersion="1.11.2"
export ScalewayCliVersion="2.34.0"

# Auto Update Option
[ -f $AXIOM_PATH/interact/includes/.auto_update ] && source $AXIOM_PATH/interact/includes/.auto_update

# Shared function across all proviers, since these functions only query an ssh configuration file
# check if instance name is in .sshconfig
# used by axiom-scan
instance_ip_cache() {
    name="$1"
    config="$2"
    ssh_config="$AXIOM_PATH/.sshconfig"

    if [[ "$config" != "" ]]; then
        ssh_config="$config"
    fi
    cat "$ssh_config" | grep -A 1 "$name" | awk '{ print $2 }'
}

# check if instances are in .sshconfig
# used by axiom-scan axiom-exec axiom-scp
query_instances_cache() {
    selected=""
    ssh_conf="$AXIOM_PATH/.sshconfig"

    for var in "$@"; do
        if [[ "$var" =~ "-F=" ]]; then
            ssh_conf="$(echo "$var" | cut -d "=" -f 2)"
        elif [[ "$var" =~ "*" ]]; then
            var=$(echo "$var" | sed 's/*/.*/g')
            selected="$selected $(cat "$ssh_conf" | grep "Host " | awk '{ print $2 }' | grep "$var")"
        else
            if [[ $query ]]; then
                query="$query\|$var"
            else
                query="$var"
            fi
        fi
    done

    if [[ "$query" ]]; then
        selected="$selected $(cat "$ssh_conf" | grep "Host " | awk '{ print $2 }' | grep -w "$query")"
    else
        if [[ ! "$selected" ]]; then
            echo -e "${Red}No instance supplied, use * if you want to delete all instances...${Color_Off}"
            exit
        fi
    fi

    selected=$(echo "$selected" | tr ' ' '\n' | sort -u)
    echo -n "$selected"
}
