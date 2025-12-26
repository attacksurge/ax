AXIOM_PATH="$HOME/.axiom"

# Random Names to Use for Fleet and Init
names=("amir" "aspen" "austin" "bango" "banzai" "bartik" "bassi" "batman" "beaver" "bell" "benz" "borg" "bose" "buck" "cannon" "cerf" "chell" "clarke" "codingo" "cori" "cray" "ctbb" "darwin" "dawgyg" "diffie" "dirac" "elion" "ellis" "euler" "failopen" "fire" "fisher" "fox" "gates" "gauss" "ghost" "gould" "haddix" "haibt" "hakluke" "hertz" "hickey" "hunt" "iambouali" "jang" "jarvis" "jepsen" "jobs" "joliot" "jones" "kalam" "kare" "keller" "kepler" "kilby" "kirch" "knox" "knuth" "lamar" "lamp" "lande" "leaky" "leder" "leman" "lewin" "liskov" "loka" "lupin" "martho" "mato" "max" "mayer" "mclean" "medin" "mendel" "merkle" "mog" "moore" "morse" "moser" "murdo" "nagli" "nahamsec" "napier" "nash" "nat" "neum" "newton" "nishant" "nobel" "noyce" "octavian" "ofjaaah" "omnom" "pani" "pare" "pasa" "payne" "pdelteil" "pdteam" "perl" "pikpikcu" "poba" "pry" "raman" "rez" "rhodes" "rich" "ride" "robin" "rubin" "rt-bast" "saha" "sammet" "sandeep" "samogod" "securibee" "six2dez" "sml555" "snyder" "stok" "stone" "sumgr0" "tesla" "tess" "theo" "thl" "thomp" "todayisnew" "tu" "turing" "victoni" "vince" "wright" "wu" "xpn" "zonduu")

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
export LinodeCliVersion='5.65.0'
export IBMCloudCliVersion='2.27.0'
export HetznerCliVersion='1.47.0'
export AzureCliVersion="2.64.0"
export AWSCliVersion="2.17.45"
export GCloudCliVersion="493.0.0"
export PackerVersion="1.11.2"
export ScalewayCliVersion="2.34.0"
export ExoscaleCliVersion="1.84.0"

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
    ssh_conf="$AXIOM_PATH/.sshconfig"
    selected=""

    for var in "$@"; do
        if [[ "$var" =~ "-F=" ]]; then
            ssh_conf="$(echo "$var" | cut -d '=' -f 2)"
            continue
        fi

        if [[ "$var" == "\\*" ]]; then
            var="*"
        fi

        if [[ "$var" == *"*"* ]]; then
            var=$(echo "$var" | sed 's/*/.*/g')
            matches=$(grep -E "Host " "$ssh_conf" | awk '{ print $2 }' | grep -E "^${var}$")
        else
            matches=$(grep -E "Host " "$ssh_conf" | awk '{ print $2 }' | grep -w -E "^${var}$")
        fi

        if [[ -n "$matches" ]]; then
            selected="$selected $matches"
        fi
    done

    selected=$(echo "$selected" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo -n "${selected}" | xargs
}

# shared function to log fleet spin up stats
# stats are saved to ~/.axiom/stats.log
axiom_stats_log_instance() {
    # args: name ip region size image_id instance_id
    local name="$1"
    local ip="$2"
    local region="$3"
    local size="$4"
    local image_id="$5"
    local instance_id="$6"

    local log_file="${AXIOM_STATS_LOG:-$HOME/.axiom/stats.log}"
    local lock_dir="${log_file}.lockdir"

    local provider="${AXIOM_PROVIDER:-}"
    local image_name="${AXIOM_IMAGE_NAME:-}"
    local fleet="${AXIOM_FLEET_PREFIX:-}"
    local deploy="${AXIOM_DEPLOY:-false}"

    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    json_escape() {
        echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
    }

    mkdir -p "$(dirname "$log_file")" 2>/dev/null

    while ! mkdir "$lock_dir" 2>/dev/null; do
        sleep 0.02
    done

    {
        printf '{'
        printf '"fleet":{'
        printf '"name":"%s",' "$(json_escape "$name")"
        printf '"ip":"%s",' "$(json_escape "$ip")"
        printf '"provider":"%s",' "$(json_escape "$provider")"
        printf '"region":"%s",' "$(json_escape "$region")"
        printf '"size":"%s",' "$(json_escape "$size")"
        printf '"image":"%s",' "$(json_escape "$image_name")"
        printf '"image_id":"%s",' "$(json_escape "$image_id")"
        printf '"instance_id":"%s",' "$(json_escape "$instance_id")"
        printf '"prefix":"%s",' "$(json_escape "$fleet")"
        printf '"time":"%s"' "$(json_escape "$now")"
        printf '}}\n'
    } >> "$log_file"

    rmdir "$lock_dir" 2>/dev/null
}
