export ASH_ROOT_DIR="$(cd $(dirname "$(dirname "$0")"); pwd)"
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"

# LPURPLE='\033[1;35m'
# LGRAY='\033[0;37m'
# GREEN='\033[0;32m'
# RED='\033[0;31m'
# YELLOW='\033[0;33m'
# CYAN='\033[0;36m'
# NC='\033[0m' # No Color

debug_echo() {
  [[ "${ASH_DEBUG:-"NO"}" != "NO" ]] && >&2 echo -e "\033[0;33m[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG:\033[0m ${1}"
}

debug_show_tree() {
  _TREE_FLAGS="-x -h -a --du -I .git"
  [[ "${ASH_DEBUG:-"NO"}" != "NO" ]] && tree ${_TREE_FLAGS} ${1:-$(pwd)}
}
