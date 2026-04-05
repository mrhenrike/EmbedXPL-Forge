#!/bin/bash

# By 0xyassine

#COLORS
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
TOOL_VERSION=1.4

ACCEPTED_SOURCES=(github sploitus exploit-db vulnerability-lab packetstormsecurity)

function red
{
	echo -ne "${RED}$1${NC}"
}

function green()
{
	echo -ne "${GREEN}$1${NC}"
}

function blue()
{
	echo -ne "${BLUE}$1${NC}"
}

function cyan()
{
	echo -ne "${CYAN}$1${NC}"
}

function yellow()
{
	echo -ne "${YELLOW}$1${NC}"
}
function white()
{
  echo -ne "${NC}$1${NC}"
}


function logo()
{
  echo
  echo "██████╗  ██████╗  ██████╗███████╗███████╗███████╗██╗  ██╗███████╗██████╗"
  echo "██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗"
  echo "██████╔╝██║   ██║██║     ███████╗█████╗  █████╗  █████╔╝ █████╗  ██████╔╝"
  echo "██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══██╗"
  echo "██║     ╚██████╔╝╚██████╗███████║███████╗███████╗██║  ██╗███████╗██║  ██║"
  echo "╚═╝      ╚═════╝  ╚═════╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"
  echo
  printf "                                                     ${BLUE}Developer${NC}: 0xyassine\n"
  printf "                                                     ${BLUE}Version${NC}  : ${RED}$TOOL_VERSION${NC}\n"
  printf "                                                                "
  echo
}

function help()
{
  SCRIPT_NAME=$(basename "$0")
  echo ""
  green "OPTIONS:\n"
  printf "${CYAN}  -h  | --help${NC}                Display this help menu 🤩\n"
  printf "${CYAN}  -q  | --query${NC}               Provide search query (${RED}mandatory${NC}) 😀\n"
  printf "${CYAN}  -s  | --source${NC}              Supply search source separated by a comma (optional) 🥸\n"
  printf "                              default   : ${YELLOW}github,sploitus,exploit-db,vulnerability-lab${NC}\n"
  printf "                              available : ${CYAN}github,sploitus,exploit-db,vulnerability-lab,packetstormsecurity${NC}\n"
  printf "${CYAN}  -e  | --extensions${NC}          Supply a list of file extensions separated by a comma used to search \n"
  printf "                              inside the respositories (optional)\n"
  printf "                              default : ${CYAN}.py,.rb,.pl,.sh,.ps1,.bat,.js,.php,.c,.cpp,.go,.lua,.rs,.swift${NC}\n"
  printf "${YELLOW}                              Be careful, do not use bash extension for windows based exploits 😉${NC}\n"
  printf "${CYAN}  -c  | --check${NC}               The script accurately checks whether the CVE identifier is defined\n"
  printf "                              in the exploit to improve precision (optional) 🫠\n"
  printf "${CYAN}  -sl | --sploitus-limit${NC}      Limit the number of entries returned by sploitus (optional) 🙂\n"
  printf "                              default : ${CYAN}10${NC}\n"
  printf "${CYAN}  -gl | --github-limit${NC}        Limit the number of entries returned by github (optional) 🙂\n"
  printf "                              default : ${CYAN}10${NC}\n"
  printf "${CYAN}  -o  | --output${NC}              Save the output to a file 🫣\n"
  printf "${CYAN}  --github-access-token${NC}       Supply a GitHub access token to increase the API request limit (optional) 😀\n"
  printf "${CYAN}  --nvd-api-key${NC}               Supply an NVD api key to increase the API request limit (optional) 😏\n"
  printf "${CYAN}  --disable-nvd${NC}               Prevent the script from searching for CVE details (optional) 😞\n"
  echo
  printf "  E.g: ${RED}$(basename $0) -c -q CVE-2023-40028 -s github,sploitus -o cve-2023-40028.txt${NC}\n"
  echo
}

function spinner()
{
	local CATEGORY="$2"
	local DESCRIPTION=$1
	local -a SPIN=("🤞" "👌" "🫰" "👍")
	local INTERVAL=0.1
	while :; do
		for CHAR in "${SPIN[@]}"; do
			printf "\r%s   $DESCRIPTION ${RED}$CATEGORY${NC}" "$CHAR"
			sleep "$INTERVAL"
		done
	done
}

function install_packages()
{
  echo
  local PACKAGE_NAME=$1
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID_LIKE
  else
    printf "* ${CYAN}$PACKAGE_NAME${NC} is missing\n"
    return 1
  fi
  case $OS in
    ubuntu|debian|linuxmint)
      printf "* ${CYAN}$PACKAGE_NAME${NC} is missing, what about trying ${CYAN}sudo apt update && sudo apt install -y $PACKAGE_NAME ${NC}😀\n"
      ;;
    fedora|centos|rhel)
      if [[ "$OS" == "centos" || "$OS" == "rhel" ]]; then
        printf "* ${CYAN}$PACKAGE_NAME${NC} is missing, what about trying ${CYAN}sudo yum install -y $PACKAGE_NAME ${NC}😀\n"
      else
        printf "* ${CYAN}$PACKAGE_NAME${NC} is missing, what about trying ${CYAN}sudo dnf install -y $PACKAGE_NAME ${NC}😀\n"
      fi
      ;;
    arch|manjaro)
      printf "* ${CYAN}$PACKAGE_NAME${NC} is missing, what about trying ${CYAN}sudo pacman -Syu --noconfirm $PACKAGE_NAME ${NC}😀\n"
      ;;
    *)
      printf "* ${CYAN}$PACKAGE_NAME${NC} is missing\n"
      ;;
  esac
}

function verify_packages()
{
  REQUIRED_PACKAGES=(curl jq)
  MISSING_PACKAGES=()
  for PACKAGE in ${REQUIRED_PACKAGES[@]};do
    if ! which $PACKAGE &>/dev/null;then
      MISSING_PACKAGES+=($PACKAGE)
    fi
  done
  if [ ${#MISSING_PACKAGES[@]} -ne 0 ];then
    red "😞 Please install the following packages before executing the script 😞\n"
    for MISSING in ${MISSING_PACKAGES[@]};do
      install_packages "$MISSING"
    done
    echo
    exit 1
  fi
}

function check_curl_features()
{
  if ! curl --version | grep -q HTTP2;then
    yellow "🤔 I guess your curl version does not support HTTP/2. Sploitus search may fail 🤔\n"
    yellow "😎 However, you can install a new curl version to support this protocol 😎\n"
    echo
  fi
}

function check_for_update()
{
  SCRIPT_RAW_URL="https://raw.githubusercontent.com/0xyassine/poc-seeker/master/poc-seeker.sh"
  REMOTE_VERSION=$(curl -r 0-160 -m 5 --connect-timeout 5 -s "$SCRIPT_RAW_URL" 2>/dev/null | grep 'TOOL_VERSION=' | awk -F= '{print $2}' | head -n 1)
  if [ $? -eq 0 ];then
    if [[ "$REMOTE_VERSION" == "$TOOL_VERSION" ]];then
      green "😎 The script is up-to-date 😎 \n"
      echo
    else
      yellow "You are using an outdated script version. The update is really easy using this command 🤓\n"
      cyan "sudo curl -s https://raw.githubusercontent.com/0xyassine/poc-seeker/master/poc-seeker.sh -o /usr/local/bin/poc-seeker && sudo chmod +x /usr/local/bin/poc-seeker\n"
      echo
    fi
  fi
}

#VARIABLES
POTENTIAL_FINDING=()
HAVE_A_LOOK=()
CHECK_RESULTS=false
HELP=false
SEARCH_FIRST=false
POC_SCRIPT_EXTENSIONS=(
  ".py"    # Python, popular for its simplicity and the extensive availability of libraries
  ".rb"    # Ruby, used for metaprogramming and quick exploits
  ".pl"    # Perl, known for its text processing capabilities
  ".sh"    # Shell script, for UNIX/Linux environments
  ".ps1"   # PowerShell, powerful for Windows environments and automation
  ".bat"   # Batch files, for simple Windows-oriented tasks
  ".js"    # JavaScript, for web-based vulnerabilities and browser exploits
  ".php"   # PHP, for server-side web application vulnerabilities
  ".c"     # C language, for low-level exploits, buffer overflows, etc.
  ".cpp"   # C++, used similarly to C for exploits requiring object-oriented features
  ".go"    # Go, for writing efficient and concurrent programs, sometimes used in PoCs
  ".lua"   # Lua, lightweight scripting language, used in game modding and sometimes web
  ".rs"    # Rust, for safe and concurrent system-level exploits
  ".swift" # Swift, mainly for PoCs targeting Apple ecosystems
#  "nse"   # nmap script
)

#RANDOM USER AGENT
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36"
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0"
)
RANDOM_UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}

function exploit-db()
{
  if ! which searchsploit &> /dev/null;then
    printf "😔${CYAN} You have to install${NC} ${RED}searchsploit${NC} ${CYAN}to search into exploit-db${NC} 😔\n"
    if [ -f /etc/os-release ]; then
      . /etc/os-release
      OS=$ID
      if [[ "$OS" == "kali" ]];then
        printf " Seems like you are using Kali linux, what about trying ${CYAN}sudo apt update && sudo apt install -y exploitdb ${NC}😀\n"
      else
        printf "You can check ${CYAN}https://gitlab.com/exploit-database/exploitdb${NC} 😀\n"
      fi
    else
      printf "You can check ${CYAN}https://gitlab.com/exploit-database/exploitdb${NC} 😀\n"
    fi
  else
    spinner "Searching" "exploit db" &
    if [[ ! -z "$CVE_FROM_QUERY" ]];then
      RESULTS=$(searchsploit --cve "$CVE_FROM_QUERY" -w | awk '{print $NF}' | grep 'http')
    else
      RESULTS=$(searchsploit "$QUERY" -w | awk '{print $NF}' | grep 'http')
    fi
    for URL in $RESULTS;do
      FILE_ID=$(echo "$URL" | awk -F/ '{print $NF}')
      if $CHECK_RESULTS && [[ ! -z "$CVE_FROM_QUERY" ]];then
        if searchsploit -p $FILE_ID | grep -wq "$CVE_FROM_QUERY";then
          POTENTIAL_FINDING+=("$URL")
        else
          HAVE_A_LOOK+=("$URL")
        fi
      else
        POTENTIAL_FINDING+=("$URL")
      fi
    done
    kill "$!"
    printf "\r🤞   Searching ${RED}exploit db${NC} ${GREEN}             DONE${NC}\n"
  fi
}

#GET ALL GITHUB REPOS FOUND BY THE SEARCH QUERY
function github_repos()
{
  local QUERY="$@"
  if [ ! -z $GITHUB_TOKEN ];then
    QUERY_RESULT=$(curl -m 15 --connect-timeout 15 -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" "https://api.github.com/search/repositories?q=${QUERY}+in:name,description&sort=stars&order=desc" 2>/dev/null)
    REPOS=$( echo "$QUERY_RESULT" | jq -r '.items[] | .full_name' 2>/dev/null | head -n $GITHUB_LIMIT)
  else
    QUERY_RESULT=$(curl -m 15 --connect-timeout 15 -s -H "Accept: application/vnd.github+json" "https://api.github.com/search/repositories?q=${QUERY}+in:name,description&sort=stars&order=desc" 2>/dev/null)
    REPOS=$(echo "$QUERY_RESULT" | jq -r '.items[] | .full_name' 2>/dev/null | head -n $GITHUB_LIMIT)
  fi
  if [ $? -eq 0 ];then
    REPOS=$(echo $REPOS | tr '\n' ' ')
  else
    if echo "$QUERY_RESULT" | jq -r .message | grep -qi 'API rate limit';then
      GITHUB_SEARCH_FAILED=true
      IS_RATE_LIMITED=true
      GITHUB_EXTENSIONS_FAILED=true
    else
      GITHUB_SEARCH_FAILED=true
    fi
  fi
}

#GET FILES INSIDE THE GITHUB REPO
function github_repo_files()
{
  local REPO="$@"
  sleep 0.1
  if [ ! -z $GITHUB_TOKEN ];then
    CONTENT_RESULTS=$(curl -m 15 --connect-timeout 15 -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/contents" 2>/dev/null)
    FILE_LIST=$( echo "$CONTENT_RESULTS" | jq -r '.[] | .name' 2>/dev/null)
  else
    CONTENT_RESULTS=$(curl -m 15 --connect-timeout 15 -s -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/contents" 2>/dev/null)
    FILE_LIST=$(echo "$CONTENT_RESULTS" | jq -r '.[] | .name' 2>/dev/null)
  fi
  if [ $? -eq 0 ];then
    FILE_LIST=$(echo $FILE_LIST | tr '\n' ' ')
  else
    if echo "$CONTENT_RESULTS" | jq -r .message | grep -qi 'API rate limit';then
      IS_RATE_LIMITED=true
      GITHUB_EXTENSIONS_FAILED=true
    else
      GITHUB_EXTENSIONS_FAILED=true
    fi
  fi
}

function github()
{
  GITHUB_SEARCH_FAILED=false
  GITHUB_EXTENSIONS_FAILED=false
  IS_RATE_LIMITED=false

  spinner "Searching" "github" &
  #GET THE LIST OF REPOSITORIES
  github_repos "$QUERY"
  for REPO in $REPOS; do
    sleep 0.5
    #GET THE LIST OF FILES INSIDE THE REPOSITORY
    if ! $IS_RATE_LIMITED && ! $GITHUB_EXTENSIONS_FAILED;then
      github_repo_files "$REPO"
    else
      if $GITHUB_SEARCH_FAILED;then
        echo
        red "\n 🤯 Searching github repositories failed. Results from GitHub may not be accurate 🤯 \n"
        echo
      fi
      if $GITHUB_EXTENSIONS_FAILED;then
        echo
        red "\n 🤯 Searching github for file extensions failed. Results from GitHub may not be accurate 🤯 \n"
        echo
      fi
      if $IS_RATE_LIMITED;then
        echo
        red "\n 🤯 GitHub Api rate limit is hit. Results from GitHub may not be accurate 🤯 \n"
        echo
      fi
      if [ -z $GITHUB_TOKEN ];then
        printf " * Consider using ${CYAN}--github-access-token${NC} option 😀\n"
      fi
      kill "$!"
      return
    fi
    POTENTIAL=false
    POSSIBLE=false
    REPO_WITH_README=false
    REQUIRED_EXTENSION_FOUND=false
    CVE_FOUND=false
    if echo "$FILE_LIST" | grep -qEi 'README\.md';then
      REPO_WITH_README=true
    fi
    #CHECK FILE EXTENSION
    if echo "$FILE_LIST" | grep -Eqi "($(echo ${POC_SCRIPT_EXTENSIONS[@]} | tr ' ' '|' | sed -e 's/\./\\./g' | sed 's/|/\ \|/g' | sed -e 's/$/\ /'))";then
      REQUIRED_EXTENSION_FOUND=true
    fi
    #FINDING
    if $REPO_WITH_README;then
      if curl -m 15 --connect-timeout 15 -s "https://raw.githubusercontent.com/$REPO/main/README.md" | grep -wiq "$CVE_FROM_QUERY";then
        CVE_FOUND=true
      elif curl -m 15 --connect-timeout 15 -s "https://raw.githubusercontent.com/$REPO/master/README.md" | grep -wiq "$CVE_FROM_QUERY";then
        CVE_FOUND=true
      fi
      if $REQUIRED_EXTENSION_FOUND && $CVE_FOUND;then
        POTENTIAL=true
      else
        ! $CHECK_RESULTS && POSSIBLE=true
      fi
    else
      if $REQUIRED_EXTENSION_FOUND;then
        POTENTIAL=true
      else
        ! $CHECK_RESULTS && POSSIBLE=true
      fi
    fi
    if $POTENTIAL;then
      POTENTIAL_FINDING+=("https://github.com/$REPO ")
    fi
    if $POSSIBLE;then
      HAVE_A_LOOK+=("https://github.com/$REPO ")
    fi
  done
  kill "$!"
  if ! $GITHUB_SEARCH_FAILED;then
    printf "\r🤞   Searching ${RED}github${NC} ${GREEN}                 DONE${NC}\n"
  fi
}

function sploitus()
{
  SPLOITUS_SEARCH_FAILED=false
  spinner "Searching" "sploitus" &
  OFFSET=0
  MAX_ITEMS=$SPLOITUS_LIMIT
  while true;do
    ALL_INFO=$(curl -m 15 --connect-timeout 15 -s -X $'POST' -H $'Host: sploitus.com' -H "Accept: application/json" -H "Content-Type: application/json" -H "User-Agent: $RANDOM_UA" -H $'Origin: https://sploitus.com' -H "Referer: https://sploitus.com/?query=${QUERY}" -H $'Accept-Language: en-US,en;q=0.9' --data "{\"type\":\"exploits\",\"sort\":\"default\",\"query\":\"${QUERY}\",\"title\":false,\"offset\":${OFFSET}}" https://sploitus.com/search 2>/dev/null | jq)
    if [ $? -ne 0 ];then
      echo
      red "🤯 Searching sploitus failed 🤯 \n"
      SPLOITUS_SEARCH_FAILED=true
      break
      echo
    fi
    if $CHECK_RESULTS && [[ ! -z "$CVE_FROM_QUERY" ]];then
      URLS=$(echo $ALL_INFO | jq -r --arg KEY "$CVE_FROM_QUERY" '.exploits[] | select(.source | test($KEY; "i")) | .href' 2>/dev/null | tr '\n' ' ')
    else
      URLS=$(echo "$ALL_INFO" | jq -r '.exploits[] | .href' 2>/dev/null | tr '\n' ' ')
    fi
    if [ $(echo "$URLS" | wc -l) -eq 0 ];then
      break
    fi
    for URL in "$URLS";do
      HAVE_A_LOOK+=($URL)
    done
    OFFSET=$((OFFSET + 10))
    if [ $OFFSET -eq $MAX_ITEMS ];then
      break
    fi
  done
  kill "$!"
  if ! $SPLOITUS_SEARCH_FAILED;then
    printf "\r🤞   Searching ${RED}sploitus${NC} ${GREEN}               DONE${NC}\n"
  fi
}

function packetstormsecurity()
{
  PACKETSTORM_SEARCH_FAILED=false
  spinner "Searching" "packetstormsecurity" &
  PACKET_STORM_IDS=$(curl -m 5 --connect-timeout 5 -s "https://packetstormsecurity.com/search/?q=${QUERY}&s=files" -H "User-Agent: $RANDOM_UA" 2>/dev/null | grep -Eo '\/files\/[0-9]*\/' | awk -F/ '{print $3}' | sort -u)
  if [ $? -eq 0 ];then
    for FILE_ID in $(echo $PACKET_STORM_IDS);do
      sleep 1
      if $CHECK_RESULTS && [[ ! -z "$CVE_FROM_QUERY" ]];then
        if curl -m 5 --connect-timeout 5 -s "https://packetstormsecurity.com/files/${FILE_ID}" -H "User-Agent: $RANDOM_UA" 2>/dev/null | grep -wiq "$CVE_FROM_QUERY";then
          HAVE_A_LOOK+=("https://packetstormsecurity.com/files/${FILE_ID}/")
        fi
      else
        HAVE_A_LOOK+=("https://packetstormsecurity.com/files/${FILE_ID}/")
      fi
    done
  else
    red "🤯 Searching packetstorm security failed 🤯 \n"
    PACKETSTORM_SEARCH_FAILED=true
  fi
  kill "$!"
  if ! $PACKETSTORM_SEARCH_FAILED;then
    printf "\r🤞   Searching ${RED}packetstormsecurity${NC} ${GREEN}    DONE${NC}\n"
  fi
}

function vulnerability-lab()
{
  VULNERABILITY_LAB_SEARCH_FAILED=false
  spinner "Searching" "vulnerability lab" &
  VULNERABILITY_LIST=$(curl -m 15 --connect-timeout 15 -i -s -k -X GET -H $'Host: www.vulnerability-lab.com' -H $'Upgrade-Insecure-Requests: 1' -H "User-Agent: $RANDOM_UA" -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Referer: https://www.vulnerability-lab.com/search.php' "https://www.vulnerability-lab.com/search.php?search=${QUERY}&submit=Search" 2>/dev/null | grep -Eo 'get\_content\.php\?id=[0-9]*' | sort -u)
  if [ $? -eq 0 ];then
    for ID_URL in $(echo $VULNERABILITY_LIST);do
      sleep 1
      if $CHECK_RESULTS && [[ ! -z "$CVE_FROM_QUERY" ]];then
        if curl -m 15 --connect-timeout 15 -s "https://www.vulnerability-lab.com/$ID_URL" 2>/dev/null | grep -wiq "$CVE_FROM_QUERY";then
          POTENTIAL_FINDING+=("https://www.vulnerability-lab.com/$ID_URL")
        fi
      else
        HAVE_A_LOOK+=("https://www.vulnerability-lab.com/$ID_URL")
      fi
    done
  else
    red "🤯 Searching vulnerability lab failed 🤯 \n"
    VULNERABILITY_LAB_SEARCH_FAILED=true
  fi
  kill "$!"
  if ! $VULNERABILITY_LAB_SEARCH_FAILED;then
    printf "\r🤞   Searching ${RED}vulnerability lab${NC} ${GREEN}      DONE${NC}\n"
  fi
}

function print_item()
{
    local LABLE=$1
    local VALUE=$2
    printf "${RED}-> ${NC}${BLUE}%-20s${NC}: %s\n" "$LABLE" "$VALUE"
    if [ ! -z "$OUTPUT_FILE" ] && ! $IGNORE_SAVING_OUTPUT;then
      printf "%-20s: %s\n" "$LABLE" "$VALUE" >> $OUTPUT_FILE
    fi
}

NVD_DISABLED=false
function nvd_collect_information()
{
  cyan "🤓 Hold on, trying to collect few details 🤓\n"
  CVE_FROM_QUERY=$(echo "$CVE_FROM_QUERY" | tr 'a-z' 'A-Z')
  if [[ ! -z "$NVD_API_KEY" ]];then
    ALL_DETAILS=$(curl -m 15 --connect-timeout 15 -s --location "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVE_FROM_QUERY" -H "apiKey: $NVD_API_KEY")
  else
    ALL_DETAILS=$(curl -m 15 --connect-timeout 15 -s --location "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVE_FROM_QUERY")
  fi
  TOTAL_RESULTS=$(echo $ALL_DETAILS | jq -r '.totalResults')
  if [[ ! -z "$ALL_DETAILS" ]] && [[ $TOTAL_RESULTS -ne 0 ]];then
    SEARCH_FIRST=true
    cyan "🥳 Before searching for a valid POC, I've got few details for you 🥳\n"
    echo
    printf '%.0s-' {1..30}
    echo
    CVE_ID=$(echo "$ALL_DETAILS" | jq -r '.vulnerabilities[0].cve.id')
    CVE_DESCRIPTION=$(echo "$ALL_DETAILS" | jq -r '.vulnerabilities[0].cve.descriptions[0].value')
    BASE_SCORE=$(echo "$ALL_DETAILS" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore')
    ATTACK_COMPLEXITY=$(echo "$ALL_DETAILS" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.attackComplexity')
    USER_INTERACTION=$(echo "$ALL_DETAILS" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.userInteraction')
    PRIVILEGES_REQUIRED=$(echo "$ALL_DETAILS" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.privilegesRequired')
    if [[ ! -z "$CVE_ID" ]]; then
        print_item "CVE id" "$CVE_ID"
    fi
    if [[ ! -z "$CVE_DESCRIPTION" ]]; then
        print_item "CVE description" "$CVE_DESCRIPTION"
    fi
    if [[ ! -z "$BASE_SCORE" ]]; then
        print_item "Base score" "$BASE_SCORE"
    fi
    if [[ ! -z "$ATTACK_COMPLEXITY" ]]; then
        print_item "Attack complexity" "$ATTACK_COMPLEXITY"
    fi
    if [[ ! -z "$USER_INTERACTION" ]]; then
        print_item "User interaction" "$USER_INTERACTION"
    fi
    if [[ ! -z "$PRIVILEGES_REQUIRED" ]]; then
        print_item "Required privileges" "$PRIVILEGES_REQUIRED"
    fi
    printf '%.0s-' {1..30}
    echo;echo
  fi
}

logo
verify_packages
check_curl_features

#IS THE TOOL EXECUTED WITHOUT ANY ARGUEMTNS?
if [[ $# -eq 0 ]];then
  red "🤯 Looks like you executed the script without any arguments 🤯 \n"
  green "🤓 No worries, I can help 🤓\n"
  help
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -q|--query)
      if [ -n "$2" ]; then
        QUERY="$2"
        QUERY=$(echo "$QUERY" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        shift 2
      else
        red "😔 Opsss ! Search query not provided after -q or --query 😔\n"
        exit 1
      fi
      ;;
    -o|--output)
      if [ -n "$2" ]; then
        OUTPUT_FILE="$2"
        shift 2
      else
        red "😔 Opsss ! Output file name not provided after -o or --output 😔\n"
        help
        exit 1
      fi
      ;;
    --nvd-api-key)
      if [ -n "$2" ]; then
        NVD_API_KEY="$2"
        shift 2
      else
        red "😔 Opsss ! Nvd api key not provided after --nvd-api-key 😔\n"
        exit 1
      fi
      ;;
    -c|--check)
        CHECK_RESULTS=true
        shift
      ;;
    --disable-nvd)
        NVD_DISABLED=true
        shift
      ;;
    -h|--help)
        HELP=true
        shift
      ;;
    --github-access-token)
      if [ -n "$2" ]; then
        GITHUB_TOKEN="$2"
        shift 2
      else
        red "😔 Opsss ! Github token not provided after the --github-access-token option 😔\n"
        exit 1
      fi
      ;;
    -s|--source)
      if [ -n "$2" ]; then
        SOURCE_LIST="$2"
        SOURCE_LIST=$(echo "$SOURCE_LIST" | tr ',' ' ')
        for SOURCE in $SOURCE_LIST;do
          if ! echo ${ACCEPTED_SOURCES[@]} | grep -qwF "$SOURCE";then
            red "😔 Opsss ! you provided a non valid source [ $SOURCE ] 😔\n"
            help
            exit 1
          fi
        done
        shift 2
      else
        red "😔 Opsss ! The source is not provided after the -s or --source option 😔\n"
        exit 1
      fi
      ;;
    -e|--extensions)
      if [ -n "$2" ]; then
        EXTENSIONS_LIST="$2"
        EXTENSIONS_LIST=($(echo "$EXTENSIONS_LIST" | tr ',' ' '))
        for EXTENSIONS in ${EXTENSIONS_LIST[@]};do
          if ! [[ $EXTENSIONS =~ ^\.[a-zA-Z0-9]+$ ]];then
            red "😔 [ $EXTENSIONS ] does not have a valid file extension format 😔\n"
            echo
            help
            exit
          fi
        done
        shift 2
      else
        red "😔 Opsss ! The extensions are not provided after the -e or --extensions option 😔\n"
        exit 1
      fi
      ;;
    -sl|--sploitus-limit)
      if [ -n "$2" ]; then
        SPLOITUS_LIMIT="$2"
        if ! ([[ $SPLOITUS_LIMIT =~ ^[0-9]+$ ]] && [ $(($SPLOITUS_LIMIT % 10)) -eq 0 ]);then
          red "😔 Opsss ! Sploitus search limit can only be a number multiple of 10 😔\n"
          help
          exit 1
        fi
        shift 2
      else
        red "😔 Opsss ! Sploitus search limit is not provided after the -sl or --sploitus-limit option 😔\n"
        exit 1
      fi
      ;;
    -gl|--github-limit)
      if [ -n "$2" ]; then
        GITHUB_LIMIT="$2"
        if ! [[ $GITHUB_LIMIT =~ ^[0-9]+$ ]];then
          red "😔 Opsss ! GitHub search limit can only be a number 😔\n"
          help
          exit 1
        fi
        shift 2
      else
        red "😔 Opsss ! GitHub search limit is not provided after the -gl or --github-limit option 😔\n"
        exit 1
      fi
      ;;
    *)
      red "😱 Oh noo, you provided unknown argument [ $1 ] 😱\n"
      green "Maybe it's time to have a look at the help menu again 😉\n"
      help
      exit 1
      ;;
    esac
done

if $HELP;then
  help
  exit
fi

#MAKE SURE WE HAVE AN INPUT
if [ -z "$QUERY" ];then
  red "🥶 Unfortunately I can't search for CVE if you don't provide an input 🥶\n"
  printf "🙄 ${BLUE}Please use${NC} ${CYAN}-q ${NC} or  ${CYAN}--query ${NC}${BLUE}option${NC}🙄\n"
  help
  exit 1
else
  if [ $(echo "$QUERY" | wc -c) -le 2 ];then
    yellow "😕 You used a very short query, please don't blame me if I found nothing useful 😕\n"
    echo
  fi
  CVE=$(echo "$QUERY" | grep -oiE 'CVE-[0-9]*-[0-9]*')
  if [[ ! -z "$CVE" ]];then
    if [ $(echo $CVE | awk -F- '{print $2}' | wc -c) -lt 5 ] || [ $(echo $CVE | awk -F- '{print $3}' | wc -c) -lt 5 ];then
      yellow "😕 Seems like the CVE id is not really correct, results may not be accurate 😕\n"
      echo
    fi
  fi
fi

echo
check_for_update

if [ -z "$SPLOITUS_LIMIT" ] || [ $SPLOITUS_LIMIT -lt 10 ];then
  SPLOITUS_LIMIT=10
fi
if [ -z "$GITHUB_LIMIT" ];then
  GITHUB_LIMIT=10
fi

#EXTRACT THE CVE FROM THE QUERY
CVE_FROM_QUERY=$(echo "$QUERY" | grep -oiE 'CVE-[0-9]{4}-[0-9]{4,}')
if [ ! -z "$CVE_FROM_QUERY" ];then
  if [ $(echo "$CVE_FROM_QUERY" | tr ' ' '\n' | wc -l) -gt 1 ];then
    red "😪 Searching for multiple CVE's is not supported for now 😪\n"
    cyan "😉 This will be implemented in the future 😉\n"
    exit 1
  fi
fi

IGNORE_SAVING_OUTPUT=false
if [ ! -z "$OUTPUT_FILE" ];then
  if [ ! -f $OUTPUT_FILE ];then
    if ! mkdir -p $(dirname $OUTPUT_FILE) &>/dev/null;then
      red "😔 I failed to create the output directory for you, maybe check you permissions 😔\n"
      echo
      IGNORE_SAVING_OUTPUT=true
    else
      if ! touch $OUTPUT_FILE &>/dev/null;then
        red "😔 I failed to create the output file for you, maybe check you permissions 😔\n"
        echo
        IGNORE_SAVING_OUTPUT=true
      fi
    fi
  else
    if ! touch $OUTPUT_FILE &>/dev/null;then
      red "😔 I failed to write to the output file for you, maybe check you permissions 😔\n"
      echo
      IGNORE_SAVING_OUTPUT=true
    fi
  fi
fi

if [ ! -z "$OUTPUT_FILE" ] && ! $IGNORE_SAVING_OUTPUT;then
  echo "------------" > $OUTPUT_FILE
  echo "$QUERY" >> $OUTPUT_FILE
  echo "------------" >> $OUTPUT_FILE
fi

if [[ ! -z "$CVE_FROM_QUERY" ]] && ! $NVD_DISABLED;then
  nvd_collect_information
fi

if ! $SEARCH_FIRST;then
  printf "🥸 ${BLUE}I am searching for${NC}${CYAN} $QUERY ${NC}${BLUE}POC, hold on ${NC} 🥸\n"
  echo
fi

if [[ ! -z "$EXTENSIONS_LIST" ]];then
  POC_SCRIPT_EXTENSIONS=(${EXTENSIONS_LIST[@]})
fi

if [[ -z "$SOURCE_LIST" ]];then
  github
  sploitus
  exploit-db
  vulnerability-lab
else
  for SOURCE in $SOURCE_LIST;do
    $SOURCE
  done
fi


echo
if [ ${#POTENTIAL_FINDING[@]} -ne 0 ];then
  green "😎 I think I've found potential POC for you 😎 \n"
  echo
  if [ ! -z "$OUTPUT_FILE" ] && ! $IGNORE_SAVING_OUTPUT;then
    echo '' >> $OUTPUT_FILE
    echo "Potential POC's" >> $OUTPUT_FILE
  fi
  for POTENTIAL in $(echo ${POTENTIAL_FINDING[@]} | tr ' ' '\n' | sort -u);do
    printf "\r${RED}[+] ${NC}${GREEN}${POTENTIAL} ${NC}\n"
    if [ ! -z "$OUTPUT_FILE" ] && ! $IGNORE_SAVING_OUTPUT;then
      echo "[+] $POTENTIAL" >> $OUTPUT_FILE
    fi
  done
echo
fi 


for ITEM in ${POTENTIAL_FINDING[@]};do
  if echo ${HAVE_A_LOOK[@]} | grep -q "$ITEM";then
    HAVE_A_LOOK=($(echo ${HAVE_A_LOOK[@]} | sed -e "s#$ITEM##g"))
  fi
done



if [ ${#HAVE_A_LOOK[@]} -ne 0 ];then
  green "🧐 You may have a look at the following 🧐 \n"
  echo
  if [ ! -z "$OUTPUT_FILE" ] && ! $IGNORE_SAVING_OUTPUT;then
    echo '' >> $OUTPUT_FILE
    echo "Have a look" >> $OUTPUT_FILE
  fi
  for POSSIBLE in $(echo ${HAVE_A_LOOK[@]} | tr ' ' '\n' | sort -u);do
    printf "\r${RED}[!] ${NC}${YELLOW}$POSSIBLE${NC}\n"
    if [ ! -z "$OUTPUT_FILE" ] && ! $IGNORE_SAVING_OUTPUT;then
      echo "[!] $POSSIBLE" >> $OUTPUT_FILE
    fi
  done
fi

if [ ${#HAVE_A_LOOK[@]} -eq 0 ] && [ ${#POTENTIAL_FINDING[@]} -eq 0 ];then
  red "🥺 Oh no I wasn't able to find any POC for you 🥺 \n"
fi

if [ ! -z "$OUTPUT_FILE" ] && ! $IGNORE_SAVING_OUTPUT;then
  echo "------------" >> $OUTPUT_FILE
  echo "------------" >> $OUTPUT_FILE
fi
