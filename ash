#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
set -e
START_TIME=$(date +%s)

print_usage() {
  echo "NAME:"
  echo -e "\t$(basename $0)"
  echo "SYNOPSIS:"
  echo -e "\t$(basename $0) [OPTIONS] --source-dir /path/to/dir --output-dir /path/to/dir"
  echo "OPTIONS:"
  echo -e "\t-p | --preserve-report   Add timestamp to the final report file to avoid overriding it after multiple executions"
  echo -e "\t--source-dir             Path to the directory containing the code/files you wish to scan. Defaults to \$(pwd)"
  echo -e "\t--output-dir             Path to the directory that will contain the report of the scans. Defaults to \$(pwd)"
  echo -e "\t--force                  Rebuild the Docker images of the scanning tools, to make sure software is up-to-date."
  echo -e "\t-q | --quiet             Don't print verbose text about the build process.\n"
  echo -e "\t-c | --no-color          Don't print colorized output"
  echo -e "\t-q | --quiet             Don't print verbose text about the build process.\n"
  echo -e "For more information please visit https://github.com/aws-samples/automated-security-helper"
}

# Look for extensions
GIT_EXTENSIONS=("git")
PY_EXTENSIONS=("py" "pyc" "ipynb")
INFRA_EXTENSIONS=("yaml" "yml" "tf" "json" "dockerfile")
CFN_EXTENSIONS=("yaml" "yml" "json")
JS_EXTENSIONS=("js")
GRYPE_EXTENSIONS=("js" "py")

# Look for specific files
CDK_FILENAMES=("cdk.json")

DOCKERFILE_LOCATION="$(dirname "${BASH_SOURCE[0]}")"/"helper_dockerfiles"
UTILS_LOCATION="$(dirname "${BASH_SOURCE[0]}")"/"utils"
CFNRULES_LOCATION="$(dirname "${BASH_SOURCE[0]}")"/"appsec_cfn_rules"

#
# for tracking the highest return code from running tools
#
HIGHEST_RC=0

#
# Initialize options
#
COLOR_OUTPUT="true"

while (("$#")); do
  case $1 in
  --source-dir)
    shift
    SOURCE_DIR="$1"
    ;;
  --output-dir)
    shift
    OUTPUT_DIR="$1"
    ;;
  --force)
    DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} --no-cache"
    ;;
  --quiet | -q)
    DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} -q"
    QUIET_OUTPUT="-q"
    ;;
  --preserve-report | -p)
    PRESERVE_FILE="true"
    ;;
  --no-color | -c)
    COLOR_OUTPUT="false"
    ;;
  *)
    print_usage
    exit 1
    ;;
  esac
  shift
done

print_found_msg() {
  EXTENSIONS=$1
  echo -e "${LPURPLE}Found one of ${EXTENSIONS} items in your source dir${NC}"
}

TIMESTAMP=$(date +%s)
USERID=$(echo -n "$(whoami)$(hostname)" | openssl dgst -sha512)
TOOLID=$(basename "$0")
EXTENSIONS_USED=()

if [[ $COLOR_OUTPUT = "true" ]]; then
  LPURPLE='\033[1;35m'
  LGRAY='\033[0;37m'
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  CYAN='\033[0;36m'
  NC='\033[0m' # No Color
else
  #
  # Set all the colorizing escape sequences to empty strings
  #
  LPURPLE=''
  LGRAY=''
  GREEN=''
  RED=''
  CYAN=''
  NC='' # No Color
fi

# shellcheck disable=SC2120
# Find all possible extensions in the $SOURCE_DIR directory
map_extensions_anf_files() {
  all_files=$(find "${SOURCE_DIR}" \( -path '*/node_modules*' -prune -o -path '*/cdk.out*' -prune \) -o -type f -name '*') # $SOURCE_DIR comes from user input
  extenstions_found=()
  files_found=()

  for file in $all_files; do
    file=$(echo "$file" | tr '[:upper:]' '[:lower:]') # lower case all the names

    extension="${file##*.}" # extract the extensions out of each file name.
    filename="${file##*/}" # extract the base filename plus extension

    # add only new extensions, skipping already-found ones.
    if [[ ! "${extenstions_found[*]}" =~ ${extension} ]]; then
      extenstions_found+=("$extension")
    fi

    # add only new files, skipping already-found ones.
    if [[ ! "${files_found[*]}" =~ ${filename} ]]; then
      files_found+=("$filename")
    fi
  done
}

# Try to locate specific extension type (ie yaml, py) from all the extensions found in $SOURCE_DIR
search_extension() {
  items_to_search=("$@") # passed as parameter to the function
  item_found=false
  for item in "${items_to_search[@]}"; do
    if [[ "${extenstions_found[*]}" =~ ${item} || "${files_found[*]}" =~ ${item} ]]; then
      item_found=true
    fi
  done
}

search_file_content() {
  items_to_search=("$@") # passed as parameter to the function
  item_found=false
  cfn_files=$(grep -lri 'AWSTemplateFormatVersion' ${SOURCE_DIR} --exclude-dir="cdk.out")
}

# Validate the input and set default values
# shellcheck disable=SC2120
validate_input() {
  if [[ -z ${PRESERVE_FILE} ]]; then AGGREGATED_RESULTS_REPORT_FILENAME="aggregated_results.txt"; else AGGREGATED_RESULTS_REPORT_FILENAME="aggregated_results-$(date +%s).txt"; fi
  if [[ -z ${FORCE_REBUILD} ]]; then FORCE_REBUILD="false"; fi
  if [[ -z ${SOURCE_DIR} ]]; then SOURCE_DIR="$(pwd)"; else SOURCE_DIR=$(cd "${SOURCE_DIR}"; pwd)/$(basename "$1"); fi # Transform any relative path to absolute
  if [[ -z ${OUTPUT_DIR} ]]; then OUTPUT_DIR="$(pwd)"; else OUTPUT_DIR=$(cd "${OUTPUT_DIR}"; pwd)/$(basename "$1"); fi # Transform any relative path to absolute
  CFNRULES_LOCATION=$(cd "${CFNRULES_LOCATION}"; pwd)/$(basename "$1") # Transform any relative path to absolute
  UTILS_LOCATION=$(cd "${UTILS_LOCATION}"; pwd)/$(basename "$1") # Transform any relative path to absolute
}

# Execute the main scan logic for specific framework
# The first argument passed to this method is the dockerfile that executes the actual scan
# The remaining arguments (can be treated as *args in python) are the extensions we wish to scan for
run_security_check() {
  EXTENSIONS_USED=( "${EXTENSIONS_USED[@]}" "$1" )
  echo "EXTENSIONS_USED is " $1
  DOCKERFILE_TO_EXECUTE="$1"
  ITEMS_TO_SCAN=("${@:2}") # take all the array of commands which are the extensions to scan (slice 2nd to end)
  RUNTIME_CONTAINER_NAME="scan-$RANDOM"

  search_extension "${ITEMS_TO_SCAN[@]}" # First lets verify this extension even exists in the $SOURCE_DIR directory
  if [[ $item_found == "true" ]]; then
    print_found_msg "${ITEMS_TO_SCAN}"

    docker build -t "${RUNTIME_CONTAINER_NAME}" -f "${DOCKERFILE_LOCATION}"/"${DOCKERFILE_TO_EXECUTE}" ${DOCKER_EXTRA_ARGS} "${SOURCE_DIR}" > /dev/null
    set +e # the scan will fail the command if it finds any finding. we don't want it to stop our script execution
    docker run --name "${RUNTIME_CONTAINER_NAME}" -v "${CFNRULES_LOCATION}":/cfnrules -v "${UTILS_LOCATION}":/utils -v "${SOURCE_DIR}":/app "${RUNTIME_CONTAINER_NAME}"
    #
    # capture the return code of the command invoked through docker
    #
    RETURN_CODE=$?
    if [[ $RETURN_CODE -ne 0 ]]; then

      #
      # Note the un-successful completion in RED text
      #
      echo -e "${RED}Dockerfile ${DOCKERFILE_TO_EXECUTE} returned $RETURN_CODE${NC}"

      #
      # If the return code is negative, find the absolute value
      #
      if [[ $RETURN_CODE -lt 0 ]]; then
        let RETURN_CODE=RETURN_CODE*-1
      fi

      #
      # Capture the highest return code from the tools run
      #
      if [[ $RETURN_CODE -gt $HIGHEST_RC ]]; then
        HIGHEST_RC=$RETURN_CODE
      fi
    else

      #
      # Note the successful completion in GREEN text
      #
      echo -e "${GREEN}Dockerfile ${DOCKERFILE_TO_EXECUTE} returned $RETURN_CODE${NC}"
    fi

    set -e # from this point, any failure will halt the execution.

    docker rm "${RUNTIME_CONTAINER_NAME}" >/dev/null # Let's keep it a clean environment
    docker rmi "${RUNTIME_CONTAINER_NAME}" >/dev/null # Let's keep it a clean environment
  fi
}



validate_input
map_extensions_anf_files

IFS=$'\n' # Support directories with spaces, make the loop iterate over newline instead of space
# Extract all zip files to temp dir before scanning
for zipfile in $(find "${SOURCE_DIR}" -iname "*.zip");
do
  unzip ${QUIET_OUTPUT} -d "${SOURCE_DIR}"/$(basename "${zipfile%.*}") $zipfile
done
unset IFS

run_security_check "Dockerfile-git" "${GIT_EXTENSIONS[@]}"
run_security_check "Dockerfile-py" "${PY_EXTENSIONS[@]}"
run_security_check "Dockerfile-yaml" "${INFRA_EXTENSIONS[@]}"
run_security_check "Dockerfile-js" "${JS_EXTENSIONS[@]}"
search_file_content "${CFN_EXTENSIONS}" || echo "No CFN files found"
run_security_check "Dockerfile-cdk" "${CFN_EXTENSIONS[@]}"
run_security_check "Dockerfile-grype" "${GRYPE_EXTENSIONS[@]}"

# Cleanup any previous file
rm -f "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"

# if an extension was not found, no report file will be in place, so skip the final report
if [[ $(find "${SOURCE_DIR}" -iname "*_report_result.txt" | wc -l | awk '{print $1}') > 0 ]];
then
  # Aggregate the results output files
  for result in "${SOURCE_DIR}"/*_report_result.txt;
  do
    echo "#############################################" >> "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"
    echo "Start of  ${result}" >> "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"
    echo "#############################################" >> "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"
    cat "${result}" >> "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"
    echo "#############################################" >> "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"
    echo "End of  ${result}" >> "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"
    echo -e "#############################################\n\n" >> "${OUTPUT_DIR}"/"${AGGREGATED_RESULTS_REPORT_FILENAME}"
  done
IFS=$'\n'
  # Cleanup any leftover files
  rm -f "${SOURCE_DIR}"/*_report_result.txt

  # Remove all python notebook converted files
  for converted_file in $(find "${SOURCE_DIR}" -iname "*-converted.py");
  do
    if [[ ${QUIET_OUTPUT} != '-q' ]]; then
      echo -e "${LGRAY}Deleting temporary ${converted_file}${NC}"
    fi
    rm -f ${converted_file}
  done

  # Remove all extracted zip files after scanning
  for zipfile in $(find "${SOURCE_DIR}" -iname "*.zip");
  do
    if [[ ${QUIET_OUTPUT} != '-q' ]]; then
      echo -e "${LGRAY}Deleting temporary" "${SOURCE_DIR}"/$(basename "${zipfile%.*}")${NC}
    fi
    rm -rf "${SOURCE_DIR}"/$(basename "${zipfile%.*}")
  done
unset IFS
  echo -e "${GREEN}\nYour final report can be found here:${NC} ${OUTPUT_DIR}/${AGGREGATED_RESULTS_REPORT_FILENAME}"
else
  echo -e "${GREEN}No extensions were found, nothing to scan at the moment.${NC}"
fi

END_TIME=$(date +%s)
TOTAL_EXECUTION=$((END_TIME-START_TIME))


RCCOLOR=${GREEN}
if [[ $HIGHEST_RC -gt 0 ]]; then
  RCCOLOR=${RED}
fi
echo -e "${RCCOLOR}Highest return code is $HIGHEST_RC${NC}"

exit $HIGHEST_RC
