#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
set -e
VERSION=("1.0.9-e-16May2023")
OCI_RUNNER="docker"


# Overrides default OCI Runner used by ASH
[ ! -z "$ASH_OCI_RUNNER" ] && OCI_RUNNER="$ASH_OCI_RUNNER"

print_usage() {
  echo "NAME:"
  echo -e "\t$(basename $0)"
  echo "SYNOPSIS:"
  echo -e "\t$(basename $0) [OPTIONS] --source-dir /path/to/dir --output-dir /path/to/dir"
  echo "OPTIONS:"
  echo -e "\t-v | --version           Prints version number.\n"
  echo -e "\t-p | --preserve-report   Add timestamp to the final report file to avoid overriding it after multiple executions."
  echo -e "\t--source-dir             Path to the directory containing the code/files you wish to scan. Defaults to \$(pwd)"
  echo -e "\t--output-dir             Path to the directory that will contain the report of the scans. Defaults to \$(pwd)"
  echo -e "\t--ext | -extension       Force a file extension to scan. Defaults to identify files automatically."
  echo -e "\t--force                  Rebuild the Docker images of the scanning tools, to make sure software is up-to-date."
  echo -e "\t-q | --quiet             Don't print verbose text about the build process."
  echo -e "\t-c | --no-color          Don't print colorized output."
  echo -e "\t-f | --finch             Use finch instead of docker to run the containerized tools.\n"
  echo -e "For more information please visit https://github.com/aws-samples/automated-security-helper"
}

# Look for extensions
GIT_EXTENSIONS=("git")
PY_EXTENSIONS=("py" "pyc" "ipynb")
INFRA_EXTENSIONS=("yaml" "yml" "tf" "json" "dockerfile")
CFN_EXTENSIONS=("yaml" "yml" "json" "template")
JS_EXTENSIONS=("js")
GRYPE_EXTENSIONS=("js" "py" "java" "go" "cs" "sh")

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
FORCED_EXT="false"

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
  --ext | -extenstion)
    shift
    FORCED_EXT="$1"
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
  --finch | -f)
    OCI_RUNNER="finch"
    ;;
  --version | -v)
    echo "ASH version $VERSION"
    EXITCODE=0
    exit $EXITCODE
    ;;
  *)
    print_usage
    exit 1
    ;;
  esac
  shift
done

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
map_extensions_and_files() {
  all_files=$(find "${SOURCE_DIR}" \( -path '*/node_modules*' -prune -o -path '*/cdk.out*' -prune \) -o -type f -name '*') # $SOURCE_DIR comes from user input
  extensions_found=()
  files_found=()

  for file in $all_files; do
    file=$(echo "$file" | tr '[:upper:]' '[:lower:]') # lower case all the names

    extension="${file##*.}" # extract the extensions out of each file name.
    filename="${file##*/}" # extract the base filename plus extension

    # add only new extensions, skipping already-found ones.
    if [[ ! "${extensions_found[*]}" =~ ${extension} ]]; then
      extensions_found+=("$extension")
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
  local item_found=0
  for item in "${items_to_search[@]}"; do
    if [[ "${extensions_found[*]}" =~ ${item} ]]; then
      local item_found=1
      echo "$item_found"
      break
    fi
  done
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
  local DOCKERFILE_TO_EXECUTE="$1"
  local ITEMS_TO_SCAN=("${@:2}") # take all the array of commands which are the extensions to scan (slice 2nd to end)
  local RUNTIME_CONTAINER_NAME="scan-$RANDOM"

  local RETURN_CODE=0

   # First lets verify this extension even exists in the $SOURCE_DIR directory
  echo -e "${LPURPLE}Items to scan for in ${GREEN}${DOCKERFILE_TO_EXECUTE}${LPURPLE} are: [ ${RED}${ITEMS_TO_SCAN[@]}${LPURPLE} ]${NC}"

  if [[ " ${ITEMS_TO_SCAN[*]} " =~ " ${FORCED_EXT} " ]] || [[ $(search_extension "${ITEMS_TO_SCAN[@]}") == "1" ]]; then
    echo -e "${LPURPLE}Found one or more of: [ ${RED}"${ITEMS_TO_SCAN[@]}"${LPURPLE} ] items in source dir,${NC} ${GREEN}running ${DOCKERFILE_TO_EXECUTE} ...${NC}"
    ${OCI_RUNNER} build -t "${RUNTIME_CONTAINER_NAME}" -f "${DOCKERFILE_LOCATION}"/"${DOCKERFILE_TO_EXECUTE}" ${DOCKER_EXTRA_ARGS} "${SOURCE_DIR}" > /dev/null
    set +e # the scan will fail the command if it finds any finding. we don't want it to stop our script execution
    ${OCI_RUNNER} run --name "${RUNTIME_CONTAINER_NAME}" -v "${CFNRULES_LOCATION}":/cfnrules -v "${UTILS_LOCATION}":/utils -v "${SOURCE_DIR}":/app "${RUNTIME_CONTAINER_NAME}"
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

    else

      #
      # Note the successful completion in GREEN text
      #
      echo -e "${GREEN}Dockerfile ${DOCKERFILE_TO_EXECUTE} returned $RETURN_CODE${NC}"
    fi

    set -e # from this point, any failure will halt the execution.

    ${OCI_RUNNER} rm "${RUNTIME_CONTAINER_NAME}" >/dev/null # Let's keep it a clean environment
    ${OCI_RUNNER} rmi "${RUNTIME_CONTAINER_NAME}" >/dev/null # Let's keep it a clean environment
  else
    echo -e "${LPURPLE}Found ${CYAN}none${LPURPLE} of: [ ${RED}"${ITEMS_TO_SCAN[@]}"${LPURPLE} ] items in source dir, ${CYAN}skipping run${LPURPLE} of ${GREEN}${DOCKERFILE_TO_EXECUTE}${NC}"
    RETURN_CODE=0
  fi

  #
  # This function was invoked from the main line processing of the ash script.
  # At that invocation (see below), the invocation is made with a trailing &
  # which spawns a sub-process and runs the function (really a copy of the parent process)
  # in the background.
  #
  # To propagate the return code from running the scan to the parent process, this function
  # needs to "exit ${RETURN_CODE}" rather than setting a global shell variable.
  # Setting the global shell variable in a sub-process will have no effect on the value
  # in the parent process.
  #
  # Return the status by exiting the sub-process with the return code.
  #

  # echo -e "${LPURPLE}Just before exsiting $1 - RC = ${RETURN_CODE}${NC}"
  exit ${RETURN_CODE}
}

validate_input

IFS=$'\n' # Support directories with spaces, make the loop iterate over newline instead of space
# Extract all zip files to temp dir before scanning
for zipfile in $(find "${SOURCE_DIR}" -iname "*.zip");
do
  unzip ${QUIET_OUTPUT} -d "${SOURCE_DIR}"/$(basename "${zipfile%.*}") $zipfile
done

unset IFS

all_files='' # Variable will be populated inside 'map_extensions_and_files' block

map_extensions_and_files

echo -e "ASH version $VERSION\n"

TOTAL_FILES=$(echo "$all_files" | wc -l)

echo -e "ASH found ${TOTAL_FILES} file(s) in the source directory..."
if [ $TOTAL_FILES -gt 1000 ]; then
  echo -e "${RED}Depending on your machine this might take a while...${NC}"
  for i in {1..5}
  do
    echo -n "." && sleep 1
  done
  echo -e "Starting now!";
fi

#
# set up some variables for use further down
#
typeset -a JOBS JOBS_RC
typeset -i i j

#
# Collect all the jobs to be run into a list that can be looped through
#
JOB_NAMES=("Dockerfile-git" "Dockerfile-py" "Dockerfile-yaml" "Dockerfile-js" "Dockerfile-grype" "Dockerfile-cdk")

#
# Loop through the checks to start, grabbing the right extensions to add in
# and start the check as a background process
#
i=0
for jobName in ${JOB_NAMES[@]}; do
  if [ ${jobName} == 'Dockerfile-git' ]; then
    JOB_EXTENSIONS=(${GIT_EXTENSIONS[@]})
  elif [ ${jobName} == 'Dockerfile-py' ]; then
    JOB_EXTENSIONS=(${PY_EXTENSIONS[@]})
  elif [ ${jobName} == 'Dockerfile-yaml' ]; then
    JOB_EXTENSIONS=(${INFRA_EXTENSIONS[@]})
  elif [ ${jobName} == 'Dockerfile-js' ]; then
    JOB_EXTENSIONS=(${JS_EXTENSIONS[@]})
  elif [ ${jobName} == 'Dockerfile-grype' ]; then
    JOB_EXTENSIONS=(${GRYPE_EXTENSIONS[@]})
  elif [ ${jobName} == 'Dockerfile-cdk' ]; then
    JOB_EXTENSIONS=(${CFN_EXTENSIONS[@]})
  fi

  # echo -e "${GREEN}run_security_check "${jobName}" "${JOB_EXTENSIONS[@]}" &${NC}"

  run_security_check "${jobName}" "${JOB_EXTENSIONS[@]}" &

  JOBS[${i}]=$!
  i=${i}+1
done

#
# Now that the jobs are started, wait for each job to finish, capturing the
# return code from the background process.  The return code is set by the
# "exit ${RETURN_CODE}" at the end of the run_security_check() function.
#
i=0
for pid in ${JOBS[@]}; do
  echo -e "${CYAN}waiting on ${GREEN}${JOB_NAMES[${i}]}${CYAN} to finish ...${NC}"
  WAIT_ERR=0
  j=5 # number of times to re-try a failed wait
  while wait ${pid} || WAIT_ERR=$?; do
    #
    # This check allows for the "wait" to fail for some reason, if so
    # it will return code 127, which we know will not be returned by the
    # run_security_check() sub-process.
    #
    # So, loop on a wait until the wait succeeds for the job we're waiting on.
    #
    if [ ${WAIT_ERR} -ne 127 ]; then
      JOBS_RC[${i}]=${WAIT_ERR}
      break
    else
      j=${j}-1
      if [ ${j} -gt 0 ]; then
        echo -e "${RED}wait had and error, ${j} retries left, re-waiting ...${NC}"
      else
        JOBS_RC[${i}]=${WAIT_ERR}
        echo -e "${RED}wait had and error, ${j} retries left, skipping wait for ${GREEN}${JOB_NAMES[${i}]}${RED} ...${NC}"
        break
      fi
    fi
  done
  if [ ${JOBS_RC[${i}]} -ne 127 ]; then
    echo -e "${GREEN}${JOB_NAMES[${i}]}${CYAN} finished with return code ${JOBS_RC[${i}]}${NC}"
  else
    echo -e "${GREEN}${JOB_NAMES[${i}]}${RED} wait for completion failed${NC}"
  fi
  i=$i+1
done

#
# Now that all the jobs are complete, display a final report of
# the return code status for each job that was run.
#
i=0
echo -e "${CYAN}Jobs return code report:${NC}"
for pid in ${JOBS[@]}; do
  REPORT_COLOR=${GREEN}
  if [ ${JOBS_RC[${i}]} -ne 0 ]; then
    REPORT_COLOR=${RED}
    if [ ${JOBS_RC[${i}]} -gt ${HIGHEST_RC} ]; then
      HIGHEST_RC=${JOBS_RC[${i}]}
    fi
  else
    REPORT_COLOR=${GREEN}
  fi
  printf "${REPORT_COLOR}%32s${CYAN} : %3d${NC}\\n" "${JOB_NAMES[${i}]}" "${JOBS_RC[${i}]}"
  i=$i+1
done

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


RCCOLOR=${GREEN}
if [[ $HIGHEST_RC -gt 0 ]]; then
  RCCOLOR=${RED}
fi
echo -e "${RCCOLOR}Highest return code is $HIGHEST_RC${NC}"

exit $HIGHEST_RC
