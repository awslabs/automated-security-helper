#!/bin/bash

debug_echo() {
  [[ "${ASH_DEBUG:-"NO"}" != "NO" ]] && echo "DEBUG: ${1}"
}

abs() { # compute the absolute value of the input parameter
  input=$1
  if [[ $input -lt 0 ]]; then
    input=$((-input))
  fi
  echo $input
}

bumprc() { # return the higher absolute value of the inputs
  output=$1
  if [[ $2 -ne 0 ]]; then
    lrc=$(abs $2)

    if [[ $lrc -gt $1 ]]; then
      output=$lrc
    fi
  fi
  echo $output
}

RC=0

#
# Resolve ASH paths from env vars if they exist, otherwise use defaults
#
_ASH_SOURCE_DIR=${_ASH_SOURCE_DIR:-/src}
_ASH_OUTPUT_DIR=${_ASH_OUTPUT_DIR:-/out}
_ASH_UTILS_LOCATION=${_ASH_UTILS_LOCATION:-/utils}
_ASH_CFNRULES_LOCATION=${_ASH_CFNRULES_LOCATION:-/cfnrules}
_ASH_RUN_DIR=${_ASH_RUN_DIR:-/run/scan/src}

#
# Allow the container to run Git commands against a repo in ${_ASH_SOURCE_DIR}
#
git config --global --add safe.directory ${_ASH_SOURCE_DIR} >/dev/null 2>&1
git config --global --add safe.directory ${_ASH_RUN_DIR} >/dev/null 2>&1

# cd to the source directory as a starting point
cd ${_ASH_SOURCE_DIR}
debug_echo "[js] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: ${_ASH_SOURCE_DIR} :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"
# # Check if the source directory is a git repository and clone it to the run directory
# if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" == "true" ]]; then
#   git clone --depth=1 --single-branch ${_ASH_SOURCE_DIR} ${_ASH_RUN_DIR} >/dev/null 2>&1
#   _ASH_SOURCE_DIR=${_ASH_RUN_DIR}
#   cd ${_ASH_RUN_DIR}
# fi;

# Set REPORT_PATH to the report location, then touch it to ensure it exists
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/js_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

# Run NPM audit
scan_paths=("${_ASH_SOURCE_DIR}" "${_ASH_OUTPUT_DIR}/work")
for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  echo -e "\n>>>>>> Begin npm audit output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}
  cd ${scan_path}
  for file in $(find . -iname "package-lock.json");
  do
      path="$(dirname -- $file)"
      cd $path

      npm audit >> ${REPORT_PATH} 2>&1
      NRC=$?
      RC=$(bumprc $RC $NRC)

      cd ${scan_path}
  done
  echo -e "\n<<<<<< End npm audit output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
done

# cd back to the original SOURCE_DIR in case path changed during scan
cd ${_ASH_SOURCE_DIR}

exit $RC
