#!/bin/bash

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

source ${_ASH_UTILS_LOCATION}/common.sh

#
# Allow the container to run Git commands against a repo in ${_ASH_SOURCE_DIR}
#
git config --global --add safe.directory "${_ASH_SOURCE_DIR}" >/dev/null 2>&1
git config --global --add safe.directory "${_ASH_RUN_DIR}" >/dev/null 2>&1

# cd to the source directory as a starting point
cd "${_ASH_SOURCE_DIR}"
debug_echo "[js] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: ${_ASH_SOURCE_DIR} :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"

# Set REPORT_PATH to the report location, then touch it to ensure it exists
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/js_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

# Run NPM, PNPM, or Yarn audit
scan_paths=("${_ASH_SOURCE_DIR}" "${_ASH_OUTPUT_DIR}/work")

AUDIT_ARGS=""
debug_echo "[js] ASH_OUTPUT_FORMAT: '${ASH_OUTPUT_FORMAT:-text}'"
if [[ "${ASH_OUTPUT_FORMAT:-text}" != "text" ]]; then
  debug_echo "[js] Output format is not 'text', setting output format options to JSON to enable easy translation into desired output format"
  AUDIT_ARGS="--json ${AUDIT_ARGS}"
fi

if [[ $OFFLINE == "YES" ]]; then
  debug_echo "[js] JavaScript package auditing is not available in offline mode"
else
  for i in "${!scan_paths[@]}";
  do
    scan_path=${scan_paths[$i]}
    cd ${scan_path}
    for file in $(find . \
      -iname "package-lock.json" -o \
      -iname "pnpm-lock.yaml" -o \
      -iname "yarn.lock");
    do
        path="$(dirname -- $file)"
        cd $path

        audit_command="npm"

        case $file in
          "./package-lock.json")
            audit_command="npm"
            ;;
          "./pnpm-lock.yaml")
            audit_command="pnpm"
            ;;
          "./yarn.lock")
            audit_command="yarn"
            ;;
        esac

        echo -e "\n>>>>>> Begin ${audit_command} audit output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}

        eval "${audit_command} audit ${AUDIT_ARGS} >> ${REPORT_PATH} 2>&1"

        NRC=$?
        RC=$(bumprc $RC $NRC)

        cd ${scan_path}

        echo -e "\n<<<<<< End ${audit_command} audit output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
    done
  done
fi
# cd back to the original SOURCE_DIR in case path changed during scan
cd ${_ASH_SOURCE_DIR}

exit $RC
