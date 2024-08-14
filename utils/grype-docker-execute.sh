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

if [[ "${OFFLINE}" == "YES" && ( -z "${SEMGREP_RULES_CACHE_DIR}" || -z "${GRYPE_DB_CACHE_DIR}" ) ]]; then
  echo "Invalid cache state for Semgrep or Grype, please rebuild with --offline."
  exit 100
fi

source ${_ASH_UTILS_LOCATION}/common.sh


# Empty Semgrep data dir case
if [[ $OFFLINE == "YES" && -z "$(ls -A "$SEMGREP_RULES_CACHE_DIR")" ]]; then
  debug_echo "[offline] Semgrep rulesets not found but offline mode enabled, erroring"
  exit 1
# Empty Grype data dir case
elif [[ $OFFLINE == "YES" && -z "$(ls -A "$GRYPE_DB_CACHE_DIR")" ]]; then
  debug_echo "[offline] Grype rulesets not found but offline mode enabled, erroring"
  exit 1
# Valid offline config case
elif [[ $OFFLINE == "YES" ]]; then
  export SEMGREP_RULES="$(echo "$SEMGREP_RULES_CACHE_DIR"/*)"
  SEMGREP_ARGS="--metrics=off"
  debug_echo "[offline] Semgrep rulesets are ${SEMGREP_RULES} with metrics off"

  export GRYPE_DB_VALIDATE_AGE=false
  export GRYPE_DB_AUTO_UPDATE=false
  export GRYPE_CHECK_FOR_APP_UPDATE=false
  debug_echo "[offline] Grype DB cache dir is ${GRYPE_DB_CACHE_DIR} and validation/auto update is off"
# Online (default) mode
else
  SEMGREP_ARGS="--config=auto"
fi


#
# Allow the container to run Git commands against a repo in ${_ASH_SOURCE_DIR}
#
git config --global --add safe.directory "${_ASH_SOURCE_DIR}" >/dev/null 2>&1
git config --global --add safe.directory "${_ASH_RUN_DIR}" >/dev/null 2>&1

# cd to the source directory as a starting point
cd "${_ASH_SOURCE_DIR}"
debug_echo "[grype] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: ${_ASH_SOURCE_DIR} :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"

# Set REPORT_PATH to the report location, then touch it to ensure it exists
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/grype_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

scan_paths=("${_ASH_SOURCE_DIR}" "${_ASH_OUTPUT_DIR}/work")

GRYPE_ARGS="-f medium --exclude=**/*-converted.py --exclude=**/*_report_result.txt"
SYFT_ARGS="--exclude=**/*-converted.py --exclude=**/*_report_result.txt"
SEMGREP_ARGS="${SEMGREP_ARGS} --legacy --error --exclude=\"*-converted.py,*_report_result.txt\""
debug_echo "[grype] ASH_OUTPUT_FORMAT: '${ASH_OUTPUT_FORMAT:-text}'"
if [[ "${ASH_OUTPUT_FORMAT:-text}" != "text" ]]; then
  debug_echo "[grype] Output format is not 'text', setting output format options to JSON to enable easy translation into desired output format"
  GRYPE_ARGS="-o json ${GRYPE_ARGS}"
  SYFT_ARGS="-o json ${SYFT_ARGS}"
  SEMGREP_ARGS="--json ${SEMGREP_ARGS}"
fi

#
# Run Grype
#
debug_echo "[grype] Starting all scanners within the Grype scanner tool set"
for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  cd ${scan_path}
  debug_echo "[grype] Starting Grype scan of ${scan_path}"
  # debug_show_tree ${scan_path} ${REPORT_PATH}
  echo -e "\n>>>>>> Begin Grype output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}

  debug_echo "[grype] grype ${GRYPE_ARGS} dir:${scan_path}"
  grype ${GRYPE_ARGS} dir:${scan_path} >> ${REPORT_PATH} 2>&1
  SRC=$?
  RC=$(bumprc $RC $SRC)

  echo -e "\n<<<<<< End Grype output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
  debug_echo "Finished Grype scan of ${scan_path}"
done

#
# Run Syft
#
for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  cd ${scan_path}
  debug_echo "[grype] Starting Syft scan of ${scan_path}"
  # debug_show_tree ${scan_path} ${REPORT_PATH}
  echo -e "\n>>>>>> Begin Syft output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}

  debug_echo "[grype] syft ${SYFT_ARGS} ${scan_path}"
  syft ${SYFT_ARGS} ${scan_path} >> ${REPORT_PATH} 2>&1
  SRC=$?
  RC=$(bumprc $RC $SRC)

  echo -e "\n<<<<<< End Syft output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
  debug_echo "[grype] Finished Syft scan of ${scan_path}"
done

#
# Run Semgrep
#
for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  cd ${scan_path}
  debug_echo "[grype] Starting Semgrep scan of ${scan_path}"
  # debug_show_tree ${scan_path} ${REPORT_PATH}
  echo -e "\n>>>>>> Begin Semgrep output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}

  debug_echo "[grype] semgrep ${SEMGREP_ARGS} $scan_path"
  semgrep ${SEMGREP_ARGS} $scan_path >> ${REPORT_PATH} 2>&1
  SRC=$?
  RC=$(bumprc $RC $SRC)

  echo -e "\n<<<<<< End Semgrep output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
  debug_echo "[grype] Finished Semgrep scan of ${scan_path}"
done

# cd back to the original SOURCE_DIR in case path changed during scan
cd ${_ASH_SOURCE_DIR}

debug_echo "[grype] Finished all scanners within the Grype scanner tool set"
exit $RC
