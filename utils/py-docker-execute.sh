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
debug_echo "[py] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: ${_ASH_SOURCE_DIR} :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"

# Set REPORT_PATH to the report location, then touch it to ensure it exists
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/py_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

# Convert any Jupyter notebook files to python
echo ">>>>>> begin identifyipynb output for Jupyter notebook conversion >>>>>>" >> ${REPORT_PATH}
bash -C ${_ASH_UTILS_LOCATION}/identifyipynb.sh >>${REPORT_PATH} 2>&1
echo >> ${REPORT_PATH}	# ensure that we have a newline separating end-of-section
echo "<<<<<< end identifyipynb output for Jupyter notebook conversion <<<<<<" >> ${REPORT_PATH}

# Run bandit on both the source and output directories
scan_paths=("${_ASH_SOURCE_DIR}" "${_ASH_OUTPUT_DIR}/work")

if [ -f "${_ASH_SOURCE_DIR}/.bandit" ]; then
  BANDIT_ARGS="--ini ${_ASH_SOURCE_DIR}/.bandit"
elif [ -f "${_ASH_SOURCE_DIR}/bandit.yaml" ]; then
  BANDIT_ARGS="-c ${_ASH_SOURCE_DIR}/bandit.yaml"
elif [ -f "${_ASH_SOURCE_DIR}/bandit.toml" ]; then
  BANDIT_ARGS="-c ${_ASH_SOURCE_DIR}/bandit.toml"
else
  BANDIT_ARGS="--exclude=\"*venv/*\" --severity-level=all"
fi

debug_echo "[py] BANDIT_ARGS: '${BANDIT_ARGS}'"
debug_echo "[py] ASH_OUTPUT_FORMAT: '${ASH_OUTPUT_FORMAT:-text}'"
if [[ "${ASH_OUTPUT_FORMAT:-text}" != "text" ]]; then
  debug_echo "[py] Output format is not 'text', setting output format options to JSON to enable easy translation into desired output format"
  BANDIT_ARGS="-f json ${BANDIT_ARGS}"
fi

for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  cd ${scan_path}

  echo ">>>>>> begin bandit result for ${scan_path} >>>>>>" >> ${REPORT_PATH}
  python3 -m bandit ${BANDIT_ARGS} -r $(pwd) >> ${REPORT_PATH} 2>&1
  BRC=$?
  RC=$(bumprc $RC $BRC)
  echo >> ${REPORT_PATH}	# ensure that we have a newline separating end-of-section
  echo "<<<<<< end bandit result for ${scan_path} <<<<<<" >> ${REPORT_PATH}
done

# cd back to the original SOURCE_DIR in case path changed during scan
cd ${_ASH_SOURCE_DIR}

exit $RC
