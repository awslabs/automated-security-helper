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

#
# Allow the container to run Git commands against a repo in ${_ASH_SOURCE_DIR}
#
git config --global --add safe.directory ${_ASH_SOURCE_DIR} >/dev/null 2>&1
git config --global --add safe.directory ${_ASH_RUN_DIR} >/dev/null 2>&1

# cd to the source directory as a starting point
cd ${_ASH_SOURCE_DIR}
# Check if the source directory is a git repository and clone it to the run directory
if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" == "true" ]]; then
  if [[ "$_ASH_EXEC_MODE" != "local" ]]; then
    git clone ${_ASH_SOURCE_DIR} ${_ASH_RUN_DIR} >/dev/null 2>&1
  fi
  _ASH_SOURCE_DIR=${_ASH_RUN_DIR}
  cd ${_ASH_RUN_DIR}
fi;

# Set REPORT_PATH to the report location, then touch it to ensure it exists
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/grype_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

scan_paths=("${_ASH_SOURCE_DIR}" "${_ASH_OUTPUT_DIR}/work")

#
# Run Grype
#
for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  cd ${scan_path}
  echo -e "\n>>>>>> Begin Grype output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}

  grype -f medium dir:${scan_path} --exclude="**/*-converted.py" --exclude="**/*_report_result.txt" >> ${REPORT_PATH} 2>&1
  SRC=$?
  RC=$(bumprc $RC $SRC)

  echo -e "\n<<<<<< End Grype output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
done

#
# Run Syft
#
for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  cd ${scan_path}
  echo -e "\n>>>>>> Begin Syft output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}

  syft ${scan_path} --exclude="**/*-converted.py" --exclude="**/*_report_result.txt" >> ${REPORT_PATH} 2>&1
  SRC=$?
  RC=$(bumprc $RC $SRC)

  echo -e "\n<<<<<< End Syft output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
done

#
# Run Semgrep
#
for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  cd ${scan_path}
  echo -e "\n>>>>>> Begin Semgrep output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}

  semgrep --legacy --error --config=auto $scan_path --exclude="*-converted.py,*_report_result.txt" >> ${REPORT_PATH} 2>&1
  SRC=$?
  RC=$(bumprc $RC $SRC)

  echo -e "\n<<<<<< End Semgrep output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
done

# cd back to the original SOURCE_DIR in case path changed during scan
cd ${_ASH_SOURCE_DIR}

exit $RC
