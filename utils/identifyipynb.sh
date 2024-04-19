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
debug_echo "[ipynb] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: ${_ASH_SOURCE_DIR} :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"

# nosemgrep
IFS=$'\n' # Support directories with spaces, make the loop iterate over newline instead of space
# Find Jupyter files and convert them to python file for safety and bandit scans.
echo "Looking for Jupyter notebook files"

for file in $(find . -iname "*.ipynb" -not -path "*/cdk.out/*" -not -path "*/node_modules*");
do
    echo "Found $file"
    filename="$(basename -- $file)"
    jupyter nbconvert --log-level WARN --to script "${_ASH_SOURCE_DIR}/$file" --output "${_ASH_OUTPUT_DIR}/work/$filename-converted"
    JRC=$?
    RC=$(bumprc $RC $JRC)

done
echo "$extenstions_found"
unset IFS

# cd back to the original SOURCE_DIR in case path changed during scan
cd ${_ASH_SOURCE_DIR}

exit $RC
