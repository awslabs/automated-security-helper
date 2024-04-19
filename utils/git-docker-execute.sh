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
_ASH_IS_GIT_REPOSITORY=0

source ${_ASH_UTILS_LOCATION}/common.sh

#
# Allow the container to run Git commands against a repo in ${_ASH_SOURCE_DIR}
#
git config --global --add safe.directory "${_ASH_SOURCE_DIR}" >/dev/null 2>&1
git config --global --add safe.directory "${_ASH_RUN_DIR}" >/dev/null 2>&1


# cd to the source directory as a starting point
cd "${_ASH_SOURCE_DIR}"
debug_echo "[git] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: ${_ASH_SOURCE_DIR} :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"
if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" == "true" ]]; then
  _ASH_IS_GIT_REPOSITORY=1
fi

# Set REPORT_PATH to the report location, then touch it to ensure it exists
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/git_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

# Use Tree to obtain a list of files in the source directory
_TREE_FLAGS="-x -h -a --du -I .git"
echo ">>>>>> begin tree result >>>>>>" >> "${REPORT_PATH}"
# if the value of _ASH_IS_GIT_REPOSITORY is 1 then echo a message to the report file
if [ "$_ASH_IS_GIT_REPOSITORY" -eq 1 ]; then
echo "Git repository detected. Ensure your .gitignore configuration excludes all the files that you intend to ignore." >> "${REPORT_PATH}"
fi;
tree ${_TREE_FLAGS} "${_ASH_SOURCE_DIR}" >> "${REPORT_PATH}" 2>&1
echo "<<<<<< end tree ${_TREE_FLAGS} result <<<<<<" >> "${REPORT_PATH}"

#
# There is no need to run the --install.  Furthermore if --install is
# run then any existing commit-msg, pre-commit, and prepare-commit-msg
# hooks which are already set up for the repo will be overwritten by
# the git secrets hooks.
#
# git secrets --install -f >/dev/null 2>&1 && \



if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]; then
  echo "Not in a git repository - skipping git checks" >>"${REPORT_PATH}"
else

  #
  # Configure the repo to check for AWS secrets
  #
  git secrets --register-aws >>"${REPORT_PATH}" 2>&1

  #
  # List the Git secrets configuration
  #
  echo "git config --local --get-regexp \"^secrets\\..*\$\" output:" >>"${REPORT_PATH}" 2>&1
  git config --local --get-regexp "^secrets\..*$" >>"${REPORT_PATH}" 2>&1

  echo ">>>>>> begin git secrets --scan result >>>>>>" >> "${REPORT_PATH}"
  git secrets --scan >> "${REPORT_PATH}" 2>&1
  GRC=$?
  RC=$(bumprc $RC $GRC)
  echo "<<<<<< end git secrets --scan result <<<<<<" >> "${REPORT_PATH}"

  #
  # TODO: Consider adding in a longer scan of the history as well.  Comment out for now.
  #
  # echo ">>>>>> begin git secrets --scan-history result >>>>>>" >> "${REPORT_PATH}"
  # git secrets --scan-history >> "${REPORT_PATH}" 2>&1
  # GRC=$?
  # RC=$(bumprc $RC $GRC)
  # echo "<<<<<< end git secrets --scan-history result <<<<<<" >> "${REPORT_PATH}

fi

# cd back to the original SOURCE_DIR in case path changed during scan
cd ${_ASH_SOURCE_DIR}

exit $RC
