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
# There is no need to run the --install.  Furthermore if --install is
# run then any existing commit-msg, pre-commit, and prepare-commit-msg
# hooks which are already set up for the repo will be overwritten by
# the git secrets hooks.
#
# git secrets --install -f >/dev/null 2>&1 && \

outputFilename=/app/git_report_result.txt

touch "${outputFilename}"

#
# Allow the container to run Git commands against a repo in /app
#
git config --global --add safe.directory /app >/dev/null 2>&1

if [ $(git status >/dev/null 2>&1; echo $?) -ne 0 ]; then
  echo "Not in a git repository - skipping git checks" >>"${outputFilename}"
else

  #
  # Configure the repo to check for AWS secrets
  #
  git secrets --register-aws >>"${outputFilename}" 2>&1

  #
  # List the Git secrets configuration
  #
  echo "git config --local --get-regexp \"^secrets\\..*\$\" output:" >>"${outputFilename}" 2>&1
  git config --local --get-regexp "^secrets\..*$" >>"${outputFilename}" 2>&1

  echo ">>>>>> begin git secrets --scan result >>>>>>" >> "${outputFilename}"
  git secrets --scan >> "${outputFilename}" 2>&1
  GRC=$?
  RC=$(bumprc $RC $GRC)
  echo "<<<<<< end git secrets --scan result <<<<<<" >> "${outputFilename}"

  #
  # TODO: Consider adding in a longer scan of the history as well.  Comment out for now.
  #
  # echo ">>>>>> begin git secrets --scan-history result >>>>>>" >> "${outputFilename}"
  # git secrets --scan-history >> "${outputFilename}" 2>&1
  # GRC=$?
  # RC=$(bumprc $RC $GRC)
  # echo "<<<<<< end git secrets --scan-history result <<<<<<" >> "${outputFilename}

fi

exit $RC
