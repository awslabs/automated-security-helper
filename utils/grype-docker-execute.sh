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


grype dir:. > grype_report_result.txt 2>&1
SRC=$?
RC=$(bumprc $RC $SRC)

syft . >> grype_report_result.txt 2>&1
SRC=$?
RC=$(bumprc $RC $SRC)

exit $RC
