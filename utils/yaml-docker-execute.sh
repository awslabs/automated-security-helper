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

#checkov --download-external-modules True -d . > yaml_report_result.txt 2>&1
CHECKOV_CONFIG='ash-checkov-config.yml'
checkov --download-external-modules True -d . --create-config "${CHECKOV_CONFIG}" &> /dev/null
checkov --config-file "${CHECKOV_CONFIG}" > yaml_report_result.txt 2>&1
CHRC=$?
RC=$(bumprc $RC $CHRC)
# remove the file before cfn_nag scanning so that it doesn't confuse the nag scanner
rm "${CHECKOV_CONFIG}"

cfn_nag_scan --rule-directory /cfnrules --input-path . >> yaml_report_result.txt 2>&1
CRC=$?
RC=$(bumprc $RC $CRC)

exit $RC
