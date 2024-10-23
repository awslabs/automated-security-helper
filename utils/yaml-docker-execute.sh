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
debug_echo "[yaml] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: ${_ASH_SOURCE_DIR} :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"

# Set REPORT_PATH to the report location, then touch it to ensure it exists
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/yaml_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

#
# This is used to allow/accept files which have spaces in their names
#
# nosemgrep
IFS=$'\n'

#
# Save the current directory to return to it when done
#
# cd to the source directory as a starting point
#
_CURRENT_DIR=${PWD}
cd ${_ASH_OUTPUT_DIR}

scan_paths=("${_ASH_SOURCE_DIR}" "${_ASH_OUTPUT_DIR}/work")

CHECKOV_ARGS=""
CFNNAG_ARGS="--print-suppression --rule-directory ${_ASH_CFNRULES_LOCATION}"
debug_echo "[yaml] ASH_OUTPUT_FORMAT: '${ASH_OUTPUT_FORMAT:-text}'"
if [[ "${ASH_OUTPUT_FORMAT:-text}" != "text" ]]; then
  debug_echo "[yaml] Output format is not 'text', setting output format options to JSON to enable easy translation into desired output format"
  CHECKOV_ARGS="${CHECKOV_ARGS} --output=json"
  CFNNAG_ARGS="--output-format json ${CFNNAG_ARGS}"
else
  CFNNAG_ARGS="--output-format txt ${CFNNAG_ARGS}"
fi

if [[ $OFFLINE == "YES" ]]; then
  debug_echo "[yaml] Adding --skip-download to prevent connection to Prisma Cloud during offline mode for Checkov scans"
  CHECKOV_ARGS="${CHECKOV_ARGS} --skip-download"
else
  CHECKOV_ARGS="${CHECKOV_ARGS} --download-external-modules True"
fi

for i in "${!scan_paths[@]}";
do
  scan_path=${scan_paths[$i]}
  echo -e "\n>>>>>> Begin yaml scan output for ${scan_path} >>>>>>\n" >> ${REPORT_PATH}
  cd ${scan_path}
  echo "starting to investigate ..." >> ${REPORT_PATH}

  #
  # find only files that appear to contain CloudFormation templates
  #
  cfn_files=($(readlink -f $(grep -lri 'AWSTemplateFormatVersion' . --exclude-dir={cdk.out,utils,.aws-sam,ash_cf2cdk_output} --exclude=ash) 2>/dev/null))

  #
  # For checkov scanning, add in files that are GitLab CI files or container build files
  #
  checkov_files=($(readlink -f $(find . \( -iname ".gitlab-ci.yml" \
                                          -or -iname "*Dockerfile*" \
                                          -or -iname "*.tf" \
                                          -or -iname "*.tf.json" \) \
                                        -not -path "./.git/*" \
                                        -not -path "./.github/*" \
                                        -not -path "./.venv/*" \
                                        -not -path "./.terraform/*" \
                                        -not -path "./.external_modules/*") 2>/dev/null))
  checkov_files=( ${checkov_files[@]} ${cfn_files[@]} )

  if [ "${#checkov_files[@]}" -gt 0 ]; then
    echo "found ${#checkov_files[@]} files to scan.  Starting checkov scans ..." >> ${REPORT_PATH}
    ##HACK Overcomes the String length limitation default of 10000 characters so false negatives cannot occur from large resource policies.
    ##Vendor Issue: https://github.com/bridgecrewio/checkov/issues/5627
    export CHECKOV_RENDER_MAX_LEN=0

    for file in "${checkov_files[@]}"; do
      #echo $cfn_files
      file1=`basename $file`
      echo ">>>>>> begin checkov result for ${file1} >>>>>>" >> ${REPORT_PATH}
      #
      # Run the checkov scan on the file
      #
      checkov_call="checkov ${CHECKOV_ARGS} -f '${file}'"
      debug_echo "[yaml] Running checkov ${checkov_call}"
      eval $checkov_call >> ${REPORT_PATH} 2>&1
      CHRC=$?
      echo "<<<<<< end checkov result for ${file1} <<<<<<" >> ${REPORT_PATH}
      RC=$(bumprc $RC $CHRC)
    done
  else
    echo "found ${#checkov_files[@]} files to scan.  Skipping checkov scans." >> ${REPORT_PATH}
  fi

  if [ "${#cfn_files[@]}" -gt 0 ]; then
    echo "found ${#cfn_files[@]} files to scan.  Starting cfn_nag scans ..." >> ${REPORT_PATH}

    for file in "${cfn_files[@]}"; do
      file1=`basename $file`
      echo ">>>>>> begin cfn_nag_scan result for ${file1} >>>>>>" >> ${REPORT_PATH}
      #
      # Run the cfn_nag scan on the file
      #
      cfn_nag_scan ${CFNNAG_ARGS} --input-path "${file}" >> ${REPORT_PATH} 2>&1
      CNRC=$?
      echo "<<<<<< end cfn_nag_scan result for ${file1} <<<<<<" >> ${REPORT_PATH}
      RC=$(bumprc $RC $CNRC)
    done
  else
    echo "found ${#cfn_files[@]} files to scan.  Skipping cfn_nag scans." >> ${REPORT_PATH}
  fi
  echo -e "\n<<<<<< End yaml scan output for ${scan_path} <<<<<<\n" >> ${REPORT_PATH}
done

unset IFS

# cd back to the original folder in case path changed during scan
cd ${_CURRENT_DIR}

exit $RC
