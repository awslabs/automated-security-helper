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
REPORT_PATH="${_ASH_OUTPUT_DIR}/work/cdk_report_result.txt"
rm ${REPORT_PATH} 2> /dev/null
touch ${REPORT_PATH}

#
# Set CDK_WORK_DIR to a folder in the output directory
#
# Note that the use of a hidden folder (.cdk-nag-scan) keeps this folder
# from being scanned by other scanners running in parallel.
#
CDK_WORK_DIR=$(mktemp -d -t cdk-nag-scan.XXXXX)

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

#
# Create a directory to hold all the cdk_nag results from ASH
#
DIRECTORY="ash_cf2cdk_output"
# Check if this directory already exist from previous ASH run
if [ -d "${_ASH_OUTPUT_DIR}/$DIRECTORY" ]; then
  # Delete this directory and its files and recreate it.
  rm -rf "${_ASH_OUTPUT_DIR}/$DIRECTORY"
fi
mkdir -p "${_ASH_OUTPUT_DIR}/$DIRECTORY" 2> /dev/null

RC=0

#
# Uncomment the diagnostic output below to get details about
# the  environment and node versions
#

# echo "Environment:" >> ${REPORT_PATH}
# echo "Node information:" >> ${REPORT_PATH}
# node --version >> ${REPORT_PATH}
# echo "----------------------" >> ${REPORT_PATH}
# echo "Installed NPM packages:" >> ${REPORT_PATH}
# npm list -g >> ${REPORT_PATH}
# echo "----------------------" >> ${REPORT_PATH}
# echo "CDK information:" >> ${REPORT_PATH}
# cdk --version >> ${REPORT_PATH}
# echo "----------------------" >> ${REPORT_PATH}

echo -e "\nstarting to investigate ..." >> ${REPORT_PATH}

cfn_files=($(readlink -f $(grep -lri 'AWSTemplateFormatVersion' ${_ASH_SOURCE_DIR} --exclude-dir={cdk.out,utils,.aws-sam,ash_cf2cdk_output} --exclude=ash) 2>/dev/null))

#
# Copy the CDK application to the work area and change
# to that folder so that npm install
# installs the required packages in a writable area.
#
cp -R ${_ASH_UTILS_LOCATION}/cdk-nag-scan/* ${CDK_WORK_DIR}
cd ${CDK_WORK_DIR}

# # Install the CDK application's required packages

npm install --silent

#
# Now, for each file, run a cdk synth to subject the file to CDK-NAG scanning
#
if [ "${#cfn_files[@]}" -gt 0 ]; then
  echo "found ${#cfn_files[@]} files to scan.  Starting scans ..." >> ${REPORT_PATH}

  for file in "${cfn_files[@]}"; do

    cfn_filename=`basename $file`
    echo ">>>>>> begin cdk-nag result for ${cfn_filename} >>>>>>" >> ${REPORT_PATH}
    #
    # Generate the CDK application inserting the CloudFormation template
    #
    # /usr/bin/python3 cfn_to_cdk/template_generator.py $file
    #
    # Use CDK to synthesize the CDK application,
    # running CDK-NAG on the inserted CloudFormation template
    #
    npx cdk synth --context fileName="${file}" --quiet 2>> ${REPORT_PATH}
    CRC=$?
    echo "<<<<<< end cdk-nag result for ${cfn_filename} <<<<<<" >> ${REPORT_PATH}
    mkdir -p ${_ASH_OUTPUT_DIR}/${DIRECTORY}/${cfn_filename}_cdk_nag_results

    #
    # Copy and then remove these files to avoid permission setting errors when running in a single container
    #
    cp ${CDK_WORK_DIR}/cdk.out/CdkNagScanStack.template.json ${_ASH_OUTPUT_DIR}/${DIRECTORY}/${cfn_filename}_cdk_nag_results/
    rm ${CDK_WORK_DIR}/cdk.out/CdkNagScanStack.template.json
    cp ${CDK_WORK_DIR}/cdk.out/AwsSolutions-*-NagReport.csv ${_ASH_OUTPUT_DIR}/${DIRECTORY}/${cfn_filename}_cdk_nag_results/
    rm ${CDK_WORK_DIR}/cdk.out/AwsSolutions-*-NagReport.csv

    RC=$(bumprc $RC $CRC)
  done
else
  echo "found ${#cfn_files[@]} files to scan.  Skipping scans." >> ${REPORT_PATH}
fi

unset IFS

#
# Clean up the CDK application temporary working folder
#
if [ -d "${CDK_WORK_DIR}" ]; then
  rm -rf "${CDK_WORK_DIR}"
fi

# cd back to the original folder in case path changed during scan
cd ${_CURRENT_DIR}

exit $RC
