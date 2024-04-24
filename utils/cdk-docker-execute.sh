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
cd ${_ASH_SOURCE_DIR}
debug_echo "[cdk] pwd: '$(pwd)' :: _ASH_SOURCE_DIR: "${_ASH_SOURCE_DIR}" :: _ASH_RUN_DIR: ${_ASH_RUN_DIR}"

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
if [[ -n "${_ASH_OUTPUT_DIR}" && -d "${_ASH_OUTPUT_DIR}/$DIRECTORY" ]]; then
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

debug_echo "Starting all scanners within the CDK scanner tool set"
echo -e "\nstarting to investigate ..." >> ${REPORT_PATH}

# cfn_files=($(readlink -f $(grep -lri 'AWSTemplateFormatVersion' "${_ASH_SOURCE_DIR}" --exclude-dir={cdk.out,utils,.aws-sam,ash_cf2cdk_output} --exclude=ash) 2>/dev/null))
cfn_files=($(rg AWSTemplateFormatVersion --files-with-matches --type yaml --type json "${_ASH_SOURCE_DIR}" 2>/dev/null))
debug_echo "Found ${#cfn_files[@]} CloudFormation files to scan: ${cfn_files}"

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
  debug_echo "Found CloudFormation files to scan, starting scan"
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
    debug_echo "Importing CloudFormation template file ${file} to apply CDK Nag rules against it"
    npx cdk synth --context fileName="${file}" --quiet 2>> ${REPORT_PATH}
    CRC=$?

    RC=$(bumprc $RC $CRC)

    #
    # Check to see if there is output to copy, if so, create a folder and copy the files
    #
    fileName="*.template.json"
    # echo "checking for ${fileName}" >> ${REPORT_PATH}
    # find -type f -name ${fileName} >> ${REPORT_PATH} 2>&1
    # ls ${fileName} >> ${REPORT_PATH} 2>&1
    fileExists=$(find ${CDK_WORK_DIR}/cdk.out -type f -name ${fileName} | wc -l)
    # echo "fileExists = ${fileExists}" >> ${REPORT_PATH}
    reportsName="AwsSolutions-*-NagReport.csv"
    # echo "checking for ${reportsName}" >> ${REPORT_PATH}
    # find -type f -name ${reportsName} >> ${REPORT_PATH} 2>&1
    # ls ${reportsName} >> ${REPORT_PATH} 2>&1
    reportsExist=$(find ${CDK_WORK_DIR}/cdk.out -type f -name ${reportsName} | wc -l)
    # echo "reportsExist = ${reportsExist}" >> ${REPORT_PATH}
    if [ "${fileExists}" -gt 0 -o "${reportsExist}" -gt 0 ]; then
      mkdir -p ${_ASH_OUTPUT_DIR}/${DIRECTORY}/${cfn_filename}_cdk_nag_results

      echo "Writing CDK-NAG reports for ${cfn_filename}" >> ${REPORT_PATH}
      #
      # Copy and then remove these files to avoid permission setting errors when running in a single container
      #
      cp ${CDK_WORK_DIR}/cdk.out/*.template.json ${_ASH_OUTPUT_DIR}/${DIRECTORY}/${cfn_filename}_cdk_nag_results/ >/dev/null 2>&1
      rm ${CDK_WORK_DIR}/cdk.out/*.template.json >/dev/null 2>&1
      cp ${CDK_WORK_DIR}/cdk.out/AwsSolutions-*-NagReport.csv ${_ASH_OUTPUT_DIR}/${DIRECTORY}/${cfn_filename}_cdk_nag_results/ >/dev/null 2>&1
      rm ${CDK_WORK_DIR}/cdk.out/AwsSolutions-*-NagReport.csv >/dev/null 2>&1
    else
      echo "No CDK-NAG reports generated for ${cfn_filename}" >> ${REPORT_PATH}
    fi

    echo "<<<<<< end cdk-nag result for ${cfn_filename} <<<<<<" >> ${REPORT_PATH}
  done
else
  echo "found ${#cfn_files[@]} files to scan.  Skipping scans." >> ${REPORT_PATH}
fi

unset IFS

#
# Clean up the CDK application temporary working folder
#
if [[ -n "${CDK_WORK_DIR}" && -d "${CDK_WORK_DIR}" ]]; then
  rm -rf ${CDK_WORK_DIR}
fi

# cd back to the original folder in case path changed during scan
cd ${_CURRENT_DIR}

debug_echo "Finished all scanners within the CDK scanner tool set"
exit $RC
