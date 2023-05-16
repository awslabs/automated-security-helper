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
# This is used to allow/accept files which have spaces in their names
#
IFS=$'\n'

cd /app

#
# Create a directory to hold all the cdk_nag results from ASH
#
DIRECTORY="ash_cf2cdk_output"
# Check if this directory already exist from previous ASH run
if [ -d "$DIRECTORY" ]; then
  # Delete this directory and its files and recreate it.
  rm -rf $DIRECTORY
fi
mkdir $DIRECTORY

RC=0

rm /app/cdk_report_result.txt 2>/dev/null
touch /app/cdk_report_result.txt

#
# Uncomment the diagnostic output below to get details about
# the  environment and node versions
#

# echo "Environment:" >>/app/cdk_report_result.txt
# echo "Node information:" >>/app/cdk_report_result.txt
# node --version >>/app/cdk_report_result.txt
# echo "----------------------" >>/app/cdk_report_result.txt
# echo "Installed NPM packages:" >>/app/cdk_report_result.txt
# npm list -g >>/app/cdk_report_result.txt
# echo "----------------------" >>/app/cdk_report_result.txt
# echo "CDK information:" >>/app/cdk_report_result.txt
# cdk --version >>/app/cdk_report_result.txt
# echo "----------------------" >>/app/cdk_report_result.txt

echo -e "\nstarting to investigate ..." >>/app/cdk_report_result.txt

cfn_files=($(readlink -f $(grep -lri 'AWSTemplateFormatVersion' . --exclude-dir={cdk.out,utils,.aws-sam,ash_cf2cdk_output} --exclude=ash) 2>/dev/null))

cd /utils/cfn-to-cdk/

if [ "${#cfn_files[@]}" -gt 0 ]; then
  echo "found ${#cfn_files[@]} files to scan.  Starting scans ..." >>/app/cdk_report_result.txt

  for file in ${cfn_files[@]}; do
    #echo $cfn_files
    file1=`basename $file`
    echo ">>>>>> begin cdk-nag result for ${file1} >>>>>>" >> /app/cdk_report_result.txt
    #
    # Generate the CDK application inserting the CloudFormation template
    #
    /usr/bin/python3 cfn_to_cdk/template_generator.py $file
    #
    # Use CDK to synthesize the CDK application,
    # running CDK-NAG on the inserted CloudFormation template
    #
    cdk synth --quiet 2>> /app/cdk_report_result.txt
    CRC=$?
    echo "<<<<<< end cdk-nag result for ${file1} <<<<<<" >> /app/cdk_report_result.txt
    mkdir -p /app/$DIRECTORY/${file1}_cdk_nag_results
    mv cdk.out/cfn-to-cdk.template.json /app/$DIRECTORY/${file1}_cdk_nag_results/
    mv cdk.out/AwsSolutions-*-NagReport.csv /app/$DIRECTORY/${file1}_cdk_nag_results/
    RC=$(bumprc $RC $CRC)
  done
else 
  echo "found ${#cfn_files[@]} files to scan.  Skipping scans." >>/app/cdk_report_result.txt
fi

cd /app

unset IFS

exit $RC
