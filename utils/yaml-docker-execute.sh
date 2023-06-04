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

rm /app/yaml_report_result.txt 2>/dev/null
touch /app/yaml_report_result.txt

echo "starting to investigate ..." >>/app/yaml_report_result.txt

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
  echo "found ${#checkov_files[@]} files to scan.  Starting checkov scans ..." >>/app/yaml_report_result.txt

  for file in ${checkov_files[@]}; do
    #echo $cfn_files
    file1=`basename $file`
    echo ">>>>>> begin checkov result for ${file1} >>>>>>" >> /app/yaml_report_result.txt
    #
    # Run the checkov scan on the file
    #
    checkov --download-external-modules True -f "${file}" >> /app/yaml_report_result.txt 2>&1
    CHRC=$?
    echo "<<<<<< end checkov result for ${file1} <<<<<<" >> /app/yaml_report_result.txt
    RC=$(bumprc $RC $CHRC)
  done
else 
  echo "found ${#checkov_files[@]} files to scan.  Skipping checkov scans." >>/app/yaml_report_result.txt
fi

if [ "${#cfn_files[@]}" -gt 0 ]; then
  echo "found ${#cfn_files[@]} files to scan.  Starting cfn_nag scans ..." >>/app/yaml_report_result.txt

  for file in ${cfn_files[@]}; do
    file1=`basename $file`
    echo ">>>>>> begin cfn_nag_scan result for ${file1} >>>>>>" >> /app/yaml_report_result.txt
    #
    # Run the cfn_nag scan on the file
    #
    cfn_nag_scan --output-format txt --print-suppression --rule-directory /cfnrules --input-path "${file}" >> /app/yaml_report_result.txt 2>&1
    CNRC=$?
    echo "<<<<<< end cfn_nag_scan result for ${file1} <<<<<<" >> /app/yaml_report_result.txt
    RC=$(bumprc $RC $CNRC)
  done
else 
  echo "found ${#cfn_files[@]} files to scan.  Skipping cfn_nag scans." >>/app/yaml_report_result.txt
fi

exit $RC
