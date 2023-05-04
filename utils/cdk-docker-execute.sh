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

IFS=$'\n'
# Let create a directory to hold all the cdk_nag results from ASH
#we name the directory
cd /app
DIRECTORY="ash_cf2cdk_output"
# Lets check if this directory already exist from previous ASH run
if [ -d "$DIRECTORY" ]; then
  #lets delete this directory and its files and recreate it.
  rm -rf $DIRECTORY
  mkdir $DIRECTORY
else  #lets create this directory again to capture output from this run
  mkdir $DIRECTORY
fi

touch /app/cdk_report_result.txt
cfn_files=$(readlink -f $(grep -lri 'AWSTemplateFormatVersion' . --exclude-dir={cdk.out,utils,.aws-sam} --exclude=ash))


for file in $cfn_files
do
  #echo $cfn_files
  file1=`basename $file`
  echo ">>>>>> begin cdk-nag result for ${file1} >>>>>>" >> /app/cdk_report_result.txt
  cd /utils/cfn-to-cdk/
  /usr/bin/python3 cfn_to_cdk/template_generator.py $file
  /usr/bin/python3 -m pip install -U -r requirements.txt > /dev/null
  /usr/bin/python3 /utils/cdk-addon-py.py
  cdk synth 2>> /app/cdk_report_result.txt
  echo "<<<<<< end cdk-nag result for ${file1} <<<<<<" >> /app/cdk_report_result.txt
  mkdir /app/$DIRECTORY/${file1}_cdk_nag_results
  mv cdk.out/cfn-to-cdk.template.json /app/$DIRECTORY/${file1}_cdk_nag_results/
  mv cdk.out/AwsSolutions-*-NagReport.csv /app/$DIRECTORY/${file1}_cdk_nag_results/
  CRC=$?
  RC=$(bumprc $RC $CRC)
done

cd /app
unset IFS

exit $RC
