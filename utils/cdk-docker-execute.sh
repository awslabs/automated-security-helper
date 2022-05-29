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

touch /app/cdk_report_result.txt
cfn_files=$(readlink -f $(grep -lri 'AWSTemplateFormatVersion' . --exclude-dir={cdk.out,utils} --exclude=ash))
#echo $cfn_files
cd /utils/cfn-to-cdk/
/usr/bin/python3 cfn_to_cdk/template_generator.py $cfn_files
/usr/bin/python3 -m pip install -U -r requirements.txt > /dev/null
/usr/bin/python3 /utils/cdk-addon-py.py

cdk synth 2>> /app/cdk_report_result.txt
CRC=$?
RC=$(bumprc $RC $CRC)

cd /app

# for file in $(find . -iname "cdk.json -not -path "./cdk.out/*"");
# do
#     path="$(dirname -- $file)"
#     cd $path
#     /usr/bin/python3 -m pip install -U -r requirements.txt
#     /usr/bin/python3 /utils/cdk-addon-py.py
#     cdk synth 2>> /app/cdk_report_result.txt
#     cd /app
# done

unset IFS

exit $RC
