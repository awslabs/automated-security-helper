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

touch grype_report_result.txt
echo -e "\n>>>>>> Begin Grype output >>>>>>\n" >>grype_report_result.txt

grype -f medium dir:. >>grype_report_result.txt 2>&1
SRC=$?
RC=$(bumprc $RC $SRC)

echo -e "\n<<<<<< End Grype output <<<<<<\n" >>grype_report_result.txt

echo -e "\n>>>>>> Begin Syft output >>>>>>\n" >>grype_report_result.txt

syft . >>grype_report_result.txt 2>&1
SRC=$?
RC=$(bumprc $RC $SRC)

echo -e "\n<<<<<< End Syft output <<<<<<\n" >>grype_report_result.txt

echo -e "\n>>>>>> Begin Semgrep output >>>>>>\n" >>grype_report_result.txt

semgrep --error --config=auto . >>grype_report_result.txt 2>&1
CRC=$?
RC=$(bumprc $RC $CRC)

echo -e "\n<<<<<< End Semgrep output <<<<<<\n" >>grype_report_result.txt

exit $RC
