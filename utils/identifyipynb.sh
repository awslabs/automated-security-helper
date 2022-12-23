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

IFS=$'\n' # Support directories with spaces, make the loop iterate over newline instead of space
# Find Jupyter files and convert them to python file for safety and bandit scans.
echo "Looking for Jupyter notebook files"

for file in $(find . -iname "*.ipynb" -not -path "*/cdk.out/*" -not -path "*/node_modules*");
do
    echo "Found $file"
    filename="$(basename -- $file)"
    jupyter nbconvert --log-level WARN --to script "/app/$file" --output $filename-converted
    JRC=$?
    RC=$(bumprc $RC $JRC)

done
echo "$extenstions_found"
unset IFS

exit $RC
