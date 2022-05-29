#!/bin/bash

#
# There is no need to run the --install.  Furthermore if --install is
# run then any existing commit-msg, pre-commit, and prepare-commit-msg
# hooks which are already set up for the repo will be overwritten by
# the git secrets hooks.
#
# git secrets --install -f >/dev/null 2>&1 && \

git secrets --register-aws >/dev/null 2>&1 && \
git secrets --scan > git_report_result.txt 2>&1
RC=$?

exit $RC
