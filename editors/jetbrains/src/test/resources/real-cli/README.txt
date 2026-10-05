Output captured from a real ASH 3.7.0 run over ../fixtures/leak.py plus a four-line
CloudFormation template declaring one AWS::S3::Bucket (not kept: it was there to give cfn-nag
a target). AshScanIntegrationTest's stub CLI replays these files instead of hand-written SARIF,
so the plugin is tested against what ASH actually writes.

Both were run the way the plugin runs ASH: working directory = the project,
  ash scan --source-dir <project> --output-dir <project>/.ash/ash_output \
      --output-formats sarif --no-progress --scanners <list>

exit2/  --scanners detect-secrets, over leak.py alone.
        Exit 2: detect-secrets FAILED with three findings on leak.py line 2.

exit1/  --scanners detect-secrets,cfn-nag, on a PATH with no cfn_nag_scan.
        Exit 1 (ScanIncompleteExit): cfn-nag MISSING, detect-secrets FAILED with the same three
        findings. console-tail.txt is the end of what ASH printed.

The working directory matters. A first capture run from the project's PARENT recorded the URI
as src/leak.py rather than leak.py: ASH writes SARIF URIs relative to its working directory,
not to --source-dir. AshScanRunner sets the working directory to the scanned directory for that
reason.

The absolute project path ASH recorded was replaced with /workspace/project, and the
repository's pretty-format-json hook then reformatted the two .json files (indentation and key
order). No value was changed.
