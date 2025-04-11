from detect_secrets import SecretsCollection
import detect_secrets
from detect_secrets.settings import default_settings
from argparse import ArgumentParser
import os
import json

import detect_secrets.settings

# Run detect-secrets on each file to see if they contain secrets. Uses the default settings
def scan_secrets(
        path: str,
        baseline: str,
        debug: bool = False
):
    secrets = SecretsCollection()
    for item in os.walk(path):
        for file in item[2]:
            with default_settings():

                secrets.scan_files(os.path.join(item[0], file))
    # Prints out scan results. Discovered secret values are hashed to avoid exposing them
    print(json.dumps(secrets.json(), indent=2))

# Create a CLI interface so this script can be called from a bash script
if __name__ == "__main__":
    parser = ArgumentParser(description="A tool to scan for secrets using the detect-secrets python module.")
    parser.add_argument("--source", help="path to scan", default=os.getcwd(), type=str)
    parser.add_argument("--baseline", help="path to baseline file", default=None, type=str)
    args = parser.parse_args()

    scan_secrets(path=args.source)