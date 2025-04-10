from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings
from argparse import ArgumentParser
import os
import json

def scan_secrets(
        path, 
        debug: bool = False
):
    secrets = SecretsCollection()
    for item in os.walk(path):
        for file in item[2]:
            with default_settings():
                secrets.scan_files(os.path.join(item[0], file))

    print(json.dumps(secrets.json(), indent=2))

if __name__ == "__main__":
    parser = ArgumentParser(description="A tool to scan for secrets using the detect-secrets python module.")
    parser.add_argument("--source", help="path to scan", default=os.getcwd(), type=str)
    args = parser.parse_args()

    scan_secrets(path=args.source)