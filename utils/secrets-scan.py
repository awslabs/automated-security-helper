from detect_secrets import SecretsCollection, settings
from argparse import ArgumentParser
import os
import json

# Run detect-secrets on each file to see if they contain secrets
def scan_secrets(
        path: str,
        baseline: str = None,
        debug: bool = False
):
    secrets = SecretsCollection()
    settings_context = settings.default_settings()
    # Use settings from a baseline if it is provided, otherwise the default settings will be used
    if baseline:
        baseline_file = os.path.abspath(baseline)
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
            settings_context = settings.transient_settings(config=baseline)
            f.close()
    with settings_context:
        for item in os.walk(path):
            for file in item[2]:
                secrets.scan_files(os.path.join(item[0], file))
    # Prints out scan results. Discovered secret values are hashed to avoid exposing them
    print(json.dumps(secrets.json(), indent=2))

# Create a CLI interface so this script can be called from a bash script
if __name__ == "__main__":
    parser = ArgumentParser(description="A tool to scan for secrets using the detect-secrets python module.")
    parser.add_argument("--source", help="path to scan", default=os.getcwd(), type=str)
    parser.add_argument("--baseline", help="path to baseline file", default=None, type=str)
    args = parser.parse_args()

    scan_secrets(path=args.source, baseline=args.baseline)
