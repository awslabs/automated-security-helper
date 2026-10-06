# Fixture: nothing in this file is a secret, and gitleaks must report nothing.
import os

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
# The AWS documentation example key, which gitleaks' default rules allowlist.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
PLACEHOLDER = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
