"""The name of the console script ASH installs as its command.

v4 installs ``ashx`` as the canonical command; ``ash`` and ``ashv3`` stay as
deprecated aliases (cli/deprecations.py holds that table). Everything that names
the command in a message or a command line reads it from here, so a rename is
one edit.

The name lives in ``utils`` rather than in ``cli`` because code below the CLI
names the command too: the container runner (interactions/run_ash_container.py)
starts it inside the image, the cdk-nag scanner records it as its SARIF
invocation's command line, and the uv tool runner names it in the hint a
sandboxed scan gives when a tool is missing. The layer order that
tests/unit/test_layer_dag_boundaries.py holds forbids each of those an import of
``cli``, and a plugin may import ``utils``. cli/deprecations.py imports the name
from here, so code that reads it from there keeps working.
"""

#: The console script v4 installs as the canonical command.
CANONICAL_CLI_NAME = "ashx"
