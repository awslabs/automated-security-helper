"""Help text that two command modules print, kept where neither imports the other.

``cli/main.py`` names the container build lazily, by module path, and needs its help
when it is imported to build the command table. ``cli/container.py`` is the module of
that command and prints the same help. Both read it here, so the command module does
not import the root CLI module to get a string: ``import
automated_security_helper.cli.container`` does not run ``cli/main.py``, and the root
module never imports the command modules it names.

This module imports nothing, so it is safe to import from either side.
"""

#: The container build's help, shared by ``ash container build`` and its deprecated
#: spelling ``ash build-image``, which puts its deprecation sentence in front of it.
BUILD_HELP = """Builds the ASH container image, then scans the current directory with it unless --no-run is given.

It takes only the options below. To scan with scan options, run `ash scan fs --mode container`, which builds the image the same way and accepts every scan option.
"""
