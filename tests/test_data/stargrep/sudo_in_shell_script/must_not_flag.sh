#!/bin/sh
# sudo is named in this comment, which the rule leaves alone.
    # and in this indented one
pseudo --help
visudo -c
sudoedit /etc/hosts
exec '/opt/sudo-wrapper/tool' '--root' '/srv/data'
echo 'sudoers is a file'
LOG_LEVEL='info' exec '/usr/local/bin/mcp-files' '--root' '/srv/data'
