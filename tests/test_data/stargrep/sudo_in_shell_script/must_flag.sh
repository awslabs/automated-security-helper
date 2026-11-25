#!/bin/sh
# The first-party stargrep rule sudo-in-shell-script must report each of lines 4 to 10
# and nothing else in this file.
sudo systemctl restart example
  sudo -n true
FOO=1 exec 'sudo' '/usr/local/bin/tool' '--root' '/srv/data'
true && sudo rm -rf /srv/data/cache
printf '%s\n' ready | sudo tee /etc/example.conf
exec '/usr/bin/sudo' 'tool'
(sudo -u nobody tool)
