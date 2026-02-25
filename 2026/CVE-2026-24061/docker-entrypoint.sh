#!/bin/bash
set -euo pipefail

/etc/init.d/inetutils-inetd start

echo "You are user1. Try telnet as root with: USER='-f root' telnet -a localhost"

# drop privileges for the rest of the session
exec su -s /bin/bash user1

