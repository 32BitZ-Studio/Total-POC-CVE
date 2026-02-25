#!/bin/sh
#
# $Id: chpasswd.sh, v1.01 2015-03-24 steven
#
# usage: chpasswd.sh
#

user=`nvram_get 2860 AdminID`
pass=`nvram_get 2860 AdminPassword`

if [ "$user" == "" ]; then
    echo "chpasswd: no user name"
    exit 1
fi

echo "$user:$pass" > /tmp/tmpchpw
chpasswd < /tmp/tmpchpw
rm -f /tmp/tmpchpw
