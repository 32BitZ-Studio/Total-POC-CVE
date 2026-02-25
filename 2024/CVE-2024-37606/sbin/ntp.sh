#!/bin/sh
#
# $Id: ntp.sh, v1.00 2009-11-09 andy
#
# usage: ntp.sh
#

killall -q ntpclient

# check manual mode or NTP mode
mode=`nvram_get 2860 DateTimeMode`
if [ "$mode" = "1" ]; then
exit 0
fi

srv=`nvram_get 2860 TimeServerIPAddress`
tz=`nvram_get 2860 TimeZone`

if [ "$srv" = "" ]; then
exit 0
fi

# 10 minutes = 600 seconds
# sync=600
# change to 24 hour = 24*60*60 = 86400 seconds
sync=86400

if [ "$tz" = "" ]; then
tz="UCT_000"
fi

echo $tz > /etc/tmpTZ
sed -e 's#.*_\(-*\)0*\(.*\)#GMT-\1\2#' /etc/tmpTZ > /etc/tmpTZ2
sed -e 's#\(.*\)--\(.*\)#\1\2#' /etc/tmpTZ2 > /etc/TZ
rm -rf /etc/tmpTZ
rm -rf /etc/tmpTZ2
ntpclient -s -c 0 -h $srv -i $sync &

