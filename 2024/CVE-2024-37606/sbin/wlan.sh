#!/bin/sh
#
# $Id: wlan.sh, v1.00 2009-11-11 andy
#
# usage: wlan.sh 
#

echo "**** wlan.sh ***"

lan_link=`gpio lanlink`
if [ "$lan_link" = "1" ]; then
exit 0
fi

ifconfig ra0 down

wlan_disable=`nvram_get 2860 WirelessDisable`
if [ "$wlan_disable" = "0" ]; then
gpio wlan 0
ifconfig ra0 up
fi

if [ "$wlan_disable" = "1" ]; then
gpio wlan 1
fi

# mydlink
#/mydlink/opt.local stop
#/mydlink/opt.local start
gpio mydlink

gpio ping &