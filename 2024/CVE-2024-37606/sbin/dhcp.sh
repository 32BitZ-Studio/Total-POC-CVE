#!/bin/sh
#
# $Id: dhcp.sh, v1.00 2009-11-05 andy
#
# usage: dhcp.sh
#

echo "*** begin dhcp.sh ***"

lan_if="br0"
gpio dhcpstate 0
ipmode=`nvram_get 2860 IPAddressMode`

if [ "$ipmode" = "4" ]; then
echo "*** re-start dhcp client ***"
gpio dhcpstate 1
gpio defaultip
gpio gw 0.0.0.0
killall -q udhcpc
cameraname=`nvram_get 2860 CameraName`
udhcpc -i $lan_if -s /sbin/udhcpc.sh -p /var/run/udhcpc.pid -H $cameraname &
else
killall -q udhcpc
fi
