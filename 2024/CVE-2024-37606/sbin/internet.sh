#!/bin/sh
#
# $Id: internet.sh, v1.00 2009-11-05 andy
#
# usage: internet.sh
#

sleep 1

echo "*****************"
echo "*  INTERNET.SH  *"
echo "*****************"

# run config.sh if this shell script have any configuration symbol
#. /sbin/config.sh

lan_if="br0"

# setup username:password
login=`nvram_get 2860 AdminID`
if [ "$login" = "" ]; then
echo "loading default configuration ..."
sleep 3
login=`nvram_get 2860 AdminID`
fi
pass=`nvram_get 2860 AdminPassword`
echo "$login::0:0:Adminstrator:/:/bin/sh" > /etc/passwd
echo "$login:x:0:$login" > /etc/group
chpasswd.sh $login $pass

# ftp server for wireless throughput test
echo "21 stream tcp nowait $login /usr/bin/ftpd ftpd -w" > /etc/inetd.conf
gpio telnetd_ftpd
#inetd &

# audio
model=`gpio model`
if [ "$model" == "DCS-5000L" ]; then
pcmcmd -s -q 11025 &
else
pcmcmd -s -q 8000 -x 15 &
fi

# video
uvc_stream -b &
# sleep 2 sec. in order to uvc_stream can get correct configuration data after factory reset
sleep 2

# Set RT5350 to dump switch mode (restore to no VLAN partition)
#switch reg w 14 5555
#switch reg w 40 1001
#switch reg w 44 1001
#switch reg w 48 1001
#switch reg w 4c 1
#switch reg w 50 2001
#switch reg w 70 ffffffff
#switch reg w 98 7f7f
#switch reg w e4 7f

# lo interface up -- mydlink need it
ifconfig lo up

# setup bridge, lan and wlan interface, and fast forwarding time (setfd, setmaxage)
ifconfig eth2 0.0.0.0
ifconfig ra0 0.0.0.0

brctl addbr br0
brctl addif br0 ra0
brctl addif br0 eth2

brctl setfd br0 1
brctl setmaxage br0 1 

# setup wlan enable/disable
wlanonoff=`nvram_get 2860 WirelessDisable`
if [ "$wlanonoff" = "0" ]; then
gpio wlan 0
fi
if [ "$wlanonoff" = "1" ]; then
ifconfig ra0 down
gpio wlan 1
fi

# setup lan
lan.sh

# lltd
lld2d $lan_if

# ping (send arp)
gpio ping &
swing

# Set RT5350 to dump switch mode (restore to no VLAN partition)
switch reg w 14 5555
switch reg w 40 1001
switch reg w 44 1001
switch reg w 48 1001
switch reg w 4c 1
switch reg w 50 2001
switch reg w 70 ffffffff
switch reg w 98 7f7f
switch reg w e4 7f

echo "************************"
echo "*  END OF INTERNET.SH  *"
echo "************************"


