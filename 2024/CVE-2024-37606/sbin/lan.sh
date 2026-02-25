#!/bin/sh
#
# $Id: lan.sh, v1.00 2009-11-05 andy
#
# usage: lan.sh
#

echo "*** begin lan.sh ***"

lan_if="br0"

gpio dhcpstate 0

# ip address mode
ipmode=`nvram_get 2860 IPAddressMode`

# ip address, subnet mask, default gateway 
# Fixed IP (1) and PPPoE (5) -- Init with Fixed IP
# DHCP (4) -- Init with Default IP
if [ "$ipmode" != "4" ]; then

ip=`nvram_get 2860 IPAddress`
nm=`nvram_get 2860 SubnetMask`
gw=`nvram_get 2860 DefaultGateway`
ifconfig $lan_if $ip netmask $nm
route del default
gpio gw 0.0.0.0
if [ "$gw" == "0.0.0.0" ]; then
gw=""
fi
if [ "$gw" != "" ]; then
route add default gw $gw
gpio gw $gw
else
route add default gw $ip
fi

else

gpio defaultip
gpio gw 0.0.0.0

fi

# dns address
pd=`nvram_get 2860 DNSIPAddress1`
sd=`nvram_get 2860 DNSIPAddress2`
config-dns.sh $pd $sd
gpio dns1 0.0.0.0
gpio dns2 0.0.0.0
gpio dns1 $pd
gpio dns2 $sd

# web server alphapd
#killall -q alphapd
#alphapd &
web.sh

# ddns
ddns.sh

# ntp
ntp.sh

# schedule for mail and ftp client
killall -q schedule
killall -q mail
killall -q ftpputimage
schedule &

# udp configuration and tftp upload
killall -q lanconfig
killall -q tftpupload
lanconfig &
tftpupload &

# mydlinkevent
killall -q mydlinkevent
mydlinkevent &

# mDNSResponder
killall -q mDNSResponder
gpio mDNSResponder

# upnp
#upnp=`nvram_get 2860 UPnPEnable`
#if [ "$upnp" = "1" ]; then
route add -net 239.0.0.0 netmask 255.0.0.0 dev br0
killall -q udev
killall -q ucp
udev &
ucp &
#else
#route del -net 239.0.0.0 netmask 255.0.0.0 dev br0
#killall -q udev
#killall -q ucp
#fi

# mydlink
#/mydlink/opt.local stop
#/mydlink/opt.local start
echo "from lan.sh"
gpio mydlink


# dhcp client mode
if [ "$ipmode" = "4" ]; then
gpio dhcpstate 1
killall -q udhcpc
cameraname=`nvram_get 2860 CameraName`
udhcpc -i $lan_if -s /sbin/udhcpc.sh -p /var/run/udhcpc.pid -H $cameraname &
else
killall -q udhcpc
killall -q zcip
ifconfig br0:0 down
gpio autoip 0.0.0.0
fi

# pppoe mode
if [ "$ipmode" = "5" ]; then
u=`nvram_get 2860 PPPoEUserID`
pw=`nvram_get 2860 PPPoEPassword`
# pppoecd must be kill twice. why?
killall -q pppoecd 
killall -q pppoecd
gpio pppoe_state 16
pppoecd $lan_if -u "$u" -p "$pw" -R -k -I 30 -T 6 -N -1 &
else
killall -q pppoecd 
killall -q pppoecd
gpio pppoe 0.0.0.0 0.0.0.0
fi

echo "*** end lan.sh ***"
