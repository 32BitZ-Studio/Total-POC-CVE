#!/bin/sh
#
# $Id: ddns.sh, v1.00 2009-11-12 andy
#
# usage: ddns.sh
#

killall -q inadyn

# check ddns enable or disable
enable=`nvram_get 2860 DDNSEnable`
if [ "$enable" = "0" ]; then
exit 0
fi

srv=`nvram_get 2860 DDNSProvider`
ddns=`nvram_get 2860 DDNSHostName`
u=`nvram_get 2860 DDNSUserName`
pw=`nvram_get 2860 DDNSPassword`
to=`nvram_get 2860 DDNSTimeout`

if [ "$srv" = "" -o "$srv" = "none" ]; then
	exit 0
fi
if [ "$ddns" = "" -o "$u" = "" -o "$pw" = "" ]; then
	exit 0
fi

dyndnssrv="dyndns.org"

if [ "$srv" = "www.dlinkddns.com" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system dyndns@$dyndnssrv &
elif [ "$srv" = "www.DynDNS.org(Custom)" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system custom@$dyndnssrv &
elif  [ "$srv" = "www.DynDNS.org(Free)" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system dyndns@$dyndnssrv &
elif [ "$srv" = "www.DynDNS.org" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system dyndns@$dyndnssrv &
elif  [ "$srv" = "members.dyndns.org" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system dyndns@$dyndnssrv &
elif [ "$srv" = "dyndns.org" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system dyndns@$dyndnssrv &
elif [ "$srv" = "freedns.afraid.org" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system default@$srv &
elif [ "$srv" = "zoneedit.com" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system default@$srv &
elif [ "$srv" = "no-ip.com" ]; then
	inadyn -u $u -p $pw -a $ddns --dyndns_system default@$srv &
else
	inadyn -u $u -p $pw -a $ddns --dyndns_server_name $srv &
	#echo "$0: unknown DDNS provider: $srv"
	#exit 1
fi

