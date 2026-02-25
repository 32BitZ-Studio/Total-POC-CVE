#!/bin/sh
#
# $Id: pppoe.sh, v1.00 2009-11-11 andy
#
# usage: pppoe.sh <ip> <subnet> <gw> <dns1> <dns2>
#

echo "**** pppoe.sh ***"

# ip address and subnet mask
gpio pppoe 0.0.0.0 0.0.0.0
gpio pppoe $1 $2

# default gateway
if [ $3 != "0.0.0.0" ]; then
    gpio gw 0.0.0.0
    gpio gw $3
    route del default dev br0
else
    ip=`nvram_get 2860 IPAddress`
    gw=`nvram_get 2860 DefaultGateway`
    route del default
    gpio gw 0.0.0.0
    if [ "$gw" != "" ]; then
        route add default gw $gw
        gpio gw $gw
    else
        route add default gw $ip
    fi
fi

# dns
RESOLV_CONF="/etc/resolv.conf"
echo -n > $RESOLV_CONF
if [ $4 != "0.0.0.0" -a $5 != "0.0.0.0" ]; then
    echo nameserver $4 >> $RESOLV_CONF
    gpio dns1 0.0.0.0
    gpio dns1 $4
    echo nameserver $5 >> $RESOLV_CONF
    gpio dns2 0.0.0.0
    gpio dns2 $5
elif [ $4 != "0.0.0.0" -a $5 = "0.0.0.0" ]; then
    echo nameserver $4 >> $RESOLV_CONF
    gpio dns1 0.0.0.0
    gpio dns1 $4
    pd=`nvram_get 2860 DNSIPAddress1`
    gpio dns2 0.0.0.0
    if [ "$pd" != "" ]; then
        echo nameserver $pd >> $RESOLV_CONF
        gpio dns2 $pd
    fi
elif [ $4 = "0.0.0.0" -a $5 = "0.0.0.0" ]; then
    pd=`nvram_get 2860 DNSIPAddress1`
    sd=`nvram_get 2860 DNSIPAddress2`
    gpio dns1 0.0.0.0
    gpio dns2 0.0.0.0
    if [ "$pd" != "" ]; then
        echo nameserver $pd >> $RESOLV_CONF
        gpio dns1 $pd
    fi
    if [ "$sd" != "" ]; then
        echo nameserver $sd >> $RESOLV_CONF
        gpio dns2 $sd
    fi
fi

ddns.sh
ntp.sh

