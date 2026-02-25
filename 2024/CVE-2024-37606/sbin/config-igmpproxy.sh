#!/bin/sh
#
# $Id: //WIFI_SOC/release/SDK_4_1_0_0/source/user/rt2880_app/scripts/config-igmpproxy.sh#1 $
#
# usage: config-igmpproxy.sh <wan_if_name> <lan_if_name>
#

. /sbin/global.sh

igmpproxy.sh $wan_ppp_if $lan_if
killall -q igmpproxy
igmpproxy

