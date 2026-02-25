#!/bin/sh
#
# $Id: //WIFI_SOC/release/SDK_4_1_0_0/source/user/rt2880_app/scripts/cpubusy.sh#1 $
#
# usage: cpubysu.sh
#

echo ""
echo "!! 'killall cpubusy.sh' to Break !!"
echo ""

file="/tmp/dummy"
cpfile="/tmp/testcopy"
i=0
x=0

while true; do
  i=`expr $i + 1`
  echo "--- $i ---" > ${file}
  j=0
  while [ $j -lt 1000 ]; do
    j=`expr $j + 1`
    echo " cpu dummy echo for the $i, $j times" >> ${file}
    cp /bin/goahead ${cpfile}
  done
  sleep 1
done

