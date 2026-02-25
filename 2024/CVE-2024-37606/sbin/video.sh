#!/bin/sh
#
# $Id: video.sh, v1.00 2009-11-11 andy
#
# usage: video.sh 
#

echo "**** video.sh ***"

killall -q uvc_stream
sleep 3
uvc_stream -b &