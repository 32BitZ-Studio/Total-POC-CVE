#!/bin/bash
VAR = "wlp3s0"
HOSTIP = $(ifconfig $VAR | grep "inet" | awk '{print $2}' | awk -F: '{print $2}')
echo $HOSTIP
