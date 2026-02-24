#!/bin/bash
export N=$(tput sgr0)
export R=$(tput setaf 1)
export G=$(tput setaf 2)

export NETWORK=192.168.0.21
#export SERVERIP=$(ip addr show eth1 | grep 'inet ' | awk '{print $2}' | head -n 1  | cut -d '/' -f 1) >/dev/null
