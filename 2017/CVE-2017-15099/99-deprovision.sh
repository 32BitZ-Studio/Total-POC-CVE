#!/bin/bash

. ./env.sh

printf "${G}*** De-provisioning old VM's ***${N}\n"
vagrant destroy -f
