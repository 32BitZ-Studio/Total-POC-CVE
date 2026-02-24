#!/bin/bash

. /vagrant/env.sh

printf "${R}*** Installing dependencies ***${N}\n"
dnf -y install nc vim curl

printf "${R}*** Installing Metasploit Framework ***${N}\n"
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstaller
chmod +x msfinstaller
./msfinstaller
