#!/bin/bash

. /vagrant/env.sh

printf "${R}*** Running Bootstrap_all.sh ***${N}\n"

printf "${R}*** Configuring repo ***${N}\n"
EDBTOKEN=$(cat /vagrant/.edbtoken)
curl -1sLf "https://downloads.enterprisedb.com/$EDBTOKEN/enterprise/setup.rpm.sh" | sudo -E bash

printf "${R}*** Disabling firewall ***${N}\n"
systemctl stop firewalld.service
systemctl disable firewalld.service
sed -i 's/%wheel/#%wheel/g' /etc/sudoers
sed -i 's/# #%wheel/%wheel/g' /etc/sudoers