#!/bin/bash

. /vagrant/env.sh

printf "${R}*** Installing dependencies ***${N}\n"
dnf -y install postgresql16-server
sudo postgresql-16-setup initdb
sudo systemctl start postgresql-16.service
echo "host    all             all             192.168.0.0/24            md5" >> /var/lib/pgsql/12/data/pg_hba.conf
echo "listen_addresses = '*'" >>/var/lib/pgsql/12/data/postgresql.conf
sudo systemctl restart postgresql-16.service
sudo systemctl status postgresql-16.service
