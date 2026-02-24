#!/bin/bash

. /vagrant/env.sh

printf "${R}*** Installing dependencies ***${N}\n"
dnf install tar wget gcc make readline 
printf "${R}*** Installing PostgreSQL 9.6.4 from source ***${N}\n"
wget https://ftp.postgresql.org/pub/source/v9.6.4/postgresql-9.6.4.tar.gz
tar xzf postgresql-9.6.4.tar.gz
cd postgresql-9.6.4
sudo ./configure --prefix=/usr/local/postgresql96
sudo make
sudo make install

#sudo postgresql-12-setup initdb
#sudo systemctl start postgresql-12.service
#echo "host    all             all             192.168.0.0/24            md5" >> /var/lib/pgsql/12/data/pg_hba.conf
#echo "listen_addresses = '*'" >>/var/lib/pgsql/12/data/postgresql.conf
#sudo systemctl restart postgresql-12.service
#sudo systemctl status postgresql-12.service

