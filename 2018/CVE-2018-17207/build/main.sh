#!/bin/bash

/etc/init.d/mysql start
mysqladmin -u root password "root"
mysql -e "CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8;" -uroot -proot
mysql -e "use wordpress;source /db.sql;" -uroot -proot

/etc/init.d/apache2 start

./backup.sh -D

/usr/bin/tail -f /dev/null
