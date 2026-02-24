#!/bin/bash

/etc/init.d/mysql start
mysqladmin -u root password "root"
mysql -e "CREATE DATABASE joomla DEFAULT CHARACTER SET utf8;" -uroot -proot
mysql -e "use joomla;source /db.sql;" -uroot -proot

/etc/init.d/apache2 start

/usr/bin/tail -f /dev/null
