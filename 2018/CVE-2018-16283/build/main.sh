#!/bin/bash

/etc/init.d/mysql start
mysqladmin -u root password "root"
mysql -e "CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8;" -uroot -proot
mysql -e "use wordpress;source /db.sql;" -uroot -proot

/etc/init.d/apache2 start

wp --path=/var/www/html/ plugin activate wordpress-wechat-broadcast-1.2.0 --allow-root

/usr/bin/tail -f /dev/null
