#!/bin/bash

/etc/init.d/mysql start
mysqladmin -u root password "root"
mysql -e "CREATE DATABASE joomla DEFAULT CHARACTER SET utf8;" -uroot -proot
mysql -e "use joomla;source /db.sql;" -uroot -proot

/etc/init.d/apache2 start

php /var/www/html/cli/install-joomla-extension.php --package=/tmp/com_j2store_v3-3.3.6-core.zip
chown -R www-data:www-data /var/www/html/
rm -f /tmp/com_j2store_v3-3.3.6-core.zip

/usr/bin/tail -f /dev/null
