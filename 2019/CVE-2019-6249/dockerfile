FROM registry.docker-cn.com/library/centos:6
ADD php-5.2.17.tar.gz /
ADD HuCart.zip /
RUN yum install mysql mysql-server -y
RUN yum install httpd -y
RUN yum groupinstall "Development tools" -y
RUN useradd opt -d /opt/sbin
RUN yum install wget -y
RUN yum install epel-release -y
RUN yum install -y gcc make httpd-devel libxml2-devel bzip2-devel openssl-devel curl-devel gd-devel libc-client-devel libmcrypt-devel libmhash-devel aspell-devel libxslt-devel mysql-devel    
RUN ln -s /usr/lib64/libjpeg.so /usr/lib/libjpeg.so
RUN ln -s /usr/lib64/libpng.so /usr/lib/libpng.so
RUN ln -s /usr/lib64/libXpm.so /usr/lib/libXpm.so
RUN ln -s /usr/lib64/libc-client.so /usr/lib/libc-client.so
RUN ln -s /usr/lib64/krb5 /usr/lib/krb5
RUN ln -s /usr/lib64/libgssapi_krb5.so /usr/lib/libgssapi_krb5.so
RUN ln -s /usr/lib64/libgssrpc.so /usr/lib/libgssrpc.so
RUN ln -s /usr/lib64/libk5crypto.so /usr/lib/libk5crypto.so
RUN ln -s /usr/lib64/libkadm5clnt.so /usr/lib/libkadm5clnt.so
RUN ln -s /usr/lib64/libkadm5clnt_mit.so /usr/lib/libkadm5clnt_mit.so
RUN ln -s /usr/lib64/libkadm5srv.so /usr/lib/libkadm5srv.so
RUN ln -s /usr/lib64/libkadm5srv_mit.so /usr/lib/libkadm5srv_mit.so
RUN ln -s /usr/lib64/libkdb5.so /usr/lib/libkdb5.so
RUN ln -s /usr/lib64/libkrb5.so /usr/lib/libkrb5.so
RUN ln -s /usr/lib64/libkrb5support.so /usr/lib/libkrb5support.so
RUN ln -s /usr/lib64/mysql /usr/lib/mysql
RUN usermod -aG wheel opt
RUN echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN mv /php-5.2.17 /opt/sbin/php-5.2.17
RUN mv /HuCart.zip /var/www/html/.
WORKDIR /opt/sbin/php-5.2.17
RUN ls
RUN ./configure --prefix=/opt/sbin/php --with-apxs2=/usr/sbin/apxs --with-config-file-path=/opt/sbin/php/etc  --disable-posix   --enable-bcmath   --enable-calendar   --enable-exif   --enable-fastcgi   --enable-ftp   --enable-gd-native-ttf   --enable-libxml   --enable-magic-quotes   --enable-mbstring   --enable-pdo   --enable-soap   --enable-sockets   --enable-wddx   --enable-zip  --with-bz2   --with-curl   --with-curlwrappers   --with-freetype-dir   --with-gd   --with-gettext   --with-imap   --with-imap-ssl  --with-jpeg-dir  --with-kerberos   --with-libxml-dir  --with-libxml-dir   --with-mcrypt   --with-mhash   --with-mime-magic   --with-mysql  --with-mysqli   --with-openssl --with-openssl-dir --with-pcre-regex  --with-pdo-mysql   --with-pdo-sqlite   --with-pic   --with-png-dir   --with-pspell   --with-sqlite   --with-ttf   --with-xmlrpc   --with-xpm-dir  --with-xsl --with-zlib   --with-zlib-dir
RUN make -j8
RUN make install
RUN cp php.ini-dist ../php/etc/php.ini
RUN libtool --finish /opt/sbin/php-5.2.17/libs
RUN /opt/sbin/php/bin/php --version
RUN echo "AddType application/x-httpd-php .php \
LoadModule php5_module modules/libphp5.so \
<IfModule mod_php5.c> \
    AddType application/x-httpd-php .php\
    AddType application/x-httpd-php-source .phps\
</IfModule>" >> /etc/httpd/conf/httpd.conf 
RUN sed -i "s/index.html/index.php index.html/g" /etc/httpd/conf/httpd.conf
WORKDIR /var/www/html/
RUN unzip -q HuCart.zip
RUN rm -rf HuCart.zip
RUN chmod -R 777 *
ENTRYPOINT  /etc/init.d/mysqld start && mysqladmin -hlocalhost -uroot password '123456' && mysql -uroot -p123456 -e "create database hucart;"&&mysql -uroot -p123456 -e "grant all privileges on hucart.* to root@'localhost' identified by '123456';" &&mysql -uroot -p123456 -e "flush privileges;" && /etc/init.d/httpd restart && tail -f /var/log/mysqld.log