FROM debian:10
LABEL maintainer="lucas"
EXPOSE 80

RUN apt-get update && apt-get upgrade -y && apt-get install -y nginx php php-fpm curl php-curl unzip && \
  rm -rf /var/www/html && curl -Lo /tmp/php-proxy.zip https://www.exploit-db.com/apps/533ff094ea3ec711b05345a7277f45bd-php-proxy.zip && unzip -o /tmp/php-proxy.zip -d /var/www/html && \
  echo "server { \n\
  listen 80 default_server; \n\
  listen [::]:80 default_server; \n\
  root /var/www/html; \n\
  index index.html index.htm index.php; \n\
  server_name _; \n\
  location / { \n\
    try_files \$uri \$uri/ =404; \n\
  } \n\
  location ~ \.php$ { \n\
    include snippets/fastcgi-php.conf; \n\
    fastcgi_pass unix:/run/php/php7.3-fpm.sock; \n\
  } \n}" >/etc/nginx/sites-available/default

CMD /etc/init.d/php7.3-fpm start && /etc/init.d/nginx start && tail -f /var/log/nginx/access.log