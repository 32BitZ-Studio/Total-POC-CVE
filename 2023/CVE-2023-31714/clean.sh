docker stop cve-2023-31714_mariadb_1 cve-2023-31714_nginx_1 cve-2023-31714_php_1
docker rmi -f cve-2023-31714_mariadb cve-2023-31714_nginx cve-2023-31714_php
rm -d -r sources/chitor-cms-*
sed -i 's/sources\/chitor-cms-.../sources\/chitor-cms-XXX/g' docker-compose.yml
