#!/bin/bash

# 等待数据库
echo "Waiting for MySQL to be ready..."
until nc -z -v -w30 ry-mysql 3306; do
  sleep 2
done

# 初始化数据库
mysql -u root --default-character-set=utf8mb4 -ppassword -h ry-mysql -e "SET GLOBAL character_set_server='utf8mb4'; SET GLOBAL collation_server='utf8mb4_general_ci'; SET GLOBAL character_set_database='utf8mb4'; SET GLOBAL collation_database='utf8mb4_general_ci';"

mysql -u root --default-character-set=utf8mb4 -ppassword -h ry-mysql -e "CREATE DATABASE IF NOT EXISTS ry DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root --default-character-set=utf8mb4 -ppassword -h ry-mysql ry < /workspace/RuoYi-4.2/sql/quartz.sql
mysql -u root --default-character-set=utf8mb4 -ppassword -h ry-mysql ry < /workspace/RuoYi-4.2/sql/ry_20200323.sql

echo "Database initialized"

# mvn打包
cd /workspace/RuoYi-4.2/
mvn install

# 运行jar
java -jar ruoyi-admin/target/ruoyi-admin.jar