if [ $1 = "1.0" ] || [ $1 = "1.1" ]
then
    sed -i "s/XXX/$1/g" docker-compose.yml
    tar -xvf sources/Chitor-CMS-for$1.tar -C sources/
    cp sources/chitor-cms-$1/database/chitor_db.sql images/mariadb/chitor_db.sql
    docker-compose up -d --build
else
   echo "Usage: sudo ./run.sh [1.0|1.1]"
fi
