#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [ -z "$(ps cax | grep java)" ]; then
  echo restart >> /root/out.txt
  service tomcat7 restart &
else
  echo already >> /root/out.txt
fi
