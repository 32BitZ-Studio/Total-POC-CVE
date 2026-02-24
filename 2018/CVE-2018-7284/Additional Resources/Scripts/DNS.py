#!/usr/bin/env python
import socket
import binascii


SERVER_PORT = 53
SERVER_IP = "192.168.171.128"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
address = (SERVER_IP, SERVER_PORT)
sock.bind(address)

#Response variables
flags = "8580"
questions = "0001"
answerRR = "0002"
authorityRR = "0001"
additionalRR = "0002"


while True:
    data,address= sock.recvfrom(10240)
    
    if "online" in data:
        if "sip" in data:
            if "udp" in data:
                hexdata = binascii.hexlify(data).decode()
                print hexdata    
                print data
                print "Esta es la direccion", address
                
                host = address[0]
                port = address[1]
                print "Este es el host:",host,"este es el puerto", port
                xid = hexdata[:4]
                print "Este es el transactionID: " , xid
                query1 = hexdata[24:86]
                query2 = query1.replace("742d6f6e6c696e", "b72f52006c696e")

                answer = "c00c00210001000001450020000a000013c40ab72830d0b72e83d030310465646e7307742d69706e6574c023c00c002100010000014500130014000013c40a68322d6570702d383031c048"
                #answer = "c00c00210001000001450020000a000013c40a646f2d6570702d3830310465646e7307742d69706e6574c023c00c002100010000014500130014000013c40a68322d6570702d383031c048"
                authoritativeNS = "c0160002000100000078000603706278c016"
                aditionalRecords = "c08200010001000000780004c0a8ab870000291000000000000000"
                
                hexmsg = xid
                hexmsg += flags
                hexmsg += questions
                hexmsg += answerRR
                hexmsg += authorityRR
                hexmsg += additionalRR
                hexmsg += query2
                hexmsg += answer
                hexmsg += authoritativeNS
                hexmsg += aditionalRecords
                
                print "Este es el mensaje en hexa: ",hexmsg   
                print "Esta es la query modificada: ",query2
                
                msg = hexmsg.decode('hex')
                
                sock.sendto(msg,(host,port))
   
        
    print "CHAU"
    
    
