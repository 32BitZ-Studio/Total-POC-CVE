# CVE-2019-9849: Remote bullet graphics retrieved in “stealth mode” in LibreOffice

LibreOffice has a 'stealth mode' in which only documents from locations deemed 'trusted' are allowed to retrieve remote resources.
<br/>
This mode is not the default mode, but can be enabled by users who want to disable LibreOffice's ability to include remote resources within a document.
<br/>
A flaw existed where bullet graphics were omitted from this protection prior to version 6.2.5.
<br/>

<table>
	<tr>
		<th>HTML Tag</th>
		<th>HTML Attribute</th>
		<th>Triggers When Opened</th>
		<th>Triggers On Save/Export</th>
	</tr>
	<tr>
		<td><strong>ol</strong></td>
		<td><strong>src</strong></td>
		<td>No</td>
		<td>Yes</td>
	</tr>	
	<tr>
		<td><strong>ul</strong></td>
		<td><strong>src</strong></td>
		<td>No</td>
		<td>Yes</td>
	</tr>	
</table>

### Vendor Disclosure:

The vendor's disclosure for this vulnerability can be found [here](https://www.libreoffice.org/about-us/security/advisories/cve-2019-9849/).

### Proof Of Concept:

More details and the exploitation process (plus other HTML tag-attribute combination that result in SSRF) can be found in this [PDF](https://github.com/mbadanoiu/CVE-2019-9849/blob/main/LibreOffice%20-%20CVE-2019-9849.pdf).
