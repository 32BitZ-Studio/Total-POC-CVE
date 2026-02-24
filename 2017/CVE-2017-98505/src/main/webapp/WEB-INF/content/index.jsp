<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>

<html>

<head>
</head>

<body>

    <h1>Vulnerable Struts 2 application</h1>
    <p>This application is an example of a Struts 2 application that is vulnerable to remote command execution (RCE)</p>
    <p>The current vulnerabilities are: </p>
    <ol>
        <li>Struts 2 REST plugin:  CVE-2017-98505</li>
        <li><a href="/fileupload">Multipart File upload: CVE-2017-5638</a></li>
    </ol>

</body>

</html>