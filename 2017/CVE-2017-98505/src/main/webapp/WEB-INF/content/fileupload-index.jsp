<%@ taglib prefix="s" uri="/struts-tags" %>
<html>

<head>
    <s:head />
</head>

<body>
    <h1>Struts 2 CVE-2017-5638 file upload example</h1>

    <s:form action="fileupload" namespace="/" method="POST" enctype="multipart/form-data">
        <s:file name="fileUpload" label="Select a File to upload" size="40" />
        <s:submit value="submit" name="submit" />
    </s:form>

</body>

</html>