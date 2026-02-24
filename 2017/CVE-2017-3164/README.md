# Apache Solr Poc CVE-2017-3164 CVE-2017-12629

This folder contains example exploits for Apache Solr CVE-2017-3164 CVE-2017-12629

To be use ONLY for education purposes and with full permission of the Apache Solr Server owner.

You will need to know the IP or DNS name of the Apache Solr server and the name of a Collection.

# CVE-2017-3164

Server Side Request Forgery in Apache Solr, versions 1.3 until 7.6 (inclusive). Since the "shards" parameter does not have a corresponding whitelist mechanism, a remote attacker with access to the server could make Solr perform an HTTP GET request to any reachable URL.

---

This SSRF is extremely powerful because all you have to do is send a GET request to this and it will make a POST request to the target. Additionally, you can supply the POST request body as a URL parameter along with the GET request.

# CVE-2017-12629

Rmote code execution occurs in Apache Solr before 7.1 with Apache Lucene before 7.1 by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.

---

I just chose this RCE to exploit, but Apache Solr has lots of RCE vulnerabilities you could exploit with the SSRF. You could also just as easily exploit any other server the Solr sever has access to e.g. supply Redis commands and get a reverse shell on Redis servers instead.

# exploit-javascript.html

You can host this file on a public web server and then email it to the target user. If the target loads the webpage the JavaScript will automatically exploit the Apache Solr server.

The Port number needs to be supplied in the `?n=` URL param. This way you can send emails to multiple targets and have a unique listener for each one.

