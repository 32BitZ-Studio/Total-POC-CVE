from shodan import Shodan
from dotenv import load_dotenv
import os
import sys
from pathlib import Path  
import datetime




# load Shodan API Key from .env file
load_dotenv()
env_path = Path('.') / '../.env'
load_dotenv(dotenv_path=env_path)

api = Shodan(os.getenv("api-token"))

dt = datetime.datetime.now() 

counter = 0
try:
    # Search Shodan
    results = api.search('HP HTTP Server; HP Officejet 4630 series - B4L03A')

    # Show the results
    print('Results found: {}'.format(results['total']))
    outfile = '/Users/tylerbutler/Documents/projects/Security Reporting/HP OfficePrint 4630 0-day/Proof of Concepts/Indicators of Compromise/hp-cve-check/data/shodan/shodan-search-' + str(dt)
    for result in results['matches']:
        f = open(outfile,'a')
        ip = result['ip_str']
        f.write(ip+'\n')
        f.close()
        counter +=1
except IOError as e:
    print('Error',e)

print('{!} Total Targets Enumerated: ',counter)