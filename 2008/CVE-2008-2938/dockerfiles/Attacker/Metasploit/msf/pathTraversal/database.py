EXPLOITS = ["CVE-2008-2938", "CVE-2014-3625", "CVE-2016-1240"]

DOT_DOT = "%c0%ae%c0%ae"

def check_exploit_availability(cve):
    for available in EXPLOITS:
        if cve == available:
            return

    raise KeyError
