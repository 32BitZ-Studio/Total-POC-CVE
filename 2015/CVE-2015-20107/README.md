# Python Patrol
Scan for python installations on macOS, and run CVE-2015-20107.py script to report if patching is needed

Several of these scripts need Full Disk Access permissions and must be run as root so it can scan the entire macOS filesystem (except the areas restricted by macOS)

Make sure to run this from an app with Full Disk Access permission - i.e. ensure iTerm.app has
Full Disk Access enabled in Apple System Settings, Security & Privacy Privacy & Security.

---

## How to use
Clone this repo

cd into the cloned repo directory

run
```
sudo ./python-patrol.zsh
```

---

## Example output:
```
...
lrwxr-xr-x  1 root  wheel  9 Apr 24 13:46 /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3 -> python3.9
=====CVE-2015-20107.py START=====
python_path:/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3 python_version:3.9.6
Warning encountered trying to use unquoted mailcap path: Refusing to use mailcap with filename "'$(xterm);#.txt". Use a safe temporary filename.
CVE-2015-20107 patched OK, exiting without error.
=====CVE-2015-20107.py STOP=====


lrwxrwxr-x  1 root  admin  9 Apr 26 13:59 /Library/Frameworks/Python.framework/Versions/3.9/bin/python3 -> python3.9
=====CVE-2015-20107.py START=====
python_path:/Library/Frameworks/Python.framework/Versions/3.9/bin/python3 python_version:3.9.11
No warning or error encountered importing unquoted mailcap path...!
CVE-2015-20107 NOT patched, PLEASE UPDATE OR UNINSTALL THIS PYTHON VERSION!
=====CVE-2015-20107.py STOP=====
...
```


## uninstall outdated versions installed from python.org packages
for instance, uninstall the discovered, outdated and vulnerable version 3.9.11 as follows
```
sudo ./uninstall_python.org_pkg.zsh 3.9
```
