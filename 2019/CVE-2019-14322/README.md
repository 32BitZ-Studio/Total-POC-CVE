# CVE-2019-14322-scanner

- A vulnerability was found in Pallets Werkzeug up to 0.15.4. It has been declared as critical. This vulnerability affects the function SharedDataMiddleware of the component Windows. The manipulation with an unknown input leads to a directory traversal vulnerability. The CWE definition for the vulnerability is CWE-22
- In Pallets Werkzeug before 0.15.5, SharedDataMiddleware mishandles drive names (such as C:) in Windows pathnames.
- Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

# Usage:

- This script reads c:/windows/win.ini as a proof of concept
- python3 CVE-2019-14322-scanner.py -l list_target.txt

# Published in:

- https://github.com/nomi-sec/PoC-in-GitHub#cve-2019-14322-2019-07-28

# Disclaimer:

- The script is for security analysis and research only, hence I would not be liable if it is been used for illicit activities
