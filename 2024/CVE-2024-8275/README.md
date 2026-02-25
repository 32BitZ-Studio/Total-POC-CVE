# CVE-2024-8275
CVE-2024-8275 is a critical SQL injection vulnerability discovered in the WordPress plugin The Events Calendar. This vulnerability affects versions up to and including 6.6.4. The issue arises from insufficient escaping of the 'order' parameter in the tribe_has_next_event() function. Because the input is not properly sanitized, unauthenticated attackers can append malicious SQL queries, allowing them to access sensitive information stored in the database.


1- Install Python: Ensure Python 3 is installed. Check with:
python --version


2- Install requests: Run:
pip install requests


3- Install sqlmap (Optional):
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git


4- Run the script: Save the code as exploit.py and run:
python exploit.py

Run the sqlmap command if generated after a successful exploit. 
I take no responsibility for the use of this script and use at your own risk
