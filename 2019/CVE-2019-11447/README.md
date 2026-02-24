## CVE-2019-11447 - PoC
Exploits CuteNews 2.1.2 via poor file upload checks used when uploading an avatar image leading to RCE.

### Installation

Clone the repository and install the requirements.

`pip install -r requirements.txt`

### Usage

In order to upload an avatar you will require a CuteNews user account, this doesn't have to be an administrator account.

`CVE-2019-11447.py {URL} {USERNAME} {PASSWORD}`

Example:

`CVE-2019-11447.py http://localhost/CuteNews/index.php {USERNAME} {PASSWORD}`
