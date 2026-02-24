# CVE-2018-12613
Local file inclusion bug due to no sanitization of user input.

# Software Affected
1. Wordpress Plugin: Site-Editor v.1.1.1;

# How to use
This PowerShell scripts need two parameters to craft a exploit HTTP request:

    1. Wordpress URL endpoint
    2. A full path file to be retrieved in remote server

# Example

Prepare all the parameters to use the script:

![Screenshot](example.JPG)

Then file is retrieved.


Code author: @_zc00l