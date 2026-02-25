# Details

Title: Authenticated Reflected Cross-Site Scripting in <b>"Uploading SVG, WEBP and ICO files"</b> Plugin for WordPress CMS</br>
Date: 2023-08-10</br>
Author: Danilo Albuquerque</br>
Vendor Homepage: https://wordpress.org</br>
Software Link: https://wordpress.org/download</br>
Version: WordPress 6.3</br>
Plugin's Name and Version: Uploading SVG, WEBP and ICO files 1.2.1</br>
Tested on: Brave (Version 1.50.119  Chromium: 112.0.5615.121 (Official Version)  64 bits)</br>

# PoC for Reflected XSS vulnerability in Uploading SVG, WEBP and ICO files 1.2.1

1. Install the plugin;
2. Create a SVG file with the malicious payload within it;
3. Go to the "Media" page and upload the SVG file; and then
4. Access the file through URL.

When you do all that and update the current page, it will bring you the alert pop-up with the message in it.

## Screenshots below

1. No plugin PoC:
![sem_o_plugin](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/1c6341f2-38cd-4898-ac14-a02b2105d5bc)

2. When there is no plugin the SVG file uploading does not work:
![sem_o_plugin_nao_pega](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/b870fb32-4cf9-4b1f-861a-541447856d3e)

3. The plugin's version in this day:
![versao_do_dia](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/30e1b8ac-f706-4a3b-8c7b-cb97ecf6f8d0)

4. The plugin is now installed and activated:
![plugin_instalado_e_ativo](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/08b56354-d4e4-4e2f-8bd1-d2607cae98f0)

5. Created the SVG file with the malicious payload within it:
![codigo_do_xss](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/6da49cfb-72b6-42b7-9a4f-09ecab87a93a)

6. SVG file's upload done:
![upload_feito_e_aceito](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/2cf191a2-f6cf-44aa-a400-e724a33735ce)

7. Payload triggered when the file is loaded:
![quando_acessa_xss](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/5ecafb8e-5017-41b5-8b57-b7e4b9d32c7b)

# Bonus section: Stored XSS

1. Changed the content of the malicious file:
![xss_stored_code](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/db35706c-3c80-4828-addd-a7655d7b2098)

3. Got the POST request in my Collaborator oastify:
![collaborator_poc](https://github.com/daniloalbuqrque/poc-cve-xss-uploading-svg/assets/85083396/a458b4f2-2a9c-4ae0-b693-6f1a2d2ec4c9)
