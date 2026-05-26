# Fuzzing Metodolojisi ve Uygulama Pratiği

## 1. Giriş
Bu doküman, CVE-2026-0211 hipotetik zafiyet senaryosunu (QUIC DCID Length Buffer Overflow) tetiklemek amacıyla geliştirilen fuzzing metodolojisini açıklamaktadır. Ağ tabanlı fuzzer, hedef Nginx sunucusunun QUIC parser'ındaki bellek denetimi (bounds checking) eksikliklerini tespit etmek için tasarlanmıştır.

## 2. Fuzzing Mimarisi
Modern fuzzer'ların (AFL++, libFuzzer vb.) aksine, bu çalışmada ağ tabanlı (network-based) ve yapısal (structure-aware) bir fuzzing yöntemi seçilmiştir.

- **Araç Kutusu:** Python 3, Scapy
- **Protokol:** UDP / QUIC Initial Packet
- **Hedef Değişken:** `dcid_len` (Destination Connection ID Length)
- **Topoloji:** `fuzzer_node` (10.13.37.20) üzerinden `target_nginx` (10.13.37.10) hedefine trafik üretimi.

## 3. Payload Tasarımı (Malformed Packet)
Fuzzer betiği, QUIC protokol standartlarına uygun gibi görünen ancak Nginx parser'ının zaafiyetini tetikleyecek spesifik manipülasyonlar içeren paketler üretir.

```python
# Payload Yapısı (Pseudocode)
flags = 0xc3              # Long Header, Initial Packet, Packet Number Length = 4
version = 0x00000001      # QUIC v1
dcid_len = 0xFF           # MANİPÜLE EDİLMİŞ UZUNLUK (255)
dcid_data = b"A" * 255    # Buffer'ı taşıracak veri
scid_len = 0x00
payload = flags + version + dcid_len + dcid_data + scid_len
```

## 4. Uygulama ve Güvenlik Duvarı Aşımı
Ağ izolasyonu, hedefin internete kapalı bridge network (`quic_lab`) içerisinde konumlandırılmasıyla sağlanmıştır. Fuzzer doğrudan Nginx'in 443. portuna paket göndererek, hedef sistemin `ngx_event_quic_transport.c` dosyasındaki ayrıştırma (parsing) rutinlerini tetikler.

## 5. Metrikler ve Ölçüm
- **Gönderilen Paket:** 1 adet spesifik hazırlanmış UDP paketi.
- **Sonuç:** Hedef parser fonksiyonuna (memory parsing) doğrudan erişim kanıtlanmış, AddressSanitizer/UBSAN üzerinden bellek erişim hataları yakalanmıştır.
