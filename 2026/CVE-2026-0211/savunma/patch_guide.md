# CVE-2026-0211 Savunma ve Yama Rehberi

Bu dizin, CVE-2026-0211 zafiyetine karşı geliştirilen ve test edilen proaktif güvenlik yamalarını barındırır.

## Yama Detayları (`CVE-2026-0211-defense.patch`)
Söz konusu yama, Nginx'in `src/event/quic/ngx_event_quic_transport.c` dosyasını hedef alır.

Temel olarak parser mantığına şu kuralları enjekte eder:
1. **Katı Sınır Kontrolü (Bounds Check):** İlgili `dcid_len` değerinin `NGX_QUIC_CID_LEN_MAX` sabitini veya 255 (0xFF) sınırını aşıp aşmadığını memory tahsisinden *önce* kontrol eder.
2. **Buffer Payload Kontrolü:** Belirtilen ID uzunluğunun, paket içerisinde kalan toplam okuma alanından (`end - p`) büyük olup olmadığını test ederek `memcpy` operasyonunun rastgele (out-of-bounds) bellek alanlarına erişmesini engeller.
3. **Özel Loglama:** Kötü amaçlı bir paket tespit edildiğinde doğrudan bağlantıyı `NGX_ERROR` ile düşürür ve `error.log` dosyasına saldırı girişimi izini (IOC) bırakır.

## Yamanın Uygulanması
Yama, Dockerfile içerisinde `patch` komutu kullanılarak otomatik olarak Nginx kaynak koduna derleme aşamasında enjekte edilmiştir. Ayrıntılar için `hedef/nginx/Dockerfile` içeriği incelenebilir.
