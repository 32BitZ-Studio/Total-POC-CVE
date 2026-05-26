# CVE-2026-0211: Nginx QUIC Parser Zafiyeti - Tehdit Analizi

## 1. Zafiyetin Tanımı
Nginx'in HTTP/3 (QUIC) protokolünü işleyen `ngx_quic_parse_packet` modülünde bulunan varsayımsal bir heap buffer overflow zafiyetidir. Zafiyet, QUIC bağlantı paketlerindeki (Initial Packet) `Destination Connection ID (DCID)` uzunluk baytının (`dcid_len`) doğru sınır kontrollerinden geçirilmeden işlenmesinden kaynaklanır.

## 2. Etki Alanı
Zafiyet, internete açık portlarda (genellikle UDP 443) dinleyen QUIC/HTTP3 destekli Nginx reverse proxy ve load balancer sistemlerini etkiler.
- **Gizlilik:** Hedef sunucunun memory dump'ı sızdırılabilir.
- **Erişilebilirlik:** Sistemin crash olması (Denial of Service) sağlanabilir.
- **Bütünlük:** Pre-auth Remote Code Execution (RCE) ile sisteme tam erişim sağlanabilir.

## 3. Tetiklenme Vektörü (Attack Vector)
Saldırgan, Nginx sunucusuna manipüle edilmiş bir UDP paketi gönderir. Paket içerisinde `dcid_len` değeri `0xFF` (255) olarak ayarlanır ancak gerçek payload daha kısa tutulur. Bounds check eksikliği nedeniyle `memcpy` işlemi esnasında heap taşması yaşanır.

## 4. Akademik Simülasyon
Bu laboratuvarda saldırgan vektörü Python Scapy kullanılarak `saldiri/` dizinindeki fuzzer betiği ile simüle edilmiştir. Nginx sunucusunda meydana gelen crash logları AddressSanitizer (ASAN) kullanılarak izlenmiş ve raporlanmıştır.
