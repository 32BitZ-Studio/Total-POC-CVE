# Nginx HTTP/3 QUIC (CVE-2026-0211) Ön Araştırma Raporu

> [!IMPORTANT]
> Bu rapor, **tamamen hipotetik** bir zafiyet senaryosu (CVE-2026-0211) üzerine kurulu kontrollü ve savunma odaklı bir akademik araştırmayı temel almaktadır. İçerikte hiçbir silahlandırılmış (weaponized) exploit bulunmamaktadır.

## 1. Yönetici Özeti
Bu araştırma, Nginx'in HTTP/3 (QUIC) implementasyonunda yer alan hipotetik bir heap buffer overflow zafiyetini (CVE-2026-0211) ele almaktadır. Zafiyet, internete açık load balancer sistemlerde pre-auth uzaktan kod çalıştırma (RCE) potansiyeline sahiptir. Amacımız, zafiyetin kök neden analizini yapmak, kontrollü fuzzing metodolojileri ile tetiklenme koşullarını haritalamak ve kurumsal ağların uç noktalarında yer alan sistemler için etkili savunma yamaları geliştirmektir.

## 2. Tehdit ve Protokol Analizi

### QUIC Attack Surface Analizi
QUIC protokolü, taşıma (transport) katmanı ile kriptografik katmanı (TLS 1.3) birleştirerek doğrudan user-space içerisinde çalışır. Durum makinesi (state machine) yönetimi, paket şifreleme/çözme, multiplexing ve stream yönetimi Nginx worker süreçleri tarafından gerçekleştirilir. Bu yapı, saldırı yüzeyini önemli ölçüde genişletir.

### UDP Tabanlı Protokollerin Riskleri
Geleneksel TCP'nin aksine UDP bağlantısızdır (connectionless). Bu durum protokolü IP spoofing ve amplification saldırılarına açık hale getirir. QUIC bu riskleri adres doğrulaması ve Connection ID'ler (CID) ile azaltmaya çalışsa da, bu değerlerin ayrıştırılması bağlantı öncesi ve kimlik doğrulaması olmadan yapıldığı için kritik bir zafiyet penceresi oluşturur.

### Parser Karmaşıklığı ve Hafıza Yolsuzluğu
QUIC paketlerinde Variable-Length Integers (VLINT) kullanımı yoğun olarak görülür. Bir alanın uzunluğunun dinamik belirlenmesi, C gibi dillerde integer overflow ve off-by-one hatalarına zemin hazırlar. Dinamik uzunluklu CID'lerin heap veya stack üzerindeki ayrılmış buffer'lara kopyalanması sırasında eksik bounds-checking yapılması doğrudan hafıza yolsuzluğuna yol açar.

## 3. Zafiyet Hipotezi (CVE-2026-0211)

**Kök Neden:** 
`ngx_quic_parse_packet()` fonksiyonunda, paket header'ından okunan `dcid_len` (Destination Connection ID Length) değeri doğrulanmadan `memcpy()` fonksiyonuna geçirilmektedir. 

**Tetiklenme Mekanizması:**
1. Saldırgan malformed bir QUIC Initial paketi oluşturur ve `dcid_len` değerini 255 olarak belirler.
2. Nginx, CID için heap üzerinde sadece 20 byte (`NGX_QUIC_MAX_CID_LEN`) ayırmış durumdadır.
3. `memcpy(conn->dcid, packet_data, 255)` işlemi tetiklenir, bu da 235 byte'lık bir Heap-Based Buffer Overflow'a sebep olur.

> [!WARNING]
> İnternete açık Nginx sunucularında, saldırganın heap layout'unu önceden düzenleyerek kritik kontrol yapılarını manipüle etmesi, pre-auth RCE ile sonuçlanabilir.

## 4. İzole Lab Mimarisi

Araştırmanın güvenliği için tamamen izole edilmiş bir Docker ortamı kullanılacaktır:
- **Hedef Sistem:** ASAN/UBSAN bayrakları ile derlenmiş Nginx node'u.
- **Saldırgan/Fuzzer Sistem:** AFL++, LibFuzzer ve Python/Scapy ortamı.
- **Gözlem (Monitor) Sistem:** Trafik analizi için tcpdump, Zeek ve loglama için ELK stack.

Ağ segmentasyonu ile bu laboratuvarın dış dünya (internet) ile hiçbir bağı kalmayacaktır.
