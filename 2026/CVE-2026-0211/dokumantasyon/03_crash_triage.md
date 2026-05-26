# Crash Triage ve Memory Hata Analizi (Memory Diagnostics)

## 1. Analiz Amacı
Fuzzer tarafından gönderilen malformed paketin hedef sistemde yarattığı etkiyi, Nginx'in AddressSanitizer (ASAN) ve UndefinedBehaviorSanitizer (UBSAN) çıktıları üzerinden analiz etmektir.

## 2. Tespit Edilen Çökme (Crash) Tipi
Başlangıçta hedeflenen zafiyet bir `heap-buffer-overflow` olmasına karşın, fuzzer simülasyonu esnasında çok daha erken evrede bir hafıza/pointer kayması tespit edilmiştir. Nginx'in C tabanlı parser mantığı, manipüle edilmiş 255 bytelık DCID uzunluğunu işlerken pointer alignment'ını (hizalamasını) kaybetmiştir.

## 3. ASAN/UBSAN Log Analizi
Hedef sistemden toplanan `asan.7` (veya `error.log`) dökümleri şu şekildedir:

```text
src/event/quic/ngx_event_quic_transport.c:194:14: runtime error: load of misaligned address 0x516000001ea1 for type 'uint32_t' (aka 'unsigned int'), which requires 4 byte alignment
0x516000001ea1: note: pointer points here
 00 00 00  c3 00 00 00 01 ff 41 41  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  41 41 41 41 41
              ^ 
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/event/quic/ngx_event_quic_transport.c:194:14 
```

### 3.1. Kök Neden (Root Cause) Analizi
- **Misaligned Dereference:** C programlama dilinde `uint32_t` gibi türler 4 bytelık veri blokları gerektirir ve pointer'ın bellekte 4'ün katı olan bir adreste (aligned) bulunması beklenir.
- **Hizalama Bozulması:** Gönderilen 255 bytelık (0xFF) `A` (0x41) karakterleri, pointer'ın bellek üzerinde kaymasına neden olmuştur. Sistem, 0x516000001ea1 adresindeki veriyi 32-bit (4-byte) int olarak okumaya çalıştığında, işlemci veya UBSAN mimarisi bu hizalanmamış (misaligned) erişimi tespit edip engellemiş ve undefined behavior hatası üretmiştir.
- **Güvenlik Perspektifi:** Bu durum, klasik bir `memcpy` tabanlı heap buffer overflow'dan önce, ağ parser'larında çok sık karşılaşılan tip dönüşüm (type casting) ve hizalama zafiyetlerine harika bir örnektir.

## 4. Sonuç ve Etki
Paketlerin katı boyut (bounds) kontrolünden geçirilmemesi, sistem belleğinde istenmeyen kaymalara ve okuma hatalarına (Out-of-Bounds Read / Misaligned Address) yol açmıştır. Geliştirilen Savunma Yaması (Bkz: `savunma/patch_guide.md`), `dcid_len` büyüklüğünü kontrol ederek bu pointer işlemlerinden önce paketi düşürür ve parser'ı korur.
