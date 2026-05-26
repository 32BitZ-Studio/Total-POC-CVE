# Araştırma ve Geliştirme Yol Haritası (Roadmap)

> [!NOTE]
> Bu doküman, araştırma projesinin yazılım geliştirme (fuzzer, patch, simülasyon betikleri) tarafına yönelik çalışma maddelerini listelemektedir.

## Faz 1: Laboratuvar ve Çevre Kurulumu
- [ ] **Docker Topolojisinin İnşası:** Victim (Nginx), Attacker (Fuzzer) ve Monitor node'ları için Dockerfile ve docker-compose konfigürasyonlarının hazırlanması.
- [ ] **Ağ Segmentasyonu:** Dışa kapalı (air-gapped) bir bridge ağın kurulması.
- [ ] **Nginx Kaynak Kodu Hazırlığı:** Nginx kaynak kodunun indirilmesi ve HTTP/3 desteğiyle ASAN/UBSAN (`-fsanitize=address,undefined`) kullanılarak derlenmesi.
- [ ] **Gözlem Araçlarının Kurulumu:** tcpdump ve Valgrind ortamlarının hazırlanması.

## Faz 2: Güvenli Fuzzer Geliştirme
- [ ] **Packet Corpus Oluşturma:** Wireshark veya mevcut araçlarla geçerli QUIC Initial, Handshake paketlerinin (seed corpus) elde edilmesi.
- [ ] **LibFuzzer Harness Geliştirme:** Nginx'in `ngx_quic_parse_packet` fonksiyonunu izole şekilde test edecek in-memory C/C++ harness kodunun yazılması.
- [ ] **AFL++ Entegrasyonu:** (Opsiyonel) Nginx'in ağ üzerinden beslenerek blackbox/greybox tarzında fuzz edilmesi için wrapper yazımı.
- [ ] **Fuzzing Kampanyası:** Fuzzer'ların başlatılması ve malformed (özellikle hatalı CID uzunluklu) paketlerin hedefe basılması.

## Faz 3: Kontrollü Simülasyon ve Crash Triage
- [ ] **Crash Triage:** Fuzzer tarafından bulunan ASAN crash loglarının incelenerek heap-buffer-overflow zafiyetinin tespit edilmesi.
- [ ] **Reproducer Script Geliştirme:** Python ve Scapy kullanılarak zafiyeti ağ üzerinden stabil şekilde tetikleyen minimalist bir "crash reproducer" betiği yazılması.
- [ ] **Hafıza Analizi (Memory Diagnostics):** GDB ve ASAN çıktıları ile taşan buffer'ın ve ezilen (corrupted) heap alanlarının haritalanması.

## Faz 4: Savunma Yaması Geliştirme
- [ ] **Güvenli Parsing Yaması (Patch):** Nginx `ngx_event_quic.c` dosyasına `dcid_len` için katı bounds checking eklenmesi.
- [ ] **Yamanın Entegrasyonu:** Değiştirilen kaynak kodun tekrar derlenmesi.

## Faz 5: Mitigasyon Doğrulama (Validation)
- [ ] **Regression Testing:** Fuzzer'ın bulduğu tüm crash payload'larının yamalı sisteme gönderilmesi ve Nginx'in stabil kaldığının (crash olmadığının) teyit edilmesi.
- [ ] **Performans Testleri:** Eklenen bounds-check kontrollerinin Nginx'in paket işleme kapasitesine (RPS) negatif etkisi olup olmadığının ölçülmesi.

## Faz 6: Akademik Çıktılar
- [ ] **Metriklerin Toplanması:** Fuzzing coverage verileri ve performans test sonuçlarının derlenmesi.
- [ ] **Raporun Yazılması:** Metodolojinin, yamanın ve simülasyon çıktılarının akademik bir doküman haline getirilmesi.
