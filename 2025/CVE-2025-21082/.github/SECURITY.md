## 📅 Desteklenen Sürümler

Bu depo, üretime yönelik ticari bir yazılım paketi olmayıp, kontrollü bir simülasyon ve akademik araştırma ortamı sunduğundan dolayı güvenlik desteği doğrudan simüle edilen CVE vektörlerine göre yapılandırılmıştır:

| Sürüm | Destek Durumu | İncelenen ve Adreslenen Zafiyet Vektörleri |
| :--- | :---: | :--- |
| v1.0.x (Güncel) | :white_check_mark: | CVE-2025-21082 (UAF), CVE-2025-2844 (Dizin Geçişi) |
| Eski Sürümler | :x: | Simülasyon kapsamı dışındaki geçmiş bellenim (firmware) zafiyetleri |

---

## 🎓 Akademik Sorumluluk Reddi ve Sorumlu Açıklama (Responsible Disclosure)

Bu depoda yer alan tüm araçlar, PoC (Proof of Concept) kodları ve interaktif simülasyon senaryoları **tamamen eğitim, akademik araştırma ve defansif siber güvenlik bilincini artırma** amacıyla geliştirilmiştir. Temel hedef; sistem mimarlarının, üniversite öğrencilerinin ve siber güvenlik araştırmacılarının yapısal bellek güvenliği (memory safety) hatalarını ve girdi doğrulama bypass yöntemlerini derinlemesine anlamasını sağlamaktır.

### Bağımsız Zafiyet Keşifleri İçin Önemli Not:
Bu simülasyonları ve analizleri rehber alarak gerçek Xiaomi HyperOS bellenimleri veya Android Açık Kaynak Projesi (AOSP) bileşenleri üzerinde yeni/keşfedilmemiş bir zafiyet tespit ederseniz, **kesinlikle GitHub üzerinde herkese açık bir "Issue" (Hata Bildirimi) açmayınız.** Bunun yerine endüstri standardı olan sorumlu açıklama modellerini takip ediniz:
1. Bulguyu doğrudan **Xiaomi Güvenlik Merkezi (MiSRC)** resmi ödül avcılığı (Bug Bounty) platformu üzerinden iletin.
2. Eğer zafiyet kök neden olarak AOSP medya bileşenlerini etkiliyorsa, bildirimi **Android Güvenlik Ödülleri Programı (VRP)** üzerinden gerçekleştirin.

---

## 🚨 Bu Simülasyon Projesindeki Hataları Bildirme

Eğer bizzat bizim geliştirdiğimiz simülasyon ortamının kendi kaynak kodlarında bir güvenlik açığı, beklenmeyen bir mantık hatası veya yerel sömürü vektörü tespit ederseniz (örneğin; `simulation.html` panelinde bir XSS açığı veya Rust PoC CLI aracında ana makineyi kilitleyen kararsız bir bellek taşması), lütfen aşağıdaki koordineli bildirim sürecini işletiniz:

1. **Kesinlikle herkese açık bir Issue açmayın.** Açık paylaşım, savunma mekanizmaları ve yamalar henüz hazır değilken risk faktörünü artırır.
2. Tespit ettiğiniz teknik detayları içeren kapsamlı bir raporu depo yöneticisinin birincil akademik e-posta adresine güvenli bir şekilde gönderin.
3. **Raporunuzda şu detaylara yer veriniz:**
   * Simülasyon kodu içindeki zafiyetin/hatanın net bir tanımı.
   * Davranışı yerel ortamda yeniden tetikleyebilmek için adım adım komutlar veya girdi şablonları.
   * Hatanın yerel test ortamı üzerindeki potansiyel etkisi.
   * Önerdiğiniz çözüm veya kod yaması (mitigation) adımları.

### İnceleme ve Geri Dönüş Takvimimiz:
* **İlk Onay:** Güvenli rapor alındıktan sonraki ilk 48 saat içinde durum size bildirilir.
* **Triyaj ve Analiz:** Bildirilen mantık veya siber güvenlik hatasının geçerliliği en geç 7 iş günü içerisinde doğrulanır.
* **Yama Yönetimi:** Koordineli güvenlik yaması ana (main) dala gönderilir ve talep etmeniz halinde katkınız / keşfiniz dokümantasyonda isminizle onurlandırılır.

---

## 🛡️ Projede Gösterilen Defansif Mühendislik Standartları

Bu proje aktif olarak bellek güvenliğini ve defansif kodlama pratiklerini teşvik eder. Bu simülasyondakine benzer zafiyetlerin gerçek üretim sistemlerinde engellenmesi için şu temel savunma hatlarının kurulu olduğundan emin olunmalıdır:

* **Bellek Güvenli Alternatifler (Memory Safety):** Performans kritik ve asenkron çalışan medya bileşenlerinin eski nesil C++ mimarilerinden **Rust** diline taşınması, derleme zamanındaki (compile-time) yaşam döngüsü ve sahiplik (ownership) kuralları sayesinde Use-After-Free (UAF) zafiyetlerini tamamen ortadan kaldırır.
* **Sıkı Yol Kanonikleştirme (Path Canonicalization):** Dosya transferi veya varlık okuma süreçlerinde sembolik bağlar (symbolic links) çözülmeli ve mutlak dosya yolları, izole edilmiş kök dizine (sandbox root) göre sıkı bir doğrulamadan geçirilerek dizin geçişi (directory traversal) manipülasyonları engellenmelidir.
* **Otomatik Enstrümantasyon (Sanitizers):** Yazılım derleme ve sürekli entegrasyon (CI/CD) süreçlerine `AddressSanitizer (ASan)` entegre edilerek, regresyon hatalarının ve bellek sızıntılarının daha kod üretim aşamasına geçmeden otomatik yakalanması sağlanmalıdır.