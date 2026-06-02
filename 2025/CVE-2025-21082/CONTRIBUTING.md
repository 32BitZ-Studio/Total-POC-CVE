# Katkıda Bulunma Rehberi

CVE-2025-21082 projesine katkıda bulunduğunuz için teşekkür ederiz! 🎉

## 🚀 Nasıl Katkıda Bulunabilirsiniz

### 🐛 Hata Bildirimi
- [Hata raporu şablonunu](.github/ISSUE_TEMPLATE/hata-raporu.md) kullanarak issue açın
- Hatayı yeniden üretme adımlarını detaylı şekilde açıklayın
- Sistem bilgilerinizi ve hata mesajlarını ekleyin

### 💡 Özellik Önerisi
- [Özellik isteği şablonunu](.github/ISSUE_TEMPLATE/ozellik-istegi.md) kullanın
- Özelliğin neden gerekli olduğunu açıklayın
- Mümkünse implementasyon önerileri sunun

### 🔧 Kod Katkısı
1. Projeyi fork edin
2. Yeni bir branch oluşturun (`git checkout -b ozellik/harika-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'feat: harika özellik eklendi'`)
4. Branch'inizi push edin (`git push origin ozellik/harika-ozellik`)
5. Pull Request açın

## 📝 Kod Standartları

### Rust Kodu
- `cargo fmt` ile kodu formatlayın
- `cargo clippy` uyarılarını çözün
- Unsafe kod kullanırken detaylı yorumlar ekleyin
- Test yazın ve `cargo test` ile doğrulayın

### Python Kodu
- PEP 8 standartlarını takip edin
- Type hint'leri kullanın
- Docstring'leri ekleyin
- `black` ile kodu formatlayın

### Dokümantasyon
- Türkçe dokümantasyon yazın
- Markdown formatını kullanın
- Kod örnekleri ekleyin
- Bağlantıları kontrol edin

## 🧪 Test Etme

### Rust PoC
```bash
cd poc_rust
cargo build --release
cargo test
./target/release/cve_2025_21082_uaf_poc --mode vulnerable
./target/release/cve_2025_21082_uaf_poc --mode patched
```

### Python Araçları
```bash
cd poc_python
pip install -r requirements.txt
python -m pytest tests/
```

### Simülasyon
- `simulation.html` dosyasını tarayıcıda açın
- Tüm 5 sahnenin doğru çalıştığını kontrol edin
- Farklı tarayıcılarda test edin

## 📋 Commit Mesaj Formatı

Conventional Commits formatını kullanın:

```
tip(kapsam): kısa açıklama

Detaylı açıklama (opsiyonel)

Fixes #123
```

### Commit Tipleri
- `feat`: Yeni özellik
- `fix`: Hata düzeltmesi
- `docs`: Dokümantasyon değişikliği
- `style`: Kod formatı değişikliği
- `refactor`: Kod yeniden düzenleme
- `test`: Test ekleme/düzeltme
- `chore`: Bakım işleri

## 🔒 Güvenlik

- Bu proje eğitim amaçlıdır
- Gerçek sistemlerde test etmeyin
- Zararlı kod eklemeyin
- Güvenlik açığı bulursanız özel olarak bildirin

## 📞 İletişim

- GitHub Issues üzerinden
- Dokümantasyon soruları için docs/ klasörünü inceleyin
- Teknik sorular için kod yorumlarını okuyun

## 📄 Lisans

Katkılarınız MIT lisansı altında yayınlanacaktır. Detaylar için [LICENSE](LICENSE) dosyasını inceleyin.

---

**Teşekkürler!** 🙏 Katkılarınız projeyi daha iyi hale getiriyor.