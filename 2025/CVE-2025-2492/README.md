# Origasus

`origasus.go` ile derlenen, ASUS AiCloud / AsusWRT ile ilişkilendirilebilecek uçların **yetkili güvenlik testi veya savunma analizi** (ör. kendi cihazınız, yazılı penetest laboratuvarı) kapsamında incelenmesi için yazılmış bir **Go** programıdır.

**Önemli:** Bu tür yazılımların yetkisiz sistemlere karşı kullanımı çoğu ülkede **yasadışıdır**. Yalnızca açık izin ve yasal çerçeve içinde çalıştırın. Üretimde veya üçüncü taraf ağlarda izinsiz tarama / istismar **kullanmayın**.

## Bağlam

Kaynak dosyanın başlık yorumlarında belirtilen ilgili referanslar (ör. CVE-2025-2492, CVE-2024-12912, CVE-2025-59366 ve üretici danışmanlıkları) güvenlik yamaları ve risk değerlendirmesi için kullanılabilir. Programın amacı, güvenlik araştırmacılarının ve savunma ekiplerinin bu sınıf saldırıları **tanıması ve azaltması**dır; kötüye kullanımı desteklenmez.

## Gereksinimler

- [Go](https://go.dev/dl/) (modül dosyası yoksa tek dosya olarak derlenebilir)

## Derleme

Proje kökünde:

```bash
go build -o origasus origasus.go
```

## Genel davranış (yüksek seviye)

- Standart girdiden veya `-f` ile verilen dosyadan hedef satırları okur.
- Hedefi ASUS AiCloud / AsusWRT göstergeleriyle **doğrulamaya** çalışır (yanlış pozitifleri azaltmak için).
- Ardından dosyada tanımlı HTTP istekleri ve varyantlar üzerinden zincirlenmiş adımlar dener; başarılı denemeler `exploited.txt` (veya `-exploited` ile verilen dosya) içine kaydedilebilir ve bir sonraki çalıştırmada atlanabilir.

Ayrıntılı istek gövdeleri, yük varyantları ve üretim ortamında kullanım **bu README kapsamında değildir**; detaylar yalnızca kaynak kod incelemesi ve yetkili müdahale süreçleri için bırakılmıştır.

## Komut satırı bayrakları

| Bayrak | Açıklama |
|--------|----------|
| `-port` | Bağlantı portu; `null` (satırdaki `host:port` veya ayırıcıyla port), `manual` (443 + TLS) vb. |
| `-separator` | Satırdaki port ayırıcısı (varsayılan: `,`) |
| `-tls` | TLS kullan |
| `-multiport` | Tek host için yaygın port listesini tara |
| `-f` | Girdi dosyası (`-` veya boş: stdin) |
| `-exploited` | İşlenmiş hostları tutan dosya (varsayılan: `exploited.txt`) |
| `-no-skip` | Daha önce işaretlenmiş hostları atlama |

Pozisyonel argümanlar: `manual`, `no-skip`, `multiport`, `tls`, `debug` (kaynakta `main` içinde işlenir).

Zmap ile ortak çalıştırma : zmap -p 443 | ./origasus

## Ortam değişkenleri

| Değişken | Rol |
|----------|-----|
| `ASUS_LOADER` | Yükleyici ana bilgisayar (isteğe bağlı `host:port` biçiminde önek) |
| `ASUS_LOADER_PORT` | Yükleyici TCP portu |
| `ASUS_TAG` / `ASUS_PAYLOAD_ARG` | Yükleyici / etiket parametresi |

## Sinyal davranışı

`SIGINT` / `SIGTERM` alındığında süreç `124` çıkış kodu ile sonlanır (uzun süren işlemlerde dış gözlemciler için).

## Sorumluluk reddi

Bu yazılım “olduğu gibi” sunulur. Yazarlar ve katkıda bulunanlar, yetkisiz veya yasadışı kullanımdan doğan zararlardan sorumlu tutulamaz. Savunma tarafında kullanım için günlükleri, ağ izlerini ve üretici güvenlik bültenlerini esas alın.
