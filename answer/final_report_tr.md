# Project Obsidian Clock — Nihai teknik rapor

## 1. Yönetici özeti

Obsidian Clock, gerçek bir sürücüye ait olmayan, metin tabanlı kanıt kapsülleri
üzerine kurulmuş sentetik bir Windows kernel tersine mühendislik vakasıdır.
İnceleme, beş semptomun tek bir gizli müdahaleden değil, beş ayrı mühendislik
kusurundan kaynaklandığını göstermektedir: V2 protokolünün ABI sözleşmesi,
ring-slot yaşam döngüsü, oturum kapatma senkronizasyonu, OCVM2 dal semantiği ve
PE relocation normalizasyonu.

En güçlü sonuçlar byte ve durum geçişi düzeyinde yeniden üretilebilmektedir.
28 byte'lık V2 paketinin yanlış ofsetlerden okunması, sürücünün kapsülde verilen
üç hatalı alan değerini tam olarak üretmektedir. Ring modeli, küçük sayaç
genişliğiyle yapılan bounded BFS sırasında stale cancel biletinin yeni bir IRP'yi
iki kez tamamlamasına giden karşı örneği kendisi bulmaktadır. OCVM2 örneğinde
aynı `+1` displacement değeri doğrulayıcıda `0x18`, tarihsel yorumlayıcıda
`0x11` adresini üretmektedir. Relocation modeli ise yalnız iki `DIR64` girdisini
işlediğinde preferred-image digest'ini geri elde ederken, iki `ABSOLUTE` padding
girdisini de işleyen hatalı algoritmanın nonzero delta altında farklı digest
ürettiğini göstermektedir.

Bu sonuçlar, görünmeyen bir `.sys` dosyasının gerçekten analiz edildiği anlamına
gelmez. Depoda sürücü, PDB, dump veya ETL yoktur; bütün iddialar kapsül sınırı ve
yerel sentetik modellerle açıkça ayrılmıştır.

## 2. Kapsam ve yetkilendirme sınırı

Çalışma yalnızca savunmacı analiz, parser geliştirme, bounded concurrency modeli,
kontrol akışı doğrulaması ve kaynak seviyesi düzeltme tasarımı kapsamındadır.
Exploit, privilege escalation, kernel shellcode, mapper, persistence, HVCI veya
PatchGuard bypass üretilmemiştir. Gerçek bir üretici, sertifika, makine veya
sürücü hedeflenmemiştir.

İnceleme modu `EVIDENCE-CAPSULE` olarak belirlenmiştir. Gerçek artefakt
bulunmadığı için giriş hash'leri doğrulanamamış, WinDbg/IDA/Ghidra çalıştırıldığı
iddia edilmemiş ve kapsüllerde yer almayan RVA, opcode veya durum kodları gerçek
gözlem gibi sunulmamıştır.

## 3. Kanıt envanteri ve güvenilirlik

Kanıt kataloğu `01_evidence_ledger.md` içindedir. Başlıca gruplar şunlardır:

- `[E-PE-*]`: PE meta verisi, importlar, başlangıç sorumlulukları ve CFG;
- `[E-IO-*]`: dört IOCTL, V2 bildirimi, ham paket ve korelasyon trace'i;
- `[E-RING-*]`: slot meta verisi, ticket, wrap senaryosu ve verifier özeti;
- `[E-LOCK-*]`: iki thread, resource/event sahipliği ve service beklemesi;
- `[E-VM-*]`: sekiz byte instruction, validator/interpreter hesabı ve örnek;
- `[E-INT-*]`: relocation block'u, normalizer pseudocode'u ve hash sapması;
- `[E-RH-*]`: kasıtlı olarak yetersiz üç şüpheli gözlem.

Kapsülde doğrudan verilen değerler `FACT`, bit alanı ve byte hesapları `DERIVED`,
birden çok bulguyla desteklenen kök nedenler `INFERENCE` olarak ele alınmıştır.
Unload sırası, tam IRQL sözleşmesi, gerçek hash algoritması ve eksik opcode'lar
`UNKNOWN` kalmaktadır.

## 4. Mimari rekonstrüksiyon

`[E-PE-03]`, sürücünün `\Device\ObClock` kontrol cihazı, sembolik link, dört
device-control yolu, minifilter communication port'u, `ERESOURCE`, drain event'i,
256 slotlu ring ve shutdown callback'i bulunduğunu belirtmektedir. Kullanıcı
modundaki WOW64 service kontrol düzleminde `DeviceIoControl` kullanmaktadır.

`FltSendMessage` yönü kernel minifilter'dan user-mode client'a doğrudur. Service
tarafında `FilterGetMessage`, `FilterReplyMessage` veya `FilterSendMessage`
kullanılması mümkün olsa da kapsüller kesin API'yi göstermemektedir. Önceki
belgedeki `ClockSvc -> FltSendMessage` yönü bu nedenle düzeltilmiştir.

Tam unload ve partial-initialization unwind yolu kanıttan çıkarılamaz. İmport
tablosunda bir fonksiyon bulunması da tek başına onun belirli bir yolda
çağrıldığını kanıtlamaz.

## 5. IOCTL ve V2 ABI analizi

`CTL_CODE` çözümü, function alanının `(code >> 2) & 0xFFF` olduğunu gösterir:

| IOCTL | Function | Method | Access |
|---:|---:|---|---|
| `0x8337E404` | `0x901` | BUFFERED | read + write |
| `0x8337E409` | `0x902` | IN_DIRECT | read + write |
| `0x8337E40E` | `0x903` | OUT_DIRECT | read + write |
| `0x8337E410` | `0x904` | BUFFERED | read + write |

Önceki rapordaki `0x790/0x792/0x794/0x796` değerleri aritmetik olarak yanlıştı
ve araç çıktısıyla çelişiyordu; belge ve testler `0x901`–`0x904` üzerinde
birleştirilmiştir.

V2 wire paketi 28 byte'tır. Nonce `0x0C`, capabilities `0x14`, CRC ise `0x18`
ofsetindedir. Tarihsel sürücü nonce'u `0x10` ofsetinden sekiz byte okuyarak
nonce'un üst yarısı ile capabilities değerini birleştirir:

```text
44 33 22 11 05 00 00 00 -> 0x0000000511223344
```

Ardından `0x18` değerini capabilities olarak, actual input'ın dışındaki `0x1C`
değerini CRC olarak kullanır. `[E-IO-06]` içindeki üç değer böylece tam olarak
elde edilir.

Uyumlu düzeltme V2'yi 32 byte'a çevirmek değildir. V2, 28 byte olarak açık
little-endian ofsetlerle parse edilmelidir. 32 byte'lık yeni bir gösterim ancak
yeni bir protocol version ile tanımlanabilir. Ayrıca doğrulama backing allocation
uzunluğuna değil gerçek `InputBufferLength` değerine dayanmalıdır.

## 6. Ring-buffer ve iptal yaşam döngüsü

Ticket yalnız `(slot, generation16, owner32)` alanlarını taşımaktadır. Slot 37
`65,536` kez yeniden kullanıldığında generation tekrar `0xFFFE` olur; reconnect
sonrası owner `0x2A` da yeniden kullanılabilir. Eski ve yeni `FullSequence`
değerleri farklı olmasına rağmen truncated ticket eşleşir.

Asıl kusur yalnız sayaç genişliği değildir. Eski cancellation context'i detach
olmadan slotun `FREE` durumuna dönmesine izin verilmesi, stale aktörün yetkisini
farklı bir occupant yaşam döngüsüne taşır. Eski aktör yeni IRP'yi cancel yolunda
tamamladıktan sonra normal drain yolu da aynı IRP'yi tamamlar ve `[E-RING-05]`
oluşur.

Düzeltme; 64-bit occupant sequence, reusable olmayan session epoch, explicit
request reference, tek terminal CAS ve cancel rundown sıfırlanmadan slot reuse
yasağını birlikte gerektirir. Yalnız sayacı büyütmek yaşam döngüsü sorununu
çözmez.

Yerel model reduced-width generation ile bounded BFS yapmaktadır. Hatalı model
karşı örnek bulurken, düzeltilmiş model belirtilen depth bound içinde ihlal
bulmamaktadır. Bu ifade kasıtlı olarak sınırlıdır; evrensel formal proof iddiası
yoktur.

## 7. Deadlock analizi

T41 `g_SessionResource` nesnesini exclusive tutarken `g_DrainEvent` için sonsuz
beklemektedir. Event'i sinyalleyecek tek kalan thread T73'tür; T73 ise aynı
resource'u shared almak zorundadır. T41 bekleme bitmeden resource'u bırakamaz,
T73 resource'u almadan event'i sinyelleyemez. Service control thread'i de close
IOCTL içinde beklemektedir. Bu, alternatif progress yolu olmayan kapalı bir wait
cycle'dır `[E-LOCK-01]`–`[E-LOCK-04]`.

Düzeltme, `ACTIVE -> CLOSING` geçişini ve rundown başlangıcını resource altında
yapmalı; daha sonra resource'u bırakıp drain/rundown beklemesini dışarıda
gerçekleştirmelidir. Finalizasyon resource tekrar alındığında tek bir actor
tarafından yapılmalıdır. Timeout yalnız containment ve tanılama sağlar; live
work hâlâ referans tutarken serbest bırakma izni vermez.

## 8. OCVM2 uyuşmazlığı

Validator branch hedefini instruction indeksleriyle hesaplamaktadır:

```text
target = current_index + 1 + rel24
```

Tarihsel interpreter aynı `rel24` değerini byte olarak eklemektedir. Index 1'deki
`+1` branch validator için index 3, yani byte `0x18`; interpreter için byte
`0x11` üretir. `0x11`, `0x10`'da başlayan instruction'ın içidir ve deterministic
invalid-opcode fault'unu açıklar.

Düzeltilmiş disassembler ve reference interpreter aynı ortak target fonksiyonunu
kullanmaktadır. Program uzunluğu sekizin katı olmalı, instruction sayısı
sınırlandırılmalı, bütün opcode ve branch hedefleri execution öncesi
doğrulanmalı, üç byte displacement tam üç byte'tan okunmalı ve execution fuel
ile sınırlandırılmalıdır.

## 9. Self-integrity ve relocation

`0xA000` page block'unda `A118` ve `A2F0` iki `DIR64`, iki `0000` ise
`ABSOLUTE` padding girdisidir. `type <= DIR64` koşulu enumeration değerlerini
aralık gibi kullanarak padding'i de işler. Her zero entry page başlangıcı
`0xA000` üzerinde sekiz byte'lık yanlış normalizasyon yapar.

Delta sıfırken bu yanlış çıkarma byte'ları değiştirmez; nonzero ASLR delta
altında ilk farklı sayfanın `0xA000` olması beklenir. Correct relocation handling
sonrasında farklı executable byte kalmaması, dış patch hipotezini zayıflatır
`[E-INT-04]`.

Yerel araç gerçek synthetic mapped bytes üzerinde delta ekleyip çıkarmakta,
strict block/site bounds uygulamakta ve digest karşılaştırmaktadır. Model test
için SHA-256 kullanır; gerçek sürücünün hash algoritması kapsülde verilmediğinden
SHA-256 gerçek implementation'a atfedilmez.

## 10. Kök nedenlerin özeti

| ID | Kök neden | Ana kanıt | Güven |
|---|---|---|---:|
| RC-1 | 28-byte V2 ile native-offset/input-length sözleşmesi uyuşmazlığı | `[E-IO-03]`–`[E-IO-06]` | Yüksek |
| RC-2 | Stale cancel authority, truncated identity ve ABA reuse | `[E-RING-01]`–`[E-RING-06]` | Yüksek |
| RC-3 | Resource tutulurken resource-bağımlı drain beklenmesi | `[E-LOCK-01]`–`[E-LOCK-04]` | Yüksek |
| RC-4 | Branch displacement instruction/byte birim ayrılığı | `[E-VM-01]`–`[E-VM-04]` | Yüksek |
| RC-5 | `ABSOLUTE` padding'in `DIR64` gibi normalizasyonu | `[E-INT-01]`–`[E-INT-04]` | Yüksek |

Ayrıntılı trigger, alternatif açıklama, düzeltme, test ve residual-risk matrisi
`08_root_cause_matrix.md` içindedir.

## 11. Kırmızı herring değerlendirmesi

`0x9E3779B9` sabiti tek başına TEA veya malware kanıtı değildir; verilen tek
xref production path'e bağlı olmayan self-test descriptor'dür. GuardCF açık bir
PE'de `__guard_dispatch_icall_fptr` standart CFG davranışıdır. `KCAH` pool tag'inin
bir gösterimde `HACK` okunması ise nedensel davranış sunmaz. Bu üç gözlem için
reachable data flow ve runtime korelasyonu olmadan daha güçlü sınıflandırma
yapılamaz.

## 12. Düzeltme tasarımı

Düzeltmelerin ortak ilkesi, görünür byte veya bit eşitliğini nesne yaşam döngüsü
ve açık sözleşmeyle birleştirmektir:

- V2 compiler ABI yerine explicit byte protocol olarak korunur.
- Ring ticket full sequence, session epoch ve request reference taşır.
- Normal/cancel actor tek terminal state için yarışır; kaybeden tamamlamaz.
- Close state resource altında işaretlenir, blocking wait resource dışında olur.
- OCVM validator ve interpreter ortak target hesabı kullanır.
- Relocation türleri `switch` ile ele alınır; padding atlanır ve site sınırları
  doğrulanır.

Bu tasarımlar `09_patch_design.md` içinde semantic pseudocode olarak verilmiştir.
Kaynak bulunmadan binary patch veya compile-ready WDK değişikliği olduğu iddia
edilmemektedir.

## 13. Regresyon ve stres planı

Standart-library tabanlı suite, IOCTL round trip, bütün V2 truncation sınırları,
ABA karşı örneği, terminal-loser davranışı, OCVM signed target/fuel durumları ve
strict relocation parser sınırlarını kapsamaktadır. GitHub Actions aynı suite'i
Python 3.10–3.12 üzerinde çalıştıracak şekilde yapılandırılmıştır.

Gerçek kaynak daha sonra sağlanırsa ayrı Windows VM aşamasında WOW64/x64 protocol
testleri, hedefe özel Driver Verifier, reconnect/cancel stress, concurrent close,
shutdown ve ASLR integrity karşılaştırmaları eklenmelidir. Bu plan production
endpoint üzerinde test yetkisi vermez.

## 14. Kalan belirsizlikler

Şunlar mevcut kanıtla belirlenemez:

- gerçek unload ve error-unwind sırası;
- bütün IOCTL request/response yapıları ve durum kodları;
- tam IRQL, lock ve memory-barrier sözleşmesi;
- OCVM2'nin tüm opcode, register ve policy header formatı;
- gerçek digest algoritması ve hash edilen section listesi;
- capsule pseudocode'unun gerçek machine code ile birebirliği.

Bu nedenle araç sonuçları, kapsül mekanizmasının tutarlı yeniden üretimi olarak
okunmalı; görünmeyen bir sürücünün bağımsız adli doğrulaması olarak
yorumlanmamalıdır.

## 15. Sonuç

Vaka, ileri seviye görünmesine rağmen “gizemli kernel müdahalesi” varsayımına
ihtiyaç duymamaktadır. Her semptom daha küçük fakat ciddi bir sözleşme ihlaliyle
açıklanabilmektedir: yanlış wire ofseti, yaşam döngüsünden kopmuş kimlik,
kilit altında wait, farklı kontrol-akışı birimi ve hatalı relocation type
dispatch. En güvenilir çözüm yolu, bu beş alanı ayrı invariant ve testlerle
düzeltmek; daha sonra gerçek artefakt sağlanırsa sonuçları binary/dump düzeyinde
yeniden doğrulamaktır.
