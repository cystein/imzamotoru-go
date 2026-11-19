# Bağlantı Testi Modülü — Protokol (taslak, protokol 1)

> Durum: **TASLAK, Kolitakip ile mutabık** (2026-11-19). Simülatör hazır (§12); Windows gözlemcisi yazılıyor. Exe tarafı: KolitakipIMZA v1.6.0 hedefi. Bu belge exe (imzamotoru-go),
> eczane sayfası ve Kolitakip sunucusu arasındaki ortak sözleşmedir. Değişiklikler iki tarafın onayıyla yapılır.
> `[AÇIK]` ile işaretli maddeler henüz kararlaştırılmadı.

## 0. İlkeler

1. **Karar sunucuda.** Exe hiçbir zaman "geçti/kaldı" demez; yalnız ham, zaman damgalı gözlem raporlar. Exe'nin
   hesapladığı süreler (ör. `acilma_araligi_ms`) yalnız ham olayların farkıdır, eşikle karşılaştırılmaz.
2. **Eşikler sunucudan.** Tüm aralıklar/süreler `test_basla.parametreler` ile gelir. Exe'de yalnız varsayılanlar
   ve güvenlik sınırları (clamp) vardır; uygulanan değerler rapora yazılır.
3. **Sürümlü mesajlar.** Her mesajda `protokol` vardır. Alıcı bilinmeyen alanları **yok sayar**. Bilinmeyen `tip`
   gelirse `hata` (`GECERSIZ_MESAJ`) döner, bağlantı kapanmaz.
4. **Mevcut imza akışı değişmez.** Bağlantı testi mesajları `"modul": "baglanti_testi"` taşır. `modul` alanı olmayan
   mesajlar eskisi gibi imza modülüne gider (`action` alanıyla). İki modül ayrı goroutine'lerde çalışır; test
   sürerken imza atılabilir.
5. **Monotonik saat.** Tüm süreler test başlangıcına göre monotonik milisaniyedir (`mono_ms`). Duvar saati
   (`duvar`, RFC 3339, UTC, ms) yalnız denetim içindir.
6. **Gizlilik (KVKK).** Toplanmaz: SSID, tam MAC (yalnız ilk 3 bayt = OUI), kullanıcı adı, bilgisayar adı, süreç
   listesi, tarama geçmişi. Ayrıntı: §9.

## 1. Taşıma

- WebSocket: `ws://localhost:53911/ws` (imza ile aynı port ve aynı Local Network Access izin akışı).
- Origin denetimi: izinli listede olmayan origin bağlanamaz. Liste derlemede gömülüdür (§10). **Modül bazında:**
  eczane sitesi (`https://sgkkolitakip.web.tr`, `https://www.sgkkolitakip.web.tr`) yalnız `ping` ve bağlantı
  testini kullanabilir; imza işlemleri yalnız imza sitesinden kabul edilir (Kolitakip sitesindeki olası bir XSS
  kart/PIN akışına ulaşamasın).
- Bir test, onu başlatan WebSocket bağlantısına bağlı **değildir**: sayfa yenilenir ya da bağlantı koparsa test
  sürer (olay `sayfa_koptu`), sayfa `test_baglan` ile yeniden bağlanıp akışı sürdürür.
- Bağlantı testi bağlantısı uzun ömürlüdür; exe bu bağlantıya kendiliğinden (`durum`, `olay`) mesaj yazar.

## 2. Ortak alanlar

Sayfa → exe her mesajda:

| alan | tür | açıklama |
|---|---|---|
| `modul` | string | `"baglanti_testi"` |
| `protokol` | int | sayfanın konuştuğu protokol (şu an `1`) |
| `tip` | string | mesaj türü |
| `istek_no` | int | isteğe bağlı; yanıtta aynen döner |

Exe → sayfa her mesajda: `modul`, `protokol`, `tip`, varsa `istek_no`, test mesajlarında `test_id`.

## 3. El sıkışma

Önce mevcut `{"action":"ping"}` → `{"status":"success","data":{"version":"1.6.0"}}` çalışır. Sürümü
**1.6.0'dan eski** bir exe bağlantı testi mesajlarına cevap vermez; sayfa sürümü ping'den okuyup "güncelleyin" der.

```json
→ {"modul":"baglanti_testi","protokol":1,"tip":"merhaba"}
← {"modul":"baglanti_testi","protokol":1,"tip":"merhaba_yanit",
   "hazir":true,
   "exe_surum":"1.6.0",
   "desteklenen_protokoller":[1],
   "modul_durumu":"acik",
   "isletim_sistemi":{"ad":"windows","surum":"10.0.22631","mimari":"amd64"},
   "yetenekler":["arp","tcp_yoklama","arayuz_olaylari","guc_olaylari","upnp"],
   "aktif_test":null}
```

- `modul_durumu`: `acik` | `kapali_uzaktan` (latest.json `moduller.baglanti_testi.acik=false`) | `desteklenmiyor`
  (Windows dışı derleme, simülatör hariç).
- `hazir=false` ise `neden` alanında hata kodu bulunur (§7).
- `aktif_test`: sürmekte olan test varsa `{"test_id":"…","asama":"izleme|son_izleme|rapor"}`.
- Sunucu el sıkışmadaki `exe_surum`'u kendi asgari sürümüyle karşılaştırıp testi başlatmayabilir (sunucunun kararı).

## 4. Test başlatma ve ön kontrol

```json
→ {"modul":"baglanti_testi","protokol":1,"tip":"test_basla",
   "test_id":"t_8f3c…",                // sunucunun ürettiği, 8–64 karakter [A-Za-z0-9_-]
   "nonce":"b64url…",                  // sunucunun ürettiği tek kullanımlık değer, 16–128 karakter
   "olcum_hedefi":"203.0.113.10",      // yol ölçümü için sunucu IPv4'ü (yalnız GetBestRoute'a verilir)
   "beklenen_baglanti":"modem",        // "modem" | "hotspot" — eczacının beyanı, exe yalnız rapora kopyalar
   "rapor_hedefi":"canli",             // derlemede gömülü hedeflerden birinin ANAHTARI (§8.1)
   "parametreler":{ … §4.1 … }}
```

Exe yanıtı (ölçüm bitince, tipik 1–5 sn):

```json
← {"modul":"baglanti_testi","protokol":1,"tip":"on_kontrol","test_id":"t_8f3c…",
   "engeller":["COKLU_AKTIF_ARAYUZ"],     // boş olabilir; sunucu karar verir
   "on_kontrol":{ … §4.2 … },
   "uygulanan_parametreler":{ … }}
```

Ön kontrolden hemen sonra **izleme başlar** (`izleme_basladi` olayı). Sunucu ön kontrole göre teste devam etmek
istemezse sayfa `test_iptal` gönderir. Aynı anda ikinci `test_basla` → `TEST_ZATEN_CALISIYOR`.

### 4.1 Parametreler (hepsi isteğe bağlı)

| parametre | varsayılan | exe sınırı (clamp) | açıklama |
|---|---|---|---|
| `yoklama_araligi_ms` | 500 | 100–5000 | ağ geçidi yoklama aralığı (ARP ve TCP ayrı ayrı bu aralıkla) |
| `yoklama_zaman_asimi_ms` | 400 | 50–3000 | tek yoklamanın zaman aşımı (aralıktan büyükse aralığa çekilir) |
| `durum_araligi_ms` | 1000 | 250–5000 | sayfaya `durum` (kalp atışı) aralığı |
| `on_kontrol_yoklama_sayisi` | 6 | 1–50 | ön kontrolde ardışık yoklama sayısı |
| `tcp_portlari` | [80,443,53] | ≤5 port | ağ geçidine TCP bağlantı denemesi portları; `[]` = kapalı |
| `upnp` | true | — | UPnP IGD okuma denensin mi |
| `upnp_araligi_ms` | 5000 | 2000–60000 | UPnP okuma aralığı |
| `test_azami_suresi_ms` | 900000 | 60000–900000 | izleme aşamasının azami ömrü (15 dk sert sınır) |
| `son_izleme_suresi_ms` | 60000 | 0–600000 | `test_bitir` sonrası izleme penceresi |
| `rapor_yeniden_deneme_suresi_ms` | 900000 | 600000–86400000 | rapor POST'u bu süre boyunca yeniden denenir |
| `bosluk_esigi_ms` | 3 × aralık | — | yoklama zaman çizelgesinde bu kadar boşluk → `yoklama_boslugu` olayı (bilgi amaçlı; karar sunucuda) |

### 4.2 Ön kontrol içeriği

```json
"on_kontrol":{
  "olcum_zamani":{"mono_ms":0,"duvar":"2026-11-19T09:00:00.123Z"},
  "beklenen_baglanti":"modem",
  "yol":{"hedef":"203.0.113.10","bulundu":true,"arayuz_no":12,"ag_gecidi":"192.168.1.1","metrik":35},
  "test_arayuzu":{
     "no":12, "ad":"Ethernet", "aciklama":"Realtek PCIe GbE Family Controller",
     "tur":"ethernet",                 // ethernet | wifi | mobil | sanal | tunel | diger
     "if_type":6, "medya":"802.3",     // ham Windows değerleri
     "hiz_bps":1000000000, "durum":"up",
     "ipv4":["192.168.1.34/24"], "dhcp":true,
     "dhcp_kira_suresi_s":86400,          // DHCP ile alınmadıysa null
     "dhcp_kira_baslangic":"2026-11-19T06:00:00Z"
  },
  "ag_gecidi":{"ipv4":"192.168.1.1","oui":"A4:2B:B0","ozel_aralik":true},
  "arp":{"deneme":6,"cevap":6,"sureler_ms":[2,1,1,1,1,1],"onbellek_durumu_once":"reachable"},
  "tcp":{"80":{"deneme":6,"acik":6},"443":{"deneme":6,"acik":0,"reddedildi":6},"53":{"deneme":6,"acik":6}},
  "aktif_arayuzler":[
     {"no":12,"tur":"ethernet","aciklama":"Realtek…","ag_gecidi":"192.168.1.1","varsayilan_yol":true,"metrik":35},
     {"no":18,"tur":"wifi","aciklama":"Intel Wi-Fi 6 AX201","ag_gecidi":"192.168.1.1","varsayilan_yol":true,"metrik":55}
  ],
  "vpn":{"var":false,"varsayilan_yol_vpn":false,"arayuzler":[]},
  "hotspot_ipuclari":[],              // ör. "AG_GECIDI_BILINEN_HOTSPOT_ADRESI", "ARAYUZ_RNDIS", "ARAYUZ_WWAN"
  "ikinci_yonlendirici":{"ipucu":"yok","ikinci_atlama":"85.105.1.1","ikinci_atlama_ozel":false},   // bilgi amaçlı, §4.4
  "upnp":{"durum":"yok"}             // ya da {"durum":"var","uptime_s":86123,"baglanti":"Connected","dis_ip":"…"}
}
```

### 4.3 Ön kontrol engel kodları (`engeller`)

Exe bunları yalnız **raporlar**; teste devam kararı sunucunundur.

| kod | anlamı |
|---|---|
| `VARSAYILAN_YOL_YOK` | `olcum_hedefi`'ne IPv4 yolu yok |
| `AG_GECIDI_YOK` | yol doğrudan bağlı (ağ geçidi 0.0.0.0) — ör. PPP/mobil geniş bant |
| `AG_GECIDI_ERISILEMEZ` | ön kontrolde ARP **ve** TCP yoklamalarının hiçbiri cevap almadı |
| `ARP_DESTEKLENMIYOR` | test arayüzü ARP kullanmıyor (WWAN/PPP/tünel); yalnız TCP yoklaması raporlanır |
| `VPN_VARSAYILAN_YOLDA` | varsayılan yol bir VPN/TAP/tünel arayüzünden geçiyor |
| `VPN_ARAYUZU_VAR` | yukarıda bir VPN/TAP/tünel arayüzü var (yol üzerinde olmasa da) |
| `COKLU_AKTIF_ARAYUZ` | varsayılan yolu olan birden fazla "up" arayüz var (ör. Wi-Fi + kablo) |
| `SANAL_ARAYUZ` | test arayüzü sanal (Hyper-V, VirtualBox vb.) |
| `HOTSPOT_IPUCU` | `hotspot_ipuclari` boş değil (beklenen_baglanti ile çelişip çelişmediğine sunucu bakar) |
| `IPV4_YOK` | test arayüzünde IPv4 yok |

### 4.4 İkinci yönlendirici ipucu (bilgi amaçlı)

`ikinci_yonlendirici.ipucu`: `yok` | `olasi` | `bilinmiyor`, kanıtlarıyla:
- UPnP `dis_ip` özel aralıkta (10/8, 172.16/12, 192.168/16) veya CGNAT (100.64/10) → `olasi`, `kanit:"upnp_dis_ip_ozel"`.
- TTL=2 ICMP yankısıyla (ön kontrolde tek ölçüm, Windows'ta yönetici gerektirmez) ikinci atlama adresi okunur:
  `ikinci_atlama` (IPv4 ya da null), `ikinci_atlama_ozel`. Özel aralıktaysa → `olasi`, `kanit:"ikinci_atlama_ozel"`.
  ICMP ağ geçidi erişilebilirliği için **kullanılmaz**; yalnız bilgi amaçlıdır (Kolitakip onayı 2026-11-19).

## 5. İzleme

### 5.1 Yoklamalar

- **ARP:** her `yoklama_araligi_ms`'de bir, zaman aşımı `yoklama_zaman_asimi_ms`, ayrı goroutine + deadline
  (takılan yoklama sonrakini bekletmez; üst üste binen yoklama `atlandi` sayılır).
- **TCP:** aynı aralıkla, `tcp_portlari`'ndaki her porta kısa `connect`. Sonuç: `acik` (bağlandı), `reddedildi`
  (RST — cihaz CANLI demektir), `zaman_asimi`, `hata`. **ARP ve TCP ayrı raporlanır**; birleştirilmiş tek bir
  "ağ geçidi var/yok" yalnız canlı ekran içindir (§5.3) ve raporda ham sonuçlar ayrıca bulunur.
- **ARP önbelleği:** Windows'ta yönetici hakkı olmadan önbellek kaydını silmek mümkün değil; `SendARP`/
  `ResolveIpNetEntry2` geçerli bir kayıt varken yeni istek göndermeden dönebilir. Exe her ARP sonucunun yanında
  çağrı öncesi önbellek durumunu (`reachable|stale|probe|incomplete|unreachable|yok`) raporlar. **Taze ARP
  garantisi, gerçek makinede ölçülene kadar İDDİA EDİLMEZ** (test matrisi satır 11).

### 5.2 Olaylar (`olay`)

Olaylar gerçekleştikçe sayfaya itilir ve rapora girer:

```json
← {"modul":"baglanti_testi","protokol":1,"tip":"olay","test_id":"t_8f3c…",
   "olay":{"sira":17,"mono_ms":48210,"duvar":"2026-11-19T09:00:48.333Z","kod":"kart_dustu",
           "veri":{"arayuz_no":12,"tur":"ethernet","neden":"medya_baglantisi_yok"}}}
```

| kod | ne zaman | `veri` |
|---|---|---|
| `izleme_basladi` | ön kontrol bitti | `test_arayuzu_no`, `ag_gecidi` |
| `kart_dustu` | test arayüzü OperStatus up → başka | `arayuz_no`, `tur`, `neden` (`medya_baglantisi_yok`, `devre_disi`, `radyo_kapali`, `bilinmiyor`) |
| `kart_geldi` | test arayüzü yeniden up | `arayuz_no` |
| `ipv4_kayboldu` / `ipv4_geldi` | test arayüzünün IPv4 adresi silindi/eklendi (DHCP) | `adres` (yalnız yerel özel adres) |
| `ag_gecidi_kayip` | birleşik yoklama ilk kez cevapsız (ARP yok **ve** TCP yok) | `son_cevap_mono_ms` |
| `ag_gecidi_geri` | kayıptan sonra ilk cevap | `kaynak` (`arp`/`tcp`), `kayip_suresi_ms` |
| `arp_kayip` / `arp_geri` | yalnız ARP'nin geçişleri | — |
| `tcp_kayip` / `tcp_geri` | yalnız TCP'nin geçişleri | `port` |
| `ag_gecidi_mac_degisti` | ağ geçidi OUI değişti (başka cihaz) | `onceki_oui`, `yeni_oui` |
| `yol_degisti` | `olcum_hedefi`'ne yol başka arayüz/ağ geçidine döndü | `onceki`, `yeni` |
| `arayuz_degisti` | başka bir arayüz up/down oldu ya da varsayılan yolu değişti | `arayuz_no`, `tur`, `durum` |
| `vpn_belirdi` / `vpn_kayboldu` | VPN/TAP/tünel arayüzü up/down | `aciklama` |
| `uyku` / `uyanma` | sistem uyku/hazırda bekleme ve dönüş (kapak kapatma dahil) | `tur` |
| `saat_atlamasi` | duvar saati monotonik saate göre > 2 sn kaydı | `fark_ms` |
| `yoklama_boslugu` | iki yoklama arasında `bosluk_esigi_ms`'den uzun boşluk | `bas_mono_ms`, `bit_mono_ms` |
| `upnp_uptime_sifirlandi` | UPnP Uptime öncekinden küçük | `onceki_s`, `yeni_s` |
| `upnp_dis_ip_degisti` | UPnP dış IP değişti | `onceki`, `yeni` |
| `upnp_baglanti_durumu` | ConnectionStatus değişti | `durum` |
| `sayfa_baglandi` / `sayfa_koptu` | WebSocket bağlantısı | — |
| `test_bitir_istendi` | `test_bitir` alındı | `kaynak` (`sayfa`/`zaman_asimi`) |
| `ag_gecidi_hic_kaybolmadi` | izleme aşaması bitti ve tek bir `ag_gecidi_kayip` yok | — |
| `son_izleme_basladi` / `son_izleme_bitti` | — | — |
| `program_yeniden_baslatildi` | exe test sürerken kapanıp yeniden açıldı (yarım test bulundu) | `son_bilinen_mono_ms` |
| `test_iptal` | `test_iptal` alındı | — |
| `ic_hata` | gözlemcide beklenmeyen hata | `mesaj` |

### 5.3 Canlı durum / kalp atışı (`durum`)

Her `durum_araligi_ms`'de bir (varsayılan 1 sn). Sayfa ardışık iki `durum` arasında `3 × durum_araligi_ms`'den
uzun boşluk görürse testi **geçersiz** sayar (kaçış önleme; karar sayfada/sunucuda).

```json
← {"modul":"baglanti_testi","protokol":1,"tip":"durum","test_id":"t_8f3c…",
   "sira":63,"mono_ms":63004,"asama":"izleme",       // izleme | son_izleme | rapor
   "kart":"kapali",                                   // acik | kapali
   "ag_gecidi":"yok",                                 // var | yok | bilinmiyor (ARP veya TCP cevabı = var)
   "arp":"yok","tcp":"yok",
   "kart_kapali_suresi_ms":14800,                     // bu kesintinin şu ana kadarki süresi (kart açıksa 0)
   "ag_gecidi_kayip_suresi_ms":15300,                 // bu kesintinin şu ana kadarki süresi (geri geldiyse 0)
   "toplam_kart_kapali_ms":14800,"toplam_ag_gecidi_kayip_ms":15300,
   "kalan_ms":836996}
```

Süreler **exe'nin monotonik saatiyle** ölçülür; sayfa kendi saatini kullanmaz.

## 6. Bitiş ve rapor

```json
→ {"modul":"baglanti_testi","protokol":1,"tip":"test_bitir","test_id":"t_8f3c…"}
← {"modul":"baglanti_testi","protokol":1,"tip":"test_bitir_yanit","test_id":"t_8f3c…","son_izleme_ms":60000}
→ {"modul":"baglanti_testi","protokol":1,"tip":"test_iptal","test_id":"t_8f3c…"}
← {"modul":"baglanti_testi","protokol":1,"tip":"test_iptal_yanit","test_id":"t_8f3c…","son_izleme_ms":0}
→ {"modul":"baglanti_testi","protokol":1,"tip":"test_baglan","test_id":"t_8f3c…"}   // yeniden bağlanma
← {"modul":"baglanti_testi","protokol":1,"tip":"test_baglan_yanit","test_id":"t_8f3c…","olaylar":[…şu ana kadarki tüm olaylar…]}
```

- `test_bitir` ya da `test_azami_suresi_ms` dolunca → `son_izleme` aşaması (`son_izleme_suresi_ms`) → rapor.
- `test_iptal` → izleme hemen durur, rapor yine gönderilir (`rapor_turu:"iptal"`); sunucu iptali kaydeder.
- Rapor hazırlanınca exe **kendi HTTPS isteğiyle** sunucuya POST eder (§8) ve sayfaya bildirir:

```json
← {"modul":"baglanti_testi","protokol":1,"tip":"rapor_durumu","test_id":"t_8f3c…",
   "durum":"gonderildi",            // hazirlaniyor | gonderiliyor | gonderildi | kuyrukta | reddedildi | vazgecildi
   "deneme":1,"http":200,"govde_sha256":"…"}
```

`govde_sha256` = imzalanan rapor baytlarının SHA-256'sı (sunucu aynı değeri hesaplayıp sayfaya gösterebilir).

**Boyut sınırı:** POST gövdesi en çok **512 KB** (base64 sonrası). Aşılırsa yoklama dizileri giderek
kabalaştırılır: kısa diziler `"sonuc":"karisik","dagilim":{"cevap":n,"yok":m}` olarak birleşir ve
`yoklamalar.kabalastirma_ms` yazılır; yine de aşarsa `yoklamalar:{"cikarildi":"boyut_siniri"}` (olaylar ve
kesintiler her zaman kalır). Olay sayısı en çok 5000; aşılırsa son olay `olay_siniri_asildi`.

### 6.1 Rapor içeriği (imzalanan JSON)

```json
{
 "protokol":1,
 "rapor_turu":"nihai",                  // nihai | iptal | yarim (program yeniden başlatıldı)
 "test_id":"t_8f3c…","nonce":"…",
 "exe":{"surum":"1.6.0","isletim_sistemi":{…},"simulasyon":null},   // simülatörde senaryo adı
 "beklenen_baglanti":"modem",
 "parametreler":{"istenen":{…},"uygulanan":{…}},
 "zaman":{"baslangic_duvar":"…Z","bitis_mono_ms":201550,"izleme_bitis_mono_ms":141550},
 "on_kontrol":{…},  "engeller":[…],
 "olaylar":[ {sira,mono_ms,duvar,kod,veri}, … ],
 "yoklamalar":{                          // ham yoklamalar, aynı sonuçlar art arda gelince birleştirilir (RLE)
   "arp":[ {"bas":0,"bit":47900,"sonuc":"cevap","adet":96,"onbellek_once":"reachable"}, {"bas":48400,"bit":…,"sonuc":"yok","adet":…}, … ],
   "tcp":{"80":[ … ], "53":[ … ]}
 },
 "kesintiler":[                          // olaylardan türetilmiş ham aralıklar (karar YOK)
   {"kart_dustu":48210,"kart_geldi":163400,"ag_gecidi_kayip":48390,"ag_gecidi_geri":201100,
    "kart_kapali_ms":115190,"ag_gecidi_kayip_ms":152710,"acilma_araligi_ms":37700}
 ],
 "ozet":{"ag_gecidi_hic_kaybolmadi":false,"toplam_kart_kapali_ms":115190,"toplam_ag_gecidi_kayip_ms":152710,
         "yoklama_bosluklari":0,"uyku":false,"vpn":false,"yol_degisti":false,"sayfa_koptu":0},
 "son_izleme":{"bas":141550,"bit":201550,"ag_gecidi_kayip_sayisi":0,"kart_dustu_sayisi":0,"yol_degisti":false},
 "upnp":{"durum":"yok"}
}
```

`acilma_araligi_ms = ag_gecidi_geri − kart_geldi` (kart geri geldikten sonra ağ geçidinin cevap vermesine kadar
geçen süre). Kart hiç düşmediyse `null`. Ağ geçidi kart geri gelmeden döndüyse negatif olabilir — olduğu gibi raporlanır.

## 7. Hata kodları (`tip:"hata"`)

```json
← {"modul":"baglanti_testi","protokol":1,"tip":"hata","istek_no":3,"kod":"TEST_ZATEN_CALISIYOR","mesaj":"…"}
```

| kod | anlamı |
|---|---|
| `PROTOKOL_DESTEKLENMIYOR` | `protokol` exe'nin `desteklenen_protokoller`'inde yok |
| `MODUL_KAPALI` | latest.json'da modül uzaktan kapatılmış |
| `PLATFORM_DESTEKLENMIYOR` | Windows dışı gerçek mod |
| `GECERSIZ_MESAJ` | JSON bozuk ya da bilinmeyen `tip` |
| `GECERSIZ_PARAMETRE` | `test_id`/`nonce` biçimi geçersiz, `rapor_hedefi` bilinmiyor, `olcum_hedefi` IPv4 değil |
| `TEST_ZATEN_CALISIYOR` | aynı anda ikinci test |
| `TEST_YOK` | `test_id` aktif testle eşleşmiyor |
| `NONCE_TEKRAR` | bu exe bu nonce'u daha önce kullandı (son 100 nonce yerelde tutulur; asıl denetim sunucuda) |
| `IC_HATA` | beklenmeyen hata (ayrıntı yerel günlükte) |

Ayrıca modül dışı: `modul` bilinmiyorsa `{"modul":…,"tip":"hata","kod":"BILINMEYEN_MODUL"}`; eczane origin'inden
imza işlemi istenirse eski biçimde `{"status":"error","error":"Bu sayfa imza işlemi başlatamaz."}`.

## 8. Exe → sunucu rapor POST'u

### 8.1 Hedef

- Exe yalnız **derlemede gömülü** hedeflere POST eder. Sayfa yalnız anahtarı seçer (`rapor_hedefi`):
  - `canli` → `https://sgkkolitakip.web.tr/statik_ip_ag.php` (Kolitakip teyidi 2026-11-19; uç Kolitakip'te yazılıyor)
  - Ayrı test ucu yok. Simülatörde `--rapor-url` ile yerel bir adres verilir (yalnız `--simule` modunda, yalnız
    test anahtarıyla).

### 8.2 İstek

```
POST <hedef>
Content-Type: application/json
User-Agent: KolitakipIMZA/1.6.0 (baglanti_testi; protokol 1)

{"protokol":1,"test_id":"t_8f3c…","anahtar_no":1,"govde_b64":"<base64(rapor JSON baytları)>","imza":"<hex>"}
```

- `imza = hex( HMAC-SHA256( anahtar[anahtar_no], nonce_baytları || 0x0A || rapor_baytları ) )`
  - `nonce_baytları`: `test_basla.nonce` dizgesinin UTF-8 baytları.
  - `rapor_baytları`: `govde_b64`'ün base64 çözülmüş **ham baytları**. Sunucu imzayı JSON'u yeniden
    serileştirerek değil, **gelen baytlar üzerinden** doğrular → kanonikleştirme sorunu yok.
- `anahtar_no`: anahtar sürümü (rotasyon). Sunucu aynı anda birden çok sürümü kabul edebilir. Exe derlemede tek bir
  `(anahtar_no, anahtar)` çifti taşır. Anahtar kaynak kodda **yoktur**; GitHub Actions secret'ından `-ldflags`
  (`main.btAnahtarHex`, `main.btAnahtarNo`) ile enjekte edilir.
- **`anahtar_no: 0`** = herkese açık test anahtarı `kolitakip-baglanti-testi-simulator-anahtari` (UTF-8 baytları).
  Simülatör ve anahtar enjekte edilmemiş derleme bunu kullanır. **Canlı uç `0`'ı her zaman reddeder.**
- Güncel durum (2026-11-19, kullanıcı kararı): gerçek anahtarı **Kolitakip oturumu üretir**, sunucuya kendisi koyar,
  kullanıcıya verir; kullanıcı GitHub secret'larına ekler. Eklenene kadar derlemeler `anahtar_no: 0`. Kod imzalama
  sertifikası şimdilik yok. Gerçek donanım doğrulaması kullanıcının güvendiği bir eczanede yapılacak.
- Test vektörü: `HMAC-SHA256(anahtar="anahtar", "nonce123" || 0x0A || '{"a":1}')` =
  `21c56838b9811d13dd75f2a3c3d588c59230bf3a3a1c82cb39f61b4f30ddd345`
- Gövde base64'tür: .103'teki ModSecurity ham dosya yolu/komut benzeri metinlere 403 veriyor (EL_KITABI §9.16).
- Sunucu ayrıca `test_id` + `nonce` eşleşmesini, nonce'un tek kullanımlığını ve **isteğin kaynak IP'sinin
  tarayıcı IP'siyle aynı olduğunu** denetler (exe ile tarayıcı aynı bağlantıda).

### 8.3 Yanıt ve yeniden deneme

| sunucu yanıtı | exe davranışı |
|---|---|
| 200 `{"ok":true}` | `gonderildi`; kuyruktan sil |
| 409 (nonce kullanılmış / test kapalı) | `reddedildi`; yeniden deneme YOK |
| 400/401/403/404/413 | `reddedildi`; yeniden deneme yok; HTTP kodu ve gövdenin ilk 200 baytı günlüğe |
| 429, 5xx, ağ hatası, zaman aşımı | `kuyrukta`; üstel geri çekilme 2 s → 4 → 8 … en çok 60 s, `rapor_yeniden_deneme_suresi_ms` boyunca |

- Kuyruk diske yazılır (`%LOCALAPPDATA%\KolitakipIMZA\baglanti_testi\kuyruk\`); exe yeniden başlarsa kaldığı
  yerden dener. Süre dolarsa `vazgecildi`.
- 403'te yeniden deneme yok; eimza olay-bildir ucuna tek bir `RAPOR_403` bildirimi gider. İçeriği yalnız kod +
  exe sürümü + `test_id` (SSID/MAC/IP yok).

## 9. Toplanan veri (kullanıcıya gösterilecek açıklama metni taslağı)

> **Bağlantı testi sırasında bilgisayarınızdan ne toplanır?**
> Test yalnız siz başlattığınızda çalışır ve en çok 15 dakika sürer. Bu sürede KolitakipIMZA, internete hangi ağ
> kartıyla bağlandığınızı (kablo, Wi-Fi, mobil), modeminizin yerel adresini ve modem üreticisini gösteren kısa
> kimliği, modemin cevap verip vermediğini ve bağlantının ne zaman kesilip geri geldiğini kaydeder. Bu bilgiler
> yalnız Kolitakip sunucusuna gönderilir. Kablosuz ağ adınız (SSID), cihazlarınızın tam donanım adresleri,
> bilgisayar adınız, kullanıcı adınız, açık programlarınız ve gezinme geçmişiniz **toplanmaz**.

## 10. Yapılandırma

Derlemede gömülü (kaynakta varsayılanlar, `-ldflags` ile ezilebilir):

```
imza modülü originleri        = https://eimza.sgkkolitakip.web.tr, https://itiraz.sgkkolitakip.web.tr, http://localhost:3000
bağlantı testi originleri     = https://sgkkolitakip.web.tr, https://www.sgkkolitakip.web.tr, http://localhost:3000
                                (+ simülatörde --origin ile eklenenler)
rapor_hedefleri               = canli=https://sgkkolitakip.web.tr/statik_ip_ag.php
imza_anahtari                 = GitHub secret BAGLANTI_TESTI_HMAC_ANAHTARI (hex, ≥16 bayt) → -X main.btAnahtarHex
anahtar_no                    = GitHub secret BAGLANTI_TESTI_ANAHTAR_NO → -X main.btAnahtarNo
```

Uzaktan (latest.json, eski exe bilinmeyen alanı yok sayar):

```json
"moduller":{"baglanti_testi":{"acik":true,"min_surum":"1.6.0"}}
```

`acik:false` ya da exe sürümü `min_surum`'dan eskiyse modül kapanır (`merhaba_yanit.modul_durumu:"kapali_uzaktan"`,
`test_basla` → `MODUL_KAPALI`); imza çalışmaya devam eder. Exe latest.json'ı açılışta ve 6 saatte bir okur.

## 11. Yerel günlük

`%LOCALAPPDATA%\KolitakipIMZA\baglanti_testi\` altında son 20 testin raporu (imzalanan JSON aynen) + çalışma
günlüğü (dönen dosya). Tepsi menüsü: "Tanı dosyalarını kopyala" → bu klasörü zip'leyip masaüstüne koyar.
Kullanıcı adı / SSID / tam MAC içermez.

## 11.2 Windows gözlemcisinin ayrıntıları (DOĞRULANMADI — saha testi bekleniyor)

- Yol: `GetBestRoute` (IPv4). Arayüzler: `GetAdaptersAddresses` + `GetIfEntry2Ex` (AdminStatus, MediaConnectState),
  varsayılan yollar `GetIpForwardTable2`. DHCP kirası: `GetAdaptersInfo`.
- ARP: `SendARP` (en çok bir istek uçuşta; uçuştayken gelen tur `atlandi`), öncesinde `GetIpNetEntry2` ile
  komşu durumu (`onbellek_once`). TCP: `connect` + zaman aşımı; WSAECONNREFUSED → `reddedildi`.
- Olaylar: `NotifyIpInterfaceChange`/`NotifyUnicastIpAddressChange` yalnız uyandırır; asıl fark her yoklama
  turunda arayüz/yol tablosu yeniden okunarak bulunur (bildirim kaçsa bile). Kart düşme nedeni:
  arayüz kayboldu/NotPresent/Admin kapalı → `devre_disi`; MediaConnectState bağlı değil/Oper down → `medya_baglantisi_yok`.
- Uyku: `PowerRegisterSuspendResumeNotification` (pencere gerektirmez) → `uyku`/`uyanma`. Ayrıca motor her kalp
  atışında duvar saatini monotonik saatle karşılaştırır; 2 sn'den fazla fark → `saat_atlamasi` (Windows'ta monotonik
  saat uykuyu saymayabilir; uyku bu yolla da görünür).
- Hotspot ipuçları: bilinen ağ geçidi adresleri, RNDIS/Apple açıklamaları, WWAN, ve ağ geçidinin MAC'i yerel yönetimli
  (telefonların rastgele MAC'i) → `AG_GECIDI_RASTGELE_MAC`; `ag_gecidi.yerel_yonetimli_mac`.
- TTL=2: `IcmpSendEcho` (ön kontrolde tek ölçüm). UPnP: SSDP M-SEARCH (test arayüzünün adresinden), yalnız
  özel adresli IGD'ler; GetStatusInfo + GetExternalIPAddress.
- Bilinen Windows davranışı: kapalı porta TCP bağlantısı RST sonrası yeniden denendiği için ~1–2 sn sürebilir;
  kısa zaman aşımında `reddedildi` yerine `zaman_asimi` görünebilir.

## 12. Simülatör

```
KolitakipIMZA --simule <senaryo> [--hiz 10] [--rapor-url http://localhost:8080/…] [--port 53911]
KolitakipIMZA --simule liste
```

Simülatör **gerçek protokol kodunu** (WebSocket işleyici, olay motoru, durum/kalp atışı, rapor, imza, POST,
kuyruk) kullanır; yalnız ağ gözlemcisi yerine senaryo oynatıcısı takılır. Linux'ta da çalışır. Rapordaki
`exe.simulasyon` alanı senaryo adını taşır (sunucu canlıda simülasyon raporunu reddetmeli).

| senaryo | ne üretir |
|---|---|
| `d1_modem_guc` | kablolu; kart düşer (~2 dk), kart gelir, ağ geçidi ~40 sn sonra döner (uzun açılma aralığı) |
| `d2_kablo_cek` | kart düşer ~20 sn, gelir, ağ geçidi ~1 sn sonra |
| `d3_wifi_kes` | Wi-Fi bağlantı kes/bağlan; kısa aralık |
| `d3b_kart_devre_disi` | kart devre dışı/etkin; `neden:"devre_disi"`, kısa aralık |
| `d4_router_arkasi` | ağ geçidi hiç kaybolmaz, kart düşmez; `ag_gecidi_hic_kaybolmadi`; UPnP dış IP özel |
| `d5_hotspot_ucus` | ağ geçidi 192.168.43.1, `HOTSPOT_IPUCU`; uçuş modunda Wi-Fi düşer |
| `d5b_usb_rndis` | RNDIS arayüzü, `ARAYUZ_RNDIS` |
| `d6_vpn` | ön kontrolde `VPN_VARSAYILAN_YOLDA` |
| `d6_coklu_kart` | Wi-Fi + kablo, `COKLU_AKTIF_ARAYUZ` |
| `d6_uyku` | izleme sırasında `uyku`/`uyanma` + `yoklama_boslugu` |
| `d6_program_kapatildi` | kalp atışı kesilir; yeniden açılışta `program_yeniden_baslatildi` + `rapor_turu:"yarim"` |
| `son_izleme_dalgalanma` | d1 + son izlemede ağ geçidi bir kez kaybolup gelir |
| `rapor_kuyrukta` | ilk 3 POST ağ hatası, sonra başarı |
| `upnp_sifirlandi` | d1 + UPnP: modem açılınca `upnp_uptime_sifirlandi`, dış IP aynı |
| `upnp_dis_ip_degisti` | d1 + UPnP: `upnp_uptime_sifirlandi` + `upnp_dis_ip_degisti` (statik değil) |

Senaryolarda `bitir` süresi dolunca simülatör testi kendisi bitirir (sayfa `test_bitir` göndermese de);
`d6_program_kapatildi` hiç bitmez, 15 sn kalp atışı kesildikten sonra `yarim` rapor gönderir.

Örnek (Kolitakip geliştirme makinesinde, 10 kat hızlı, rapor yerel uca):

```
./imzaci --simule d1_modem_guc --hiz 10 --rapor-url http://localhost:8080/statik_ip_ag.php --origin http://localhost:8080
```

Simülatör gerçek KolitakipIMZA ile aynı portu (53911) kullanır; gerçek program açıksa `--port` ile başka port verin.
Uçtan uca testler: `go test -run TestSimulatorSenaryolari` (tüm senaryolar, sahte sunucu HMAC doğrulamasıyla).
