# Bağlantı Testi — Eczanede Saha Doğrulama Kılavuzu

Bu kılavuz, bağlantı testi modülünü yayından önce **gerçek bir eczane bilgisayarında** denemek içindir.
Amaç, programın modem kapatma, kablo çekme, Wi-Fi ve hotspot gibi durumları doğru ayırt ettiğini görmek.
Test yaklaşık **1–1,5 saat** sürer. İnternet testler sırasında birkaç kez kesilecek; eczanenin yoğun
olmadığı bir saatte yapın (Medula'da açık işlem olmasın).

## Hazırlık

1. Kolitakip'ten gelen **`KolitakipIMZA-teshis.exe`** dosyasını masaüstüne kopyalayın.
   - Bu dosya, bilgisayarda kurulu KolitakipIMZA'yı **değiştirmez**; e-imza normal çalışmaya devam eder.
   - Windows "bilinmeyen yayıncı" uyarısı verirse: **Ek bilgi → Yine de çalıştır.**
2. Masaüstündeki dosyaya **çift tıklayın**. Siyah bir pencere açılır ve "ÖN KONTROL" yazar.
3. Pencerede **"İzleme başladı. Test adımını şimdi yapın."** yazınca aşağıdaki adımlardan birini yapın.
4. Adım bitince bir dakika bekleyin, sonra pencereye tıklayıp **Enter**'a basın. Program bir dakika daha
   izler ve **masaüstüne `kolitakip_baglanti_….json`** dosyasını kaydeder.
5. Pencerede "Kapatmak için Enter'a basın" yazınca Enter'a basın.
6. **Her adım için programı yeniden açın** (her adım ayrı bir dosya üretir). Dosya adlarını değiştirmeyin;
   hangi adımın hangi saatte yapıldığını aşağıdaki tabloya yazın.

> Toplanan bilgi: ağ kartının türü ve adı, modemin yerel adresi ve üretici kısa kodu, modemin cevap
> verip vermediği, bağlantının ne zaman kesilip geldiği. Kablosuz ağ adı, tam donanım adresleri,
> bilgisayar adı, kullanıcı adı **toplanmaz**.

## Adımlar

Her satırda: programı açın → "İzleme başladı" yazısını bekleyin → **10 sn bekleyin** → adımı yapın →
her şey normale dönünce **1 dk bekleyin** → Enter.

| # | Bağlantı | Yapılacak | Not alın |
|---|---|---|---|
| 1 | Kablolu (bilgisayar modeme kabloyla bağlı) | Modemin **elektrik fişini çekin**, **2 dakika** bekleyin, takın. Modemin ışıkları oturup internet gelene kadar bekleyin. | Fişi çektiğiniz ve taktığınız saat |
| 2 | Kablolu | Bilgisayarın arkasındaki **ağ kablosunu çekin**, 20 sn bekleyin, takın. | Saatler |
| 3 | Wi-Fi | Sağ alttaki Wi-Fi simgesinden ağın **bağlantısını kesin**, 20 sn bekleyin, yeniden **bağlanın**. | Saatler |
| 4a | Wi-Fi | Sağ alttan **Wi-Fi'yi kapatın** (ya da Uçak modu), 20 sn bekleyin, açın. | Saatler |
| 4b | Herhangi | **Ayarlar → Ağ → Bağdaştırıcı seçenekleri** → ağ kartına sağ tık **Devre dışı bırak**, 20 sn sonra **Etkinleştir**. | Saatler |
| 5 | Modemin arkasında ayrı bir router/erişim noktası varsa | Bilgisayar router'a bağlıyken **yalnız modemin** fişini 2 dk çekip takın (router açık kalsın). | Saatler; böyle bir düzen yoksa "yok" yazın |
| 6 | Telefon hotspot | Bilgisayarı telefonun **kişisel erişim noktasına** bağlayın, programı açın; telefonda **uçak modunu** açın, 20 sn sonra kapatın. | Telefon markası; saatler |
| 7 | Telefon USB | Telefonu USB kabloyla takıp **USB internet paylaşımını** açın; programı açın, 1 dk sonra Enter. | Telefon markası |
| 8 | VPN | Bilgisayarda bir VPN programı varsa açın, programı çalıştırın, 1 dk sonra Enter. | VPN adı; yoksa "yok" |
| 9 | Kablo + Wi-Fi | Kablo takılıyken Wi-Fi'ye de bağlanın; programı açın, 1 dk sonra Enter. | — |
| 10a | Uyku | Programı açın, **Başlat → Güç → Uyku**; 1 dk sonra bilgisayarı uyandırın, 1 dk bekleyin, Enter. | Saatler |
| 10b | Kapak (dizüstü) | Kapağı kapatın, 1 dk sonra açın. | Saatler |
| 10c | Program kapatma | Program izlerken **pencereyi kapatın (X)**; 1 dk sonra programı yeniden açın, ön kontrol bitince Enter. | Saatler |
| 11 | ARP önbelleği | Bilgisayar ile modem arasında bir **ağ anahtarı (switch / çoklu priz gibi ağ dağıtıcı)** ya da modeme bağlı ayrı bir **Wi-Fi erişim noktası** varsa: programı açın, **yalnız modemin** fişini 2 dk çekip takın (dağıtıcı/erişim noktası açık kalsın). Bilgisayarın bağlantı ışığı yanmaya devam etmeli. | Saatler; böyle bir düzen yoksa "yok" |
| 12 | Modem markası | Satır 1'i **farklı marka/tür modemlerde** (en az 3: ör. ADSL, VDSL, fiber) tekrarlayın. | Modem marka/modeli, hat türü |
| 13 | E-imza | Testlerden sonra eimza sayfasından **normal bir imza** atın. | İmza sorunsuz mu |

## Sonuçları gönderme

Masaüstündeki tüm `kolitakip_baglanti_….json` dosyalarını ve doldurduğunuz tabloyu Kolitakip'e gönderin.
Sorun olursa ayrıntılı günlük şurada: `%LOCALAPPDATA%\KolitakipIMZA\baglanti_testi\teshis.log`
(Başlat'a `%LOCALAPPDATA%\KolitakipIMZA\baglanti_testi` yazıp Enter).

---

## Değerlendirme (Kolitakip / geliştirici için)

Her satırın raporunda bakılacaklar. **Doğrulanamayan satır "DOĞRULANMADI" diye işaretlenir; tahmin edilmez.**

| # | Beklenen (ham veri) | Sonuç |
|---|---|---|
| 1 | `kart_dustu` → `kart_geldi` → `ag_gecidi_geri`; `acilma_araligi_ms` UZUN (modem açılış süresi, tipik 30–120 sn) | DOĞRULANMADI |
| 2 | `kart_dustu`(medya_baglantisi_yok) → `kart_geldi`; `acilma_araligi_ms` KISA (< ~3 sn) | DOĞRULANMADI |
| 3 | Wi-Fi `kart_dustu`/`kart_geldi`; aralık KISA | DOĞRULANMADI |
| 4 | 4a: `kart_dustu` (neden bilinmiyor/medya); 4b: `kart_dustu` neden `devre_disi`; aralık KISA | DOĞRULANMADI |
| 5 | `ag_gecidi_hic_kaybolmadi`; kart düşmez; varsa UPnP/ikinci atlama ipucu | DOĞRULANMADI |
| 6 | Ön kontrolde `HOTSPOT_IPUCU` (bilinen adres veya `AG_GECIDI_RASTGELE_MAC`); uçak modunda Wi-Fi düşer | DOĞRULANMADI |
| 7 | `ARAYUZ_RNDIS` | DOĞRULANMADI |
| 8 | `VPN_ARAYUZU_VAR` / `VPN_VARSAYILAN_YOLDA` | DOĞRULANMADI |
| 9 | `COKLU_AKTIF_ARAYUZ` | DOĞRULANMADI |
| 10a/b | `uyku`/`uyanma` ve/veya `saat_atlamasi`, `yoklama_boslugu` | DOĞRULANMADI |
| 10c | Kalp atışı kesilir; yeniden açılışta `rapor_turu:"yarim"` + `program_yeniden_baslatildi` | DOĞRULANMADI |
| 11 | Kart düşmez (bağlantı açık kalır) ama modem susar. Modem kapalıyken ARP sonucu `cevap` OLMAMALI. `onbellek_once` `reachable/stale` iken `cevap` geliyorsa SendARP önbellekten cevaplıyor demektir → yalnız TCP'ye güvenilir. TCP sonuçlarıyla karşılaştır. | DOĞRULANMADI |
| 12 | Satır 1 her markada aynı örüntü; açılma süreleri not edilir | DOĞRULANMADI |
| 13 | İmza akışı aynen çalışır | DOĞRULANMADI |

**Bilinen Windows davranışı (TCP):** Windows, RST alınca SYN'i birkaç kez yeniden dener; bu yüzden kapalı bir
porta bağlantı (`reddedildi`) ~1–2 sn sürer ve kısa zaman aşımında `zaman_asimi` görünebilir. Modemlerin çoğunda
80 (web arayüzü) ve 53 (DNS) açık olduğundan bunlar `acik` döner; bu ölçümle doğrulanmalı.
