package main

// APP_VERSION, self-update mekanizmasının sunucudaki latest.json ile karşılaştırdığı
// yerel sürüm numarasıdır. Yeni bir sürüm yayınlarken bu sabit ve public/imza-motoru/latest.json
// birlikte güncellenmelidir.
const APP_VERSION = "2.0.3"

// APP_NAME: kurulum klasörü, %ProgramData% günlük klasörü, exe adı gibi DOSYA SİSTEMİ adlarında
// kullanılır ve v2.0.0'da bilerek DEĞİŞMEDİ — kurulu binlerce eczanede otomatik güncelleme ve
// "eskinin üzerine kur" akışı bu adlara bağlı.
const APP_NAME = "KolitakipIMZA"

// APP_GORUNEN_AD: kullanıcının gördüğü ad (tepsi, bildirimler, mesajlar). v2.0.0'da program
// e-imzanın yanında bağlantı testi de yaptığı için "Kolitakip Asistan" oldu.
const APP_GORUNEN_AD = "Kolitakip Asistan"
