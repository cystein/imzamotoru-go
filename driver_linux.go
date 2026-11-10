//go:build linux

package main

/*
#cgo LDFLAGS: -ldl
#define _GNU_SOURCE
#include "dlfcn.h"
#include "stdlib.h"
#include "pthread.h"

static int (*orig_lock)(pthread_mutex_t*) = NULL;
static int (*orig_init)(pthread_mutex_t*, const pthread_mutexattr_t*) = NULL;

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    if (mutex) mutex->__data.__kind &= 0x1f;
    if (!orig_lock) orig_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    return orig_lock(mutex);
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    if (!orig_init) orig_init = dlsym(RTLD_NEXT, "pthread_mutex_init");
    return orig_init(mutex, NULL);
}

int force_init(const char* lib_path) {
    void* handle = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) return -1;
    int (*c_init)(void*) = dlsym(handle, "C_Initialize");
    if (!c_init) return -2;
    return c_init(NULL);
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/miekg/pkcs11"
)

// AKIS_LIB_PATH: TÜBİTAK Kamu SM AKİS sürücüsünün Linux'taki standart kurulum yolu.
const AKIS_LIB_PATH = "/usr/lib/libakisp11.so"

// initDriver, AKİS sürücüsünün C_Initialize(NULL) beklentisini (miekg/pkcs11 kütüphanesi
// her zaman dolu bir CK_C_INITIALIZE_ARGS struct'ı gönderdiği için) ham bir dlopen/dlsym
// çağrısıyla karşılar, sonra resmi pkcs11 wrapper'ını aynı yüklü kütüphaneye bağlar.
func initDriver() (*surucuSeti, error) {
	// Windows tarafındaki bulunanSurucuAdaylari()'nin dosya-varlığı kontrolüyle aynı ayrımı
	// burada da yapıyoruz: dosya hiç yoksa ErrSurucuHicKurulmamis (main.go), varsa ama
	// başlatılamıyorsa genel bir hata — surucuHatasiKullaniciMesaji() ikisini ayırt ediyor.
	if _, statErr := os.Stat(AKIS_LIB_PATH); statErr != nil {
		return nil, fmt.Errorf("%w (aranan: %s)", ErrSurucuHicKurulmamis, AKIS_LIB_PATH)
	}

	cPath := C.CString(AKIS_LIB_PATH)
	defer C.free(unsafe.Pointer(cPath))

	log.Println("[WORKER] AKİS sürücüsü bu özel Thread içinde başlatılıyor...")
	if res := C.force_init(cPath); res != 0 {
		return nil, fmt.Errorf("force_init kod %d (AKİS sürücüsü %s bulunamamış olabilir)", res, AKIS_LIB_PATH)
	}

	return &surucuSeti{surucular: []yukluSurucu{yeniYukluSurucu(AKIS_LIB_PATH, pkcs11.New(AKIS_LIB_PATH))}}, nil
}

// surucuDosyasiDurumu: Linux'ta 32/64 bit ayrımı yapılmıyor.
func surucuDosyasiDurumu(ad string) (var64, var32 bool) { return false, false }

// yeniSuruculeriYukle: Linux'ta tek sabit sürücü var, sonradan ekleme yok.
func (s *surucuSeti) yeniSuruculeriYukle() {}
