#include <jni.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <link.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <android/dlext.h>
#include "ca_crypto.h"

#define LOG_TAG "RSCoders"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

__attribute__((used, aligned(16)))
volatile uint8_t g_kekBlob[48] = {
    0xCA, 0x1B, 0x0B, 0x1E, 0x5E, 0xC0, 0xDE, 0x4B, 0x45, 0x4B, 0x21, 0x76, 0x31, 0x00, 0xA5, 0x5A,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78,0x87,0x96,0xA5,0xB4,0xC3,0xD2,0xE1,0xF0};

namespace {

constexpr int KEK_LEN = 32;

void loadKek(uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = g_kekBlob[16 + i];
}

bool fileExists(const char* path) {
    return access(path, F_OK) == 0;
}

bool procMapsContains(const char* needle) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(needle) != std::string::npos) return true;
    }
    return false;
}

std::string getProp(const char* key) {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(key, value);
    return std::string(value);
}

bool tracerPidNonZero() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            return std::atoi(line.c_str() + 10) != 0;
        }
    }
    return false;
}

bool beingDebugged() {
    return tracerPidNonZero();
}

bool isRooted() {
    const char* suPaths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/app/Superuser.apk", "/data/adb/magisk", "/sbin/.magisk",
        "/data/adb/modules", "/cache/.disable_magisk",
    };
    for (auto p : suPaths) if (fileExists(p)) return true;
    std::string tags = getProp("ro.build.tags");
    if (tags.find("test-keys") != std::string::npos) return true;
    std::ifstream mounts("/proc/self/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find("magisk") != std::string::npos) return true;
    }
    return false;
}

bool isEmulator() {
    const char* qemuFiles[] = {
        "/dev/qemu_pipe", "/dev/socket/qemud", "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props",
    };
    for (auto p : qemuFiles) if (fileExists(p)) return true;
    if (getProp("ro.kernel.qemu") == "1") return true;
    std::string model = getProp("ro.product.model");
    std::string brand = getProp("ro.product.brand");
    std::string device = getProp("ro.product.device");
    std::string fp = getProp("ro.build.fingerprint");
    auto has = [](const std::string& s, const char* n) { return s.find(n) != std::string::npos; };
    if (has(model, "sdk") || has(model, "Emulator") || has(model, "Android SDK")) return true;
    if (has(brand, "generic") || has(device, "generic") || has(fp, "generic")) return true;
    if (has(getProp("ro.hardware"), "goldfish") || has(getProp("ro.hardware"), "ranchu")) return true;
    return false;
}

bool reverseToolPresent() {
    const char* libs[] = {
        "frida", "frida-agent", "frida-gadget", "gum-js-loop", "gmain",
        "xposed", "XposedBridge", "substrate", "libriru",
    };
    for (auto n : libs) if (procMapsContains(n)) return true;
    if (fileExists("/data/local/tmp/frida-server")) return true;
    const char* xposedFiles[] = {
        "/system/framework/XposedBridge.jar", "/system/lib/libxposed_art.so",
        "/system/bin/app_process_xposed",
    };
    for (auto p : xposedFiles) if (fileExists(p)) return true;
    return false;
}

} 

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_rscoders_stub_StubApp_nativeAntiDebug(JNIEnv*, jclass) {
    return beingDebugged() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_rscoders_stub_StubApp_nativeIsRooted(JNIEnv*, jclass) {
    return isRooted() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_rscoders_stub_StubApp_nativeIsEmulator(JNIEnv*, jclass) {
    return isEmulator() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_rscoders_stub_StubApp_nativeIsReverseToolPresent(JNIEnv*, jclass) {
    return reverseToolPresent() ? JNI_TRUE : JNI_FALSE;
}

namespace {
void* antiPtracePoller(void*) {
    prctl(PR_SET_NAME, "ca-apt");
    const timespec interval{1, 0};
    while (true) {
        if (tracerPidNonZero()) {
            LOGW("debugger attached at runtime; terminating");
            kill(getpid(), SIGKILL);
            _exit(1);
        }
        nanosleep(&interval, nullptr);
    }
    return nullptr;
}
} 

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeInstallAntiPtrace(JNIEnv*, jclass) {
    prctl(PR_SET_DUMPABLE, 0);
    pthread_t t;
    if (pthread_create(&t, nullptr, antiPtracePoller, nullptr) == 0) {
        pthread_detach(t);
        LOGI("anti-ptrace installed (dumpable=0 + TracerPid poller)");
    }
}

namespace {

#if defined(__LP64__)
#define CA_R_SYM(i) ELF64_R_SYM(i)
#else
#define CA_R_SYM(i) ELF32_R_SYM(i)
#endif

struct HookReq { const char* name; void* repl; };

void patchSlot(void** slot, void* val) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(slot) & ~(static_cast<uintptr_t>(ps) - 1);
    if (mprotect(reinterpret_cast<void*>(page), ps, PROT_READ | PROT_WRITE) == 0) *slot = val;
}

void hookModule(struct dl_phdr_info* info, const HookReq* reqs, int nreqs) {
    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return;
    auto resolve = [&](ElfW(Addr) p) -> uintptr_t {
        return (p < info->dlpi_addr) ? (info->dlpi_addr + p) : p;
    };
    const char* strtab = nullptr;
    const ElfW(Sym)* symtab = nullptr;
    ElfW(Addr) jmprel = 0; size_t pltrelsz = 0; long pltrel = 0;
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_STRTAB: strtab = reinterpret_cast<const char*>(resolve(d->d_un.d_ptr)); break;
            case DT_SYMTAB: symtab = reinterpret_cast<const ElfW(Sym)*>(resolve(d->d_un.d_ptr)); break;
            case DT_JMPREL: jmprel = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
            case DT_PLTREL: pltrel = d->d_un.d_val; break;
        }
    }
    if (!strtab || !symtab || !jmprel || !pltrelsz) return;
    uintptr_t rel = resolve(jmprel);
    auto tryHook = [&](uint32_t symIdx, ElfW(Addr) rOffset) {
        const char* name = strtab + symtab[symIdx].st_name;
        for (int k = 0; k < nreqs; ++k)
            if (strcmp(name, reqs[k].name) == 0)
                patchSlot(reinterpret_cast<void**>(info->dlpi_addr + rOffset), reqs[k].repl);
    };
    if (pltrel == DT_RELA) {
        auto* r = reinterpret_cast<ElfW(Rela)*>(rel);
        for (size_t i = 0; i < pltrelsz / sizeof(ElfW(Rela)); ++i)
            tryHook(CA_R_SYM(r[i].r_info), r[i].r_offset);
    } else {
        auto* r = reinterpret_cast<ElfW(Rel)*>(rel);
        for (size_t i = 0; i < pltrelsz / sizeof(ElfW(Rel)); ++i)
            tryHook(CA_R_SYM(r[i].r_info), r[i].r_offset);
    }
}

struct HookCtx { const HookReq* reqs; int n; };
int phdrCb(struct dl_phdr_info* info, size_t, void* data) {
    const char* nm = info->dlpi_name ? info->dlpi_name : "";
    if (strstr(nm, "librscoders.so") || strstr(nm, "linker")) return 0;
    auto* ctx = reinterpret_cast<HookCtx*>(data);
    hookModule(info, ctx->reqs, ctx->n);
    return 0;
}

void pltHookAll(const HookReq* reqs, int n) {
    HookCtx ctx{reqs, n};
    dl_iterate_phdr(phdrCb, &ctx);
}

int logPrintNoop(int, const char*, const char*, ...) { return 0; }
int logWriteNoop(int, const char*, const char*) { return 0; }
int logBufWriteNoop(int, int, const char*, const char*) { return 0; }

} 

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeSuppressLogs(JNIEnv*, jclass) {
    static const HookReq reqs[] = {
        {"__android_log_print", reinterpret_cast<void*>(&logPrintNoop)},
        {"__android_log_write", reinterpret_cast<void*>(&logWriteNoop)},
        {"__android_log_buf_write", reinterpret_cast<void*>(&logBufWriteNoop)},
    };
    pltHookAll(reqs, 3);
}

namespace {
std::map<std::string, std::vector<uint8_t>>* g_protected = nullptr;

using CreateFromFdFn = void* (*)(int, const char*, int);
struct UP { void* p; ~UP() {} };
using OpenFn = UP (*)(const void*, const std::string*, int);
CreateFromFdFn g_createFromFd = nullptr;
OpenFn g_open = nullptr;

struct FindSym { const char* mod; const char* sym; void* result; };
int findSymCb(struct dl_phdr_info* info, size_t, void* data) {
    auto* f = reinterpret_cast<FindSym*>(data);
    const char* nm = info->dlpi_name ? info->dlpi_name : "";
    if (!strstr(nm, f->mod)) return 0;
    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; ++i)
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    if (!dyn) return 0;
    auto resolve = [&](ElfW(Addr) p) -> uintptr_t {
        return (p < info->dlpi_addr) ? (info->dlpi_addr + p) : p;
    };
    const char* strtab = nullptr; const ElfW(Sym)* symtab = nullptr;
    size_t syment = sizeof(ElfW(Sym));
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_STRTAB) strtab = reinterpret_cast<const char*>(resolve(d->d_un.d_ptr));
        else if (d->d_tag == DT_SYMTAB) symtab = reinterpret_cast<const ElfW(Sym)*>(resolve(d->d_un.d_ptr));
        else if (d->d_tag == DT_SYMENT) syment = d->d_un.d_val;
    }
    if (!strtab || !symtab) return 0;
    size_t count = (reinterpret_cast<uintptr_t>(strtab) - reinterpret_cast<uintptr_t>(symtab)) / syment;
    for (size_t i = 0; i < count; ++i) {
        const ElfW(Sym)* s = reinterpret_cast<const ElfW(Sym)*>(
            reinterpret_cast<const char*>(symtab) + i * syment);
        if (s->st_name == 0 || s->st_shndx == SHN_UNDEF) continue;
        if (strcmp(strtab + s->st_name, f->sym) == 0) {
            f->result = reinterpret_cast<void*>(info->dlpi_addr + s->st_value);
            return 1;
        }
    }
    return 0;
}
void* symFrom(const char* mod, const char* sym) {
    FindSym f{mod, sym, nullptr};
    dl_iterate_phdr(findSymCb, &f);
    return f.result;
}

jlong myOpenAsset(JNIEnv* env, jclass, jlong ptr, jstring name, jint mode) {
    const char* c = env->GetStringUTFChars(name, nullptr);
    std::string fn(c ? c : "");
    if (c) env->ReleaseStringUTFChars(name, c);
    auto it = g_protected ? g_protected->find(fn) : std::map<std::string, std::vector<uint8_t>>::iterator();
    if (g_protected && it != g_protected->end() && g_createFromFd) {
        const std::vector<uint8_t>& data = it->second;
        int fd = static_cast<int>(syscall(SYS_memfd_create, "ca-asset", 0));
        if (fd >= 0) {
            (void)!write(fd, data.data(), data.size());
            lseek(fd, 0, SEEK_SET);
            void* asset = g_createFromFd(fd, fn.c_str(), mode ? mode : 1);
            return reinterpret_cast<jlong>(asset);
        }
    }
    if (g_open) {
        const void* am = reinterpret_cast<const void*>(ptr);
        UP r = g_open(am, &fn, mode);
        return reinterpret_cast<jlong>(r.p);
    }
    return 0;
}
} 

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeRegisterProtectedAsset(JNIEnv* env, jclass, jstring name, jbyteArray data) {
    if (!g_protected) g_protected = new std::map<std::string, std::vector<uint8_t>>();
    const char* c = env->GetStringUTFChars(name, nullptr);
    std::string fn(c ? c : "");
    if (c) env->ReleaseStringUTFChars(name, c);
    jsize n = env->GetArrayLength(data);
    std::vector<uint8_t> v(static_cast<size_t>(n));
    if (n > 0) env->GetByteArrayRegion(data, 0, n, reinterpret_cast<jbyte*>(v.data()));
    (*g_protected)[fn] = std::move(v);
}

JNIEXPORT jboolean JNICALL
Java_com_rscoders_stub_StubApp_nativeInstallAssetHook(JNIEnv* env, jclass) {
    g_createFromFd = reinterpret_cast<CreateFromFdFn>(
        symFrom("libandroidfw.so", "_ZN7android5Asset12createFromFdEiPKcNS0_10AccessModeE"));
    g_open = reinterpret_cast<OpenFn>(symFrom(
        "libandroidfw.so",
        "_ZNK7android13AssetManager24OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS_5Asset10AccessModeE"));
    if (!g_createFromFd || !g_open) {
        LOGW("asset hook: symbol resolve failed (cff=%p open=%p)", g_createFromFd, g_open);
        return JNI_FALSE;
    }
    jclass am = env->FindClass("android/content/res/AssetManager");
    if (!am) return JNI_FALSE;
    JNINativeMethod m = {"nativeOpenAsset", "(JLjava/lang/String;I)J", reinterpret_cast<void*>(myOpenAsset)};
    if (env->RegisterNatives(am, &m, 1) != 0) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGW("asset hook: RegisterNatives failed");
        return JNI_FALSE;
    }
    LOGI("asset hook installed (transparent decryption)");
    return JNI_TRUE;
}

namespace {
std::map<std::string, std::vector<uint8_t>>* g_protectedSo = nullptr;
using DlopenExtFn = void* (*)(const char*, int, const android_dlextinfo*);
DlopenExtFn g_realDlopenExt = nullptr;

const char* baseName(const char* path) {
    const char* s = strrchr(path, '/');
    return s ? s + 1 : path;
}

void* myDlopenExt(const char* filename, int flags, const android_dlextinfo* extinfo) {
    if (filename && g_protectedSo && g_realDlopenExt) {
        auto it = g_protectedSo->find(baseName(filename));
        if (it != g_protectedSo->end()) {
            const std::vector<uint8_t>& data = it->second;
            int fd = static_cast<int>(syscall(SYS_memfd_create, "ca-so", 0));
            if (fd >= 0) {
                (void)!write(fd, data.data(), data.size());
                android_dlextinfo info{};
                if (extinfo) info = *extinfo;
                info.flags |= ANDROID_DLEXT_USE_LIBRARY_FD;
                info.library_fd = fd;
                void* h = g_realDlopenExt(filename, flags, &info);
                if (h) { LOGI("SO decrypt-load: %s", baseName(filename)); return h; }
            }
        }
    }
    return g_realDlopenExt ? g_realDlopenExt(filename, flags, extinfo) : nullptr;
}

struct ModHook { const char* mod; const HookReq* reqs; int n; };
int modHookCb(struct dl_phdr_info* info, size_t, void* data) {
    auto* m = reinterpret_cast<ModHook*>(data);
    const char* nm = info->dlpi_name ? info->dlpi_name : "";
    if (strstr(nm, m->mod)) hookModule(info, m->reqs, m->n);
    return 0;
}
}

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeRegisterProtectedSo(JNIEnv* env, jclass, jstring name, jbyteArray data) {
    if (!g_protectedSo) g_protectedSo = new std::map<std::string, std::vector<uint8_t>>();
    const char* c = env->GetStringUTFChars(name, nullptr);
    std::string fn(c ? c : "");
    if (c) env->ReleaseStringUTFChars(name, c);
    jsize n = env->GetArrayLength(data);
    std::vector<uint8_t> v(static_cast<size_t>(n));
    if (n > 0) env->GetByteArrayRegion(data, 0, n, reinterpret_cast<jbyte*>(v.data()));
    (*g_protectedSo)[fn] = std::move(v);
}

JNIEXPORT jboolean JNICALL
Java_com_rscoders_stub_StubApp_nativeInstallSoHook(JNIEnv*, jclass) {
    g_realDlopenExt = reinterpret_cast<DlopenExtFn>(dlsym(RTLD_DEFAULT, "android_dlopen_ext"));
    if (!g_realDlopenExt) g_realDlopenExt = reinterpret_cast<DlopenExtFn>(symFrom("libdl", "android_dlopen_ext"));
    if (!g_realDlopenExt) { LOGW("SO hook: android_dlopen_ext not found"); return JNI_FALSE; }
    HookReq req{"android_dlopen_ext", reinterpret_cast<void*>(&myDlopenExt)};
    ModHook mh{"libnativeloader", &req, 1};
    dl_iterate_phdr(modHookCb, &mh);
    LOGI("SO hook installed (android_dlopen_ext in libnativeloader)");
    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_rscoders_stub_StubApp_nativeUnwrapDek(JNIEnv* env, jclass, jbyteArray wrapped) {
    jsize n = env->GetArrayLength(wrapped);
    if (n < 12 + 16) return nullptr;
    std::vector<uint8_t> in(static_cast<size_t>(n));
    env->GetByteArrayRegion(wrapped, 0, n, reinterpret_cast<jbyte*>(in.data()));
    uint8_t kek[KEK_LEN]; loadKek(kek);
    size_t outLen = static_cast<size_t>(n) - 12 - 16;
    std::vector<uint8_t> out(outLen);
    bool ok = ca::aes256_gcm_decrypt(kek, in.data(), in.size(), out.data());
    memset(kek, 0, sizeof(kek));
    if (!ok) { LOGW("DEK unwrap failed (bad KEK or tampered payload)"); return nullptr; }
    jbyteArray res = env->NewByteArray(static_cast<jsize>(outLen));
    env->SetByteArrayRegion(res, 0, static_cast<jsize>(outLen), reinterpret_cast<jbyte*>(out.data()));
    return res;
}

JNIEXPORT jbyteArray JNICALL
Java_com_rscoders_stub_StubApp_nativeGetPropsKey(JNIEnv* env, jclass) {
    uint8_t kek[KEK_LEN]; loadKek(kek);
    const char* label = "rscoders-props";
    uint8_t buf[KEK_LEN + 16];
    memcpy(buf, kek, KEK_LEN);
    memcpy(buf + KEK_LEN, label, 16);
    memset(kek, 0, sizeof(kek));
    jbyteArray res = env->NewByteArray(sizeof(buf));
    env->SetByteArrayRegion(res, 0, sizeof(buf), reinterpret_cast<jbyte*>(buf));
    memset(buf, 0, sizeof(buf));
    return res;
}

} 
