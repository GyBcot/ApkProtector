#include <jni.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <link.h>
#include <elf.h>
#include <zlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <android/dlext.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
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
static volatile bool g_screenCapturePrevention = false;
static volatile bool g_antiHijacking = false;
static volatile jobject g_realAppRef = nullptr;

struct GlobalRefs {
    JavaVM* vm = nullptr;
    jobject applicationContext = nullptr;
};
static GlobalRefs g_refs;

static std::vector<uint8_t> g_dek;
static std::vector<uint8_t> g_assetKey;

void loadKek(uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = g_kekBlob[16 + i];
}

static uint32_t readU32LE(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t readU16LE(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static std::string getApkPathFromMaps() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(".apk") != std::string::npos) {
            auto pos = line.rfind(' ');
            if (pos != std::string::npos) {
                std::string path = line.substr(pos + 1);
                if (!path.empty() && path.back() == '\n') path.pop_back();
                if (!path.empty()) return path;
            }
        }
    }
    return "";
}

static std::vector<uint8_t> inflateRaw(const std::vector<uint8_t>& data) {
    z_stream zs{};
    inflateInit2(&zs, -15);
    zs.next_in = const_cast<Bytef*>(data.data());
    zs.avail_in = static_cast<uInt>(data.size());
    std::vector<uint8_t> out;
    uint8_t buf[65536];
    int ret;
    do {
        zs.next_out = buf;
        zs.avail_out = sizeof(buf);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) break;
        out.insert(out.end(), buf, buf + sizeof(buf) - zs.avail_out);
    } while (ret != Z_STREAM_END);
    inflateEnd(&zs);
    return out;
}

static std::vector<uint8_t> readCertRsaFromApk(const std::string& apkPath) {
    int fd = open(apkPath.c_str(), O_RDONLY);
    if (fd < 0) return {};

    off_t fileSize = lseek(fd, 0, SEEK_END);
    if (fileSize < 22) { close(fd); return {}; }

    uint8_t eocd[22];
    off_t searchStart = fileSize - 22;
    bool found = false;
    while (searchStart >= 0) {
        lseek(fd, searchStart, SEEK_SET);
        if (read(fd, eocd, 22) != 22) break;
        if (eocd[0] == 0x50 && eocd[1] == 0x4B && eocd[2] == 0x05 && eocd[3] == 0x06) {
            found = true;
            break;
        }
        searchStart--;
    }
    if (!found) { close(fd); return {}; }

    uint32_t cdSize   = readU32LE(eocd + 12);
    uint32_t cdOffset = readU32LE(eocd + 16);

    std::vector<uint8_t> cd(cdSize);
    lseek(fd, cdOffset, SEEK_SET);
    if ((size_t)read(fd, cd.data(), cdSize) != cdSize) { close(fd); return {}; }

    size_t pos = 0;
    while (pos + 46 <= cdSize) {
        if (readU32LE(cd.data() + pos) != 0x02014B50) break;
        uint16_t method     = readU16LE(cd.data() + pos + 10);
        uint32_t compSize   = readU32LE(cd.data() + pos + 20);
        uint16_t fnLen      = readU16LE(cd.data() + pos + 28);
        uint16_t extraLen   = readU16LE(cd.data() + pos + 30);
        uint16_t commentLen = readU16LE(cd.data() + pos + 32);
        uint32_t localOff   = readU32LE(cd.data() + pos + 42);

        std::string name(cd.begin() + pos + 46, cd.begin() + pos + 46 + fnLen);

        bool isCert = false;
        if (name.size() >= 9 && name.substr(0, 9) == "META-INF/") {
            std::string upper = name;
            for (auto& c : upper) if (c >= 'a' && c <= 'z') c -= 32;
            if (upper.size() >= 4) {
                std::string ext4 = upper.substr(upper.size() - 4);
                std::string ext3 = upper.size() >= 3 ? upper.substr(upper.size() - 3) : "";
                if (ext4 == ".RSA" || ext4 == ".DSA" || ext3 == ".EC") isCert = true;
            }
        }

        if (isCert) {
            uint8_t lhBuf[30];
            lseek(fd, localOff, SEEK_SET);
            if (read(fd, lhBuf, 30) == 30 && readU32LE(lhBuf) == 0x04034B50) {
                uint16_t lhExtraLen = readU16LE(lhBuf + 28);
                uint16_t lhFnLen    = readU16LE(lhBuf + 26);
                off_t dataOff = localOff + 30 + lhFnLen + lhExtraLen;
                lseek(fd, dataOff, SEEK_SET);
                std::vector<uint8_t> compData(compSize);
                if ((size_t)read(fd, compData.data(), compSize) == compSize) {
                    close(fd);
                    if (method == 0) return compData;
                    return inflateRaw(compData);
                }
            }
            break;
        }

        pos += 46 + fnLen + extraLen + commentLen;
    }

    close(fd);
    return {};
}

static void sha256Native(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };

    uint64_t bitLen = (uint64_t)len * 8;
    std::vector<uint8_t> msg(data, data + len);
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0);
    for (int i = 7; i >= 0; i--) msg.push_back((uint8_t)(bitLen >> (8 * i)));

    for (size_t i = 0; i < msg.size(); i += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++) {
            w[j] = ((uint32_t)msg[i+j*4] << 24) | ((uint32_t)msg[i+j*4+1] << 16) |
                   ((uint32_t)msg[i+j*4+2] << 8) | msg[i+j*4+3];
        }
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = rotr(w[j-15],7) ^ rotr(w[j-15],18) ^ (w[j-15] >> 3);
            uint32_t s1 = rotr(w[j-2],17) ^ rotr(w[j-2],19) ^ (w[j-2] >> 10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = hh + S1 + ch + K[j] + w[j];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4+0] = (h[i] >> 24) & 0xFF;
        out[i*4+1] = (h[i] >> 16) & 0xFF;
        out[i*4+2] = (h[i] >>  8) & 0xFF;
        out[i*4+3] =  h[i]        & 0xFF;
    }
}

static std::string certHashFromApkNative(const std::string& apkPath) {
    std::vector<uint8_t> certDer = readCertRsaFromApk(apkPath);
    if (certDer.empty()) return "";
    uint8_t digest[32];
    sha256Native(certDer.data(), certDer.size(), digest);
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 0; i < 32; i++) {
        s += hex[digest[i] >> 4];
        s += hex[digest[i] & 0xF];
    }
    return s;
}

std::vector<uint8_t> readAssetNative(JNIEnv* env, jobject context, const char* name) {
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getAssets = env->GetMethodID(ctxClass, "getAssets", "()Landroid/content/res/AssetManager;");
    jobject assetManager = env->CallObjectMethod(context, getAssets);
    AAssetManager* mgr = AAssetManager_fromJava(env, assetManager);
    AAsset* asset = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
    if (!asset) {
        env->DeleteLocalRef(assetManager);
        env->DeleteLocalRef(ctxClass);
        return {};
    }
    size_t len = AAsset_getLength(asset);
    std::vector<uint8_t> buf(len);
    AAsset_read(asset, buf.data(), len);
    AAsset_close(asset);
    env->DeleteLocalRef(assetManager);
    env->DeleteLocalRef(ctxClass);
    return buf;
}

std::vector<uint8_t> sha256Digest(const std::vector<uint8_t>& data) {
    JNIEnv* env = nullptr;
    g_refs.vm->AttachCurrentThread(&env, nullptr);
    jclass mdClass = env->FindClass("java/security/MessageDigest");
    jmethodID getInstance = env->GetStaticMethodID(mdClass, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring algo = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdClass, getInstance, algo);
    jmethodID digestMethod = env->GetMethodID(mdClass, "digest", "([B)[B");
    jbyteArray input = env->NewByteArray(static_cast<jsize>(data.size()));
    env->SetByteArrayRegion(input, 0, static_cast<jsize>(data.size()),
        reinterpret_cast<const jbyte*>(data.data()));
    jbyteArray result = static_cast<jbyteArray>(env->CallObjectMethod(md, digestMethod, input));
    jsize rlen = env->GetArrayLength(result);
    std::vector<uint8_t> out(rlen);
    env->GetByteArrayRegion(result, 0, rlen, reinterpret_cast<jbyte*>(out.data()));
    env->DeleteLocalRef(mdClass);
    env->DeleteLocalRef(algo);
    env->DeleteLocalRef(md);
    env->DeleteLocalRef(input);
    env->DeleteLocalRef(result);
    return out;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        s += hex[b >> 4];
        s += hex[b & 0xF];
    }
    return s;
}

std::vector<uint8_t> inflate(const std::vector<uint8_t>& data) {
    z_stream zs{};
    inflateInit(&zs);
    zs.next_in = const_cast<Bytef*>(data.data());
    zs.avail_in = static_cast<uInt>(data.size());
    std::vector<uint8_t> out;
    uint8_t buf[65536];
    int ret;
    do {
        zs.next_out = buf;
        zs.avail_out = sizeof(buf);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) break;
        out.insert(out.end(), buf, buf + sizeof(buf) - zs.avail_out);
    } while (ret != Z_STREAM_END);
    inflateEnd(&zs);
    return out;
}

uint32_t readU32BE(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

std::vector<std::vector<uint8_t>> unpackPayload(const std::vector<uint8_t>& payload) {
    const uint8_t* p = payload.data();
    size_t remaining = payload.size();

    if (remaining < 4 || memcmp(p, "CAP1", 4) != 0) return {};
    p += 4; remaining -= 4;

    if (remaining < 4) return {};
    uint32_t wrappedDekLen = readU32BE(p); p += 4; remaining -= 4;
    if (remaining < wrappedDekLen) return {};
    std::vector<uint8_t> wrappedDek(p, p + wrappedDekLen);
    p += wrappedDekLen; remaining -= wrappedDekLen;

    if (remaining < 4) return {};
    uint32_t bodyLen = readU32BE(p); p += 4; remaining -= 4;
    if (remaining < bodyLen) return {};
    std::vector<uint8_t> body(p, p + bodyLen);

    uint8_t kek[KEK_LEN];
    loadKek(kek);
    size_t dekOutLen = wrappedDek.size() - 12 - 16;
    std::vector<uint8_t> dek(dekOutLen);
    if (!ca::aes256_gcm_decrypt(kek, wrappedDek.data(), wrappedDek.size(), dek.data())) {
        memset(kek, 0, sizeof(kek));
        return {};
    }
    memset(kek, 0, sizeof(kek));

    g_dek = dek;

    std::vector<uint8_t> combined;
    combined.insert(combined.end(), dek.begin(), dek.end());
    const char* assetLabel = "rscoders-assets";
    combined.insert(combined.end(), assetLabel, assetLabel + strlen(assetLabel));
    g_assetKey = sha256Digest(combined);

    size_t bodyOutLen = body.size() - 12 - 16;
    std::vector<uint8_t> bodyDec(bodyOutLen);
    if (!ca::aes256_gcm_decrypt(dek.data(), body.data(), body.size(), bodyDec.data())) return {};

    std::vector<uint8_t> container = inflate(bodyDec);
    if (container.size() < 8 || memcmp(container.data(), "CADX", 4) != 0) return {};

    const uint8_t* cp = container.data() + 4;
    uint32_t count = readU32BE(cp); cp += 4;

    std::vector<std::vector<uint8_t>> dexBlobs;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t dexLen = readU32BE(cp); cp += 4;
        dexBlobs.emplace_back(cp, cp + dexLen);
        cp += dexLen;
    }
    return dexBlobs;
}

std::map<std::string, std::string> parseProperties(const std::vector<uint8_t>& data) {
    std::map<std::string, std::string> props;
    std::string text(data.begin(), data.end());
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        props[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return props;
}

bool propFlag(const std::map<std::string, std::string>& props, const std::string& key) {
    auto it = props.find(key);
    if (it == props.end()) return false;
    return it->second == "true";
}

std::string propStr(const std::map<std::string, std::string>& props,
                    const std::string& key, const std::string& def = "") {
    auto it = props.find(key);
    return (it != props.end()) ? it->second : def;
}

void tamper(const char* reason) {
    LOGW("guard triggered: %s", reason);
    kill(getpid(), SIGKILL);
    _exit(1);
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

bool beingDebugged() { return tracerPidNonZero(); }

bool isRooted() {
    const char* suPaths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/app/Superuser.apk", "/data/adb/magisk", "/sbin/.magisk",
        "/data/adb/modules", "/cache/.disable_magisk",
    };
    for (auto path : suPaths) if (fileExists(path)) return true;
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
        "/dev/qemu_pipe", "/dev/socket/qemud",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props",
    };
    for (auto path : qemuFiles) if (fileExists(path)) return true;
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
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/bin/app_process_xposed",
    };
    for (auto path : xposedFiles) if (fileExists(path)) return true;
    return false;
}

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

void installAntiPtrace() {
    prctl(PR_SET_DUMPABLE, 0);
    pthread_t t;
    if (pthread_create(&t, nullptr, antiPtracePoller, nullptr) == 0) {
        pthread_detach(t);
    }
}

void injectDex(JNIEnv* env, jobject context, const std::vector<std::vector<uint8_t>>& dexBlobs) {
    jclass ctxClass = env->GetObjectClass(context);
    jclass fileClass = env->FindClass("java/io/File");
    jclass classCls = env->FindClass("java/lang/Class");
    jclass fieldCls = env->FindClass("java/lang/reflect/Field");

    jmethodID getCacheDir = env->GetMethodID(ctxClass, "getCacheDir", "()Ljava/io/File;");
    jmethodID getAbsPath = env->GetMethodID(fileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jmethodID getClassLoader = env->GetMethodID(ctxClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jmethodID getDeclaredField = env->GetMethodID(classCls, "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID setAccessible = env->GetMethodID(fieldCls, "setAccessible", "(Z)V");
    jmethodID fieldGet = env->GetMethodID(fieldCls, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID fieldSet = env->GetMethodID(fieldCls, "set", "(Ljava/lang/Object;Ljava/lang/Object;)V");

    jobject cacheDir = env->CallObjectMethod(context, getCacheDir);
    jstring jCachePath = static_cast<jstring>(env->CallObjectMethod(cacheDir, getAbsPath));
    const char* cacheChars = env->GetStringUTFChars(jCachePath, nullptr);
    std::string cacheDirStr(cacheChars);
    env->ReleaseStringUTFChars(jCachePath, cacheChars);

    std::string dexPath;
    std::vector<std::string> tempFiles;
    for (int i = 0; i < (int)dexBlobs.size(); i++) {
        std::string path = cacheDirStr + "/rc_" + std::to_string(i) + ".dex";
        FILE* f = fopen(path.c_str(), "wb");
        if (f) { fwrite(dexBlobs[i].data(), 1, dexBlobs[i].size(), f); fclose(f); }
        if (!dexPath.empty()) dexPath += ":";
        dexPath += path;
        tempFiles.push_back(path);
    }

    jobject appLoader = env->CallObjectMethod(context, getClassLoader);

    jclass dexLoaderClass = env->FindClass("dalvik/system/DexClassLoader");
    jmethodID dexLoaderCtor = env->GetMethodID(dexLoaderClass, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    jstring jDexPath = env->NewStringUTF(dexPath.c_str());
    jstring jOptDir = env->NewStringUTF(cacheDirStr.c_str());
    jobject tempLoader = env->NewObject(dexLoaderClass, dexLoaderCtor,
        jDexPath, jOptDir, nullptr, appLoader);
    env->DeleteLocalRef(jDexPath);
    env->DeleteLocalRef(jOptDir);

    jclass baseDexClass = env->FindClass("dalvik/system/BaseDexClassLoader");
    jstring pathListName = env->NewStringUTF("pathList");
    jobject pathListField = env->CallObjectMethod(baseDexClass, getDeclaredField, pathListName);
    env->CallVoidMethod(pathListField, setAccessible, JNI_TRUE);
    env->DeleteLocalRef(pathListName);

    jobject appPathList = env->CallObjectMethod(pathListField, fieldGet, appLoader);
    jobject tempPathList = env->CallObjectMethod(pathListField, fieldGet, tempLoader);
    env->DeleteLocalRef(pathListField);

    jclass dexPathListClass = env->GetObjectClass(appPathList);
    jstring elemName = env->NewStringUTF("dexElements");
    jobject elemField = env->CallObjectMethod(dexPathListClass, getDeclaredField, elemName);
    env->CallVoidMethod(elemField, setAccessible, JNI_TRUE);
    env->DeleteLocalRef(elemName);

    jobjectArray appElems = static_cast<jobjectArray>(env->CallObjectMethod(elemField, fieldGet, appPathList));
    jobjectArray tempElems = static_cast<jobjectArray>(env->CallObjectMethod(elemField, fieldGet, tempPathList));

    jint appLen = env->GetArrayLength(appElems);
    jint tempLen = env->GetArrayLength(tempElems);
    jclass elemClass = env->FindClass("dalvik/system/DexPathList$Element");
    jobjectArray merged = env->NewObjectArray(appLen + tempLen, elemClass, nullptr);
    for (jint i = 0; i < appLen; i++)
        env->SetObjectArrayElement(merged, i, env->GetObjectArrayElement(appElems, i));
    for (jint i = 0; i < tempLen; i++)
        env->SetObjectArrayElement(merged, appLen + i, env->GetObjectArrayElement(tempElems, i));
    env->CallVoidMethod(elemField, fieldSet, appPathList, merged);

    for (auto& p : tempFiles) remove(p.c_str());

    env->DeleteLocalRef(ctxClass);
    env->DeleteLocalRef(fileClass);
    env->DeleteLocalRef(classCls);
    env->DeleteLocalRef(fieldCls);
    env->DeleteLocalRef(cacheDir);
    env->DeleteLocalRef(jCachePath);
    env->DeleteLocalRef(appLoader);
    env->DeleteLocalRef(dexLoaderClass);
    env->DeleteLocalRef(tempLoader);
    env->DeleteLocalRef(baseDexClass);
    env->DeleteLocalRef(appPathList);
    env->DeleteLocalRef(tempPathList);
    env->DeleteLocalRef(dexPathListClass);
    env->DeleteLocalRef(elemField);
    env->DeleteLocalRef(appElems);
    env->DeleteLocalRef(tempElems);
    env->DeleteLocalRef(elemClass);
    env->DeleteLocalRef(merged);
}

jobject findField(JNIEnv* env, jclass cls, const char* name) {
    jclass classClass = env->FindClass("java/lang/Class");
    jmethodID getDeclaredField = env->GetMethodID(classClass, "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jstring jname = env->NewStringUTF(name);
    jobject field = nullptr;
    jclass c = static_cast<jclass>(env->NewLocalRef(cls));
    while (c != nullptr && field == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        field = env->CallObjectMethod(c, getDeclaredField, jname);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            jmethodID getSuperclass = env->GetMethodID(classClass, "getSuperclass",
                "()Ljava/lang/Class;");
            jclass parent = static_cast<jclass>(env->CallObjectMethod(c, getSuperclass));
            env->DeleteLocalRef(c);
            c = parent;
            field = nullptr;
        }
    }
    if (c) env->DeleteLocalRef(c);
    env->DeleteLocalRef(jname);
    env->DeleteLocalRef(classClass);
    return field;
}

jobject getFieldValue(JNIEnv* env, jobject field, jobject obj) {
    jclass fieldClass = env->FindClass("java/lang/reflect/AccessibleObject");
    jmethodID setAccessible = env->GetMethodID(fieldClass, "setAccessible", "(Z)V");
    env->CallVoidMethod(field, setAccessible, JNI_TRUE);
    jclass fClass = env->FindClass("java/lang/reflect/Field");
    jmethodID get = env->GetMethodID(fClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jobject result = env->CallObjectMethod(field, get, obj);
    env->DeleteLocalRef(fieldClass);
    env->DeleteLocalRef(fClass);
    return result;
}

void setFieldValue(JNIEnv* env, jobject field, jobject obj, jobject value) {
    jclass fieldClass = env->FindClass("java/lang/reflect/AccessibleObject");
    jmethodID setAccessible = env->GetMethodID(fieldClass, "setAccessible", "(Z)V");
    env->CallVoidMethod(field, setAccessible, JNI_TRUE);
    jclass fClass = env->FindClass("java/lang/reflect/Field");
    jmethodID set = env->GetMethodID(fClass, "set", "(Ljava/lang/Object;Ljava/lang/Object;)V");
    env->CallVoidMethod(field, set, obj, value);
    env->DeleteLocalRef(fieldClass);
    env->DeleteLocalRef(fClass);
}

jobject createRealApp(JNIEnv* env, jobject context, const std::string& className) {
    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getClassLoader = env->GetMethodID(ctxClass, "getClassLoader",
        "()Ljava/lang/ClassLoader;");
    jobject classLoader = env->CallObjectMethod(context, getClassLoader);
    jmethodID loadClass = env->GetMethodID(classLoaderClass, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring jclassName = env->NewStringUTF(className.c_str());
    jclass realClass = static_cast<jclass>(
        env->CallObjectMethod(classLoader, loadClass, jclassName));
    if (!realClass || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(jclassName);
        env->DeleteLocalRef(classLoader);
        env->DeleteLocalRef(ctxClass);
        env->DeleteLocalRef(classLoaderClass);
        return nullptr;
    }
    jmethodID ctor = env->GetMethodID(realClass, "<init>", "()V");
    jobject app = env->NewObject(realClass, ctor);

    jclass appCls = env->FindClass("android/app/Application");
    jclass classCls = env->FindClass("java/lang/Class");
    jclass accessCls = env->FindClass("java/lang/reflect/AccessibleObject");
    jmethodID setAcc = env->GetMethodID(accessCls, "setAccessible", "(Z)V");
    jmethodID getDeclMethod = env->GetMethodID(classCls, "getDeclaredMethod",
        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    jstring attachName = env->NewStringUTF("attach");
    jclass contextClass = env->FindClass("android/content/Context");
    jobjectArray paramTypes = env->NewObjectArray(1, classCls, contextClass);
    env->SetObjectArrayElement(paramTypes, 0, contextClass);
    jobject attachMethodObj = env->CallObjectMethod(appCls, getDeclMethod, attachName, paramTypes);
    env->CallVoidMethod(attachMethodObj, setAcc, JNI_TRUE);
    jclass methodClass = env->FindClass("java/lang/reflect/Method");
    jmethodID invokeMethod = env->GetMethodID(methodClass, "invoke",
        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    jclass objClass = env->FindClass("java/lang/Object");
    jobjectArray invokeArgs = env->NewObjectArray(1, objClass, context);
    env->CallObjectMethod(attachMethodObj, invokeMethod, app, invokeArgs);

    env->DeleteLocalRef(jclassName);
    env->DeleteLocalRef(classLoader);
    env->DeleteLocalRef(ctxClass);
    env->DeleteLocalRef(classLoaderClass);
    env->DeleteLocalRef(realClass);
    env->DeleteLocalRef(appCls);
    env->DeleteLocalRef(classCls);
    env->DeleteLocalRef(accessCls);
    env->DeleteLocalRef(attachName);
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(paramTypes);
    env->DeleteLocalRef(attachMethodObj);
    env->DeleteLocalRef(methodClass);
    env->DeleteLocalRef(objClass);
    env->DeleteLocalRef(invokeArgs);
    return app;
}

void swapInRealApp(JNIEnv* env, jobject stubApp, jobject realApp) {
    jclass atClass = env->FindClass("android/app/ActivityThread");
    jmethodID currentAt = env->GetStaticMethodID(atClass, "currentActivityThread",
        "()Landroid/app/ActivityThread;");
    jobject activityThread = env->CallStaticObjectMethod(atClass, currentAt);
    jclass atCls = env->GetObjectClass(activityThread);

    jobject boundAppField = findField(env, atCls, "mBoundApplication");
    jobject boundApp = getFieldValue(env, boundAppField, activityThread);
    jclass boundAppCls = env->GetObjectClass(boundApp);
    jobject infoField = findField(env, boundAppCls, "info");
    jobject loadedApk = getFieldValue(env, infoField, boundApp);
    jclass loadedApkCls = env->GetObjectClass(loadedApk);
    jobject mAppField = findField(env, loadedApkCls, "mApplication");
    setFieldValue(env, mAppField, loadedApk, realApp);

    jobject initAppField = findField(env, atCls, "mInitialApplication");
    setFieldValue(env, initAppField, activityThread, realApp);

    const char* mapFields[] = {"mPackages", "mResourcePackages"};
    for (auto mapName : mapFields) {
        jobject mapField = findField(env, atCls, mapName);
        if (!mapField) continue;
        jobject pkgMap = getFieldValue(env, mapField, activityThread);
        if (!pkgMap) continue;
        jclass mapClass = env->GetObjectClass(pkgMap);
        jmethodID values = env->GetMethodID(mapClass, "values", "()Ljava/util/Collection;");
        jobject valCol = env->CallObjectMethod(pkgMap, values);
        jclass colClass = env->GetObjectClass(valCol);
        jmethodID iterator = env->GetMethodID(colClass, "iterator", "()Ljava/util/Iterator;");
        jobject iter = env->CallObjectMethod(valCol, iterator);
        jclass iterClass = env->GetObjectClass(iter);
        jmethodID hasNext = env->GetMethodID(iterClass, "hasNext", "()Z");
        jmethodID next = env->GetMethodID(iterClass, "next", "()Ljava/lang/Object;");
        jclass refClass = env->FindClass("java/lang/ref/Reference");
        jmethodID refGet = env->GetMethodID(refClass, "get", "()Ljava/lang/Object;");
        while (env->CallBooleanMethod(iter, hasNext)) {
            jobject ref = env->CallObjectMethod(iter, next);
            jobject apk = env->IsInstanceOf(ref, refClass)
                ? env->CallObjectMethod(ref, refGet) : ref;
            if (!apk) { env->DeleteLocalRef(ref); continue; }
            jclass apkCls = env->GetObjectClass(apk);
            jobject apkAppField = findField(env, apkCls, "mApplication");
            if (apkAppField) {
                jobject cur = getFieldValue(env, apkAppField, apk);
                if (env->IsSameObject(cur, stubApp) || cur == nullptr)
                    setFieldValue(env, apkAppField, apk, realApp);
                if (cur) env->DeleteLocalRef(cur);
                env->DeleteLocalRef(apkAppField);
            }
            env->DeleteLocalRef(apkCls);
            if (apk != ref) env->DeleteLocalRef(apk);
            env->DeleteLocalRef(ref);
        }
        env->DeleteLocalRef(iter);
        env->DeleteLocalRef(iterClass);
        env->DeleteLocalRef(colClass);
        env->DeleteLocalRef(valCol);
        env->DeleteLocalRef(mapClass);
        env->DeleteLocalRef(pkgMap);
        env->DeleteLocalRef(mapField);
        env->DeleteLocalRef(refClass);
    }

    jobject allAppsField = findField(env, atCls, "mAllApplications");
    jobject allApps = getFieldValue(env, allAppsField, activityThread);
    jclass allAppsCls = env->GetObjectClass(allApps);
    jmethodID removeMethod = env->GetMethodID(allAppsCls, "remove", "(Ljava/lang/Object;)Z");
    jmethodID addMethod = env->GetMethodID(allAppsCls, "add", "(Ljava/lang/Object;)Z");
    env->CallBooleanMethod(allApps, removeMethod, stubApp);
    env->CallBooleanMethod(allApps, addMethod, realApp);

    env->DeleteLocalRef(atClass);
    env->DeleteLocalRef(activityThread);
    env->DeleteLocalRef(atCls);
    env->DeleteLocalRef(boundAppField);
    env->DeleteLocalRef(boundApp);
    env->DeleteLocalRef(boundAppCls);
    env->DeleteLocalRef(infoField);
    env->DeleteLocalRef(loadedApk);
    env->DeleteLocalRef(loadedApkCls);
    env->DeleteLocalRef(mAppField);
    env->DeleteLocalRef(initAppField);
    env->DeleteLocalRef(allAppsField);
    env->DeleteLocalRef(allApps);
    env->DeleteLocalRef(allAppsCls);
}

void verifySignature(JNIEnv* env, jobject context, const std::string& expectedHex) {
    if (expectedHex.empty()) return;
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getPm = env->GetMethodID(ctxClass, "getPackageManager",
        "()Landroid/content/pm/PackageManager;");
    jmethodID getPkg = env->GetMethodID(ctxClass, "getPackageName", "()Ljava/lang/String;");
    jobject pm = env->CallObjectMethod(context, getPm);
    jstring pkg = static_cast<jstring>(env->CallObjectMethod(context, getPkg));
    jclass pmClass = env->GetObjectClass(pm);
    jmethodID getPackageInfo = env->GetMethodID(pmClass, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject pi = env->CallObjectMethod(pm, getPackageInfo, pkg, (jint)0x8000000);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        pi = env->CallObjectMethod(pm, getPackageInfo, pkg, (jint)64);
    }
    jclass piClass = env->GetObjectClass(pi);
    bool matched = false;
    jfieldID sigInfoField = env->GetFieldID(piClass, "signingInfo",
        "Landroid/content/pm/SigningInfo;");
    if (sigInfoField && !env->ExceptionCheck()) {
        jobject sigInfo = env->GetObjectField(pi, sigInfoField);
        jclass siClass = env->GetObjectClass(sigInfo);
        jmethodID getSigners = env->GetMethodID(siClass, "getApkContentsSigners",
            "()[Landroid/content/pm/Signature;");
        jobjectArray sigs = static_cast<jobjectArray>(env->CallObjectMethod(sigInfo, getSigners));
        jclass sigClass = env->FindClass("android/content/pm/Signature");
        jmethodID toBytes = env->GetMethodID(sigClass, "toByteArray", "()[B");
        jint sigCount = env->GetArrayLength(sigs);
        for (jint i = 0; i < sigCount && !matched; i++) {
            jobject sig = env->GetObjectArrayElement(sigs, i);
            jbyteArray sigBytes = static_cast<jbyteArray>(env->CallObjectMethod(sig, toBytes));
            jsize len = env->GetArrayLength(sigBytes);
            std::vector<uint8_t> bytes(len);
            env->GetByteArrayRegion(sigBytes, 0, len, reinterpret_cast<jbyte*>(bytes.data()));
            if (bytesToHex(sha256Digest(bytes)) == expectedHex) matched = true;
            env->DeleteLocalRef(sig);
            env->DeleteLocalRef(sigBytes);
        }
        env->DeleteLocalRef(sigInfo);
        env->DeleteLocalRef(siClass);
        env->DeleteLocalRef(sigs);
        env->DeleteLocalRef(sigClass);
    } else {
        if (env->ExceptionCheck()) env->ExceptionClear();
        jfieldID sigsField = env->GetFieldID(piClass, "signatures",
            "[Landroid/content/pm/Signature;");
        jobjectArray sigs = static_cast<jobjectArray>(env->GetObjectField(pi, sigsField));
        jclass sigClass = env->FindClass("android/content/pm/Signature");
        jmethodID toBytes = env->GetMethodID(sigClass, "toByteArray", "()[B");
        jint sigCount = env->GetArrayLength(sigs);
        for (jint i = 0; i < sigCount && !matched; i++) {
            jobject sig = env->GetObjectArrayElement(sigs, i);
            jbyteArray sigBytes = static_cast<jbyteArray>(env->CallObjectMethod(sig, toBytes));
            jsize len = env->GetArrayLength(sigBytes);
            std::vector<uint8_t> bytes(len);
            env->GetByteArrayRegion(sigBytes, 0, len, reinterpret_cast<jbyte*>(bytes.data()));
            if (bytesToHex(sha256Digest(bytes)) == expectedHex) matched = true;
            env->DeleteLocalRef(sig);
            env->DeleteLocalRef(sigBytes);
        }
        env->DeleteLocalRef(sigs);
        env->DeleteLocalRef(sigClass);
    }
    env->DeleteLocalRef(ctxClass);
    env->DeleteLocalRef(pm);
    env->DeleteLocalRef(pkg);
    env->DeleteLocalRef(pmClass);
    env->DeleteLocalRef(pi);
    env->DeleteLocalRef(piClass);
    if (!matched) tamper("signature-mismatch");
}

void verifySignatureNative(const std::string& expectedHex) {
    if (expectedHex.empty()) return;
    std::string apkPath = getApkPathFromMaps();
    if (apkPath.empty()) tamper("native-sig-apkpath");
    std::string actual = certHashFromApkNative(apkPath);
    if (actual.empty()) tamper("native-sig-read");
    if (actual != expectedHex) tamper("native-sig-mismatch");
}

void verifyIntegrity(const std::vector<uint8_t>& payload, const std::string& expectedHex) {
    if (expectedHex.empty()) return;
    if (bytesToHex(sha256Digest(payload)) != expectedHex) tamper("payload-integrity");
}

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
            dyn = reinterpret_cast<const ElfW(Dyn)*>(
                info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
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
            case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(resolve(d->d_un.d_ptr)); break;
            case DT_SYMTAB:
                symtab = reinterpret_cast<const ElfW(Sym)*>(resolve(d->d_un.d_ptr)); break;
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
                patchSlot(reinterpret_cast<void**>(
                    info->dlpi_addr + rOffset), reqs[k].repl);
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

std::map<std::string, std::vector<uint8_t>>* g_protected = nullptr;

using CreateFromFdFn = void* (*)(int, const char*, int);
struct UP { void* p; };
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
            dyn = reinterpret_cast<const ElfW(Dyn)*>(
                info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    if (!dyn) return 0;
    auto resolve = [&](ElfW(Addr) p) -> uintptr_t {
        return (p < info->dlpi_addr) ? (info->dlpi_addr + p) : p;
    };
    const char* strtab = nullptr;
    const ElfW(Sym)* symtab = nullptr;
    size_t syment = sizeof(ElfW(Sym));
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_STRTAB)
            strtab = reinterpret_cast<const char*>(resolve(d->d_un.d_ptr));
        else if (d->d_tag == DT_SYMTAB)
            symtab = reinterpret_cast<const ElfW(Sym)*>(resolve(d->d_un.d_ptr));
        else if (d->d_tag == DT_SYMENT)
            syment = d->d_un.d_val;
    }
    if (!strtab || !symtab) return 0;
    size_t count = (reinterpret_cast<uintptr_t>(strtab) -
        reinterpret_cast<uintptr_t>(symtab)) / syment;
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
                if (h) return h;
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

void installSoHook() {
    g_realDlopenExt = reinterpret_cast<DlopenExtFn>(
        dlsym(RTLD_DEFAULT, "android_dlopen_ext"));
    if (!g_realDlopenExt)
        g_realDlopenExt = reinterpret_cast<DlopenExtFn>(
            symFrom("libdl", "android_dlopen_ext"));
    if (!g_realDlopenExt) return;
    HookReq req{"android_dlopen_ext", reinterpret_cast<void*>(&myDlopenExt)};
    ModHook mh{"libnativeloader", &req, 1};
    dl_iterate_phdr(modHookCb, &mh);
}

void installAssetHook() {
    g_createFromFd = reinterpret_cast<CreateFromFdFn>(symFrom("libandroidfw.so",
        "_ZN7android5Asset12createFromFdEiPKcNS0_10AccessModeE"));
    g_open = reinterpret_cast<OpenFn>(symFrom("libandroidfw.so",
        "_ZNK7android13AssetManager24OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS_5Asset10AccessModeE"));
}

}

extern "C" {

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeBootstrap(JNIEnv* env, jclass, jobject context) {
    env->GetJavaVM(&g_refs.vm);
    g_refs.applicationContext = env->NewGlobalRef(context);

    uint8_t kek[KEK_LEN];
    loadKek(kek);
    uint8_t propsKeyRaw[KEK_LEN + 16];
    memcpy(propsKeyRaw, kek, KEK_LEN);
    memcpy(propsKeyRaw + KEK_LEN, "rscoders-props16", 16);
    memset(kek, 0, sizeof(kek));
    std::vector<uint8_t> propsKeyInput(propsKeyRaw, propsKeyRaw + sizeof(propsKeyRaw));
    memset(propsKeyRaw, 0, sizeof(propsKeyRaw));
    std::vector<uint8_t> propsKey = sha256Digest(propsKeyInput);

    std::vector<uint8_t> encProps = readAssetNative(env, context, "rscoders.bin");
    if (encProps.empty()) tamper("props-missing");
    size_t plainLen = encProps.size() - 12 - 16;
    std::vector<uint8_t> plainProps(plainLen);
    if (!ca::aes256_gcm_decrypt(propsKey.data(), encProps.data(), encProps.size(), plainProps.data()))
        tamper("props-decrypt");
    std::fill(propsKey.begin(), propsKey.end(), 0);

    auto props = parseProperties(plainProps);

    if (propFlag(props, "guard.debuggingDetection") && beingDebugged()) tamper("debugger");
    if (propFlag(props, "guard.antiPtrace")) installAntiPtrace();
    if (propFlag(props, "guard.antiReverseTools") && reverseToolPresent()) tamper("reverse-tool");
    if (propFlag(props, "guard.rootDetection") && isRooted()) tamper("root");
    if (propFlag(props, "guard.emulatorDetection") && isEmulator()) tamper("emulator");

    if (propFlag(props, "guard.signatureVerification")) {
        std::string expectedCert = propStr(props, "guard.certSha256");
        verifySignatureNative(expectedCert);
        verifySignature(env, context, expectedCert);
    }

    std::string payloadAsset = propStr(props, "rscoders.payload", "rscoders.payload");
    std::vector<uint8_t> payload = readAssetNative(env, context, payloadAsset.c_str());
    if (payload.empty()) tamper("payload-missing");

    if (propFlag(props, "guard.fileIntegrityVerification"))
        verifyIntegrity(payload, propStr(props, "guard.payloadSha256"));

    auto dexBlobs = unpackPayload(payload);
    if (dexBlobs.empty()) tamper("payload-unpack");

    injectDex(env, context, dexBlobs);

    g_screenCapturePrevention = propFlag(props, "guard.screenCapturePrevention");
    g_antiHijacking = propFlag(props, "guard.antiHijacking");

    std::string protectedAssets = propStr(props, "guard.protectedAssets");
    if (!protectedAssets.empty() && !g_assetKey.empty()) {
        if (!g_protected) g_protected = new std::map<std::string, std::vector<uint8_t>>();
        std::istringstream ss(protectedAssets);
        std::string name;
        bool any = false;
        while (std::getline(ss, name, ',')) {
            if (name.empty()) continue;
            std::vector<uint8_t> enc = readAssetNative(env, context,
                ("rscoders/enc/" + name).c_str());
            if (enc.empty()) continue;
            size_t plen = enc.size() - 12 - 16;
            std::vector<uint8_t> plain(plen);
            if (!ca::aes256_gcm_decrypt(g_assetKey.data(), enc.data(), enc.size(),
                plain.data())) continue;
            (*g_protected)[name] = std::move(plain);
            any = true;
        }
        if (any) installAssetHook();
    }

    std::string protectedSo = propStr(props, "guard.protectedSo");
    if (!protectedSo.empty() && !g_dek.empty()) {
        std::vector<uint8_t> soKeyInput;
        soKeyInput.insert(soKeyInput.end(), g_dek.begin(), g_dek.end());
        const char* soLabel = "rscoders-so";
        soKeyInput.insert(soKeyInput.end(), soLabel, soLabel + strlen(soLabel));
        std::vector<uint8_t> soKey = sha256Digest(soKeyInput);

        jclass ctxClass = env->GetObjectClass(context);
        jmethodID getAppInfo = env->GetMethodID(ctxClass, "getApplicationInfo",
            "()Landroid/content/pm/ApplicationInfo;");
        jobject appInfo = env->CallObjectMethod(context, getAppInfo);
        jclass aiClass = env->GetObjectClass(appInfo);
        jfieldID sourceDirField = env->GetFieldID(aiClass, "sourceDir", "Ljava/lang/String;");
        jstring sourceDir = static_cast<jstring>(env->GetObjectField(appInfo, sourceDirField));

        if (!g_protectedSo) g_protectedSo = new std::map<std::string, std::vector<uint8_t>>();
        std::istringstream ss(protectedSo);
        std::string soName;
        bool any = false;
        while (std::getline(ss, soName, ',')) {
            if (soName.empty()) continue;
            jclass zipClass = env->FindClass("java/util/zip/ZipFile");
            jmethodID zipCtor = env->GetMethodID(zipClass, "<init>", "(Ljava/lang/String;)V");
            jobject zip = env->NewObject(zipClass, zipCtor, sourceDir);
            jmethodID getEntry = env->GetMethodID(zipClass, "getEntry",
                "(Ljava/lang/String;)Ljava/util/zip/ZipEntry;");
            jclass buildClass = env->FindClass("android/os/Build");
            jfieldID supportedAbis = env->GetStaticFieldID(buildClass, "SUPPORTED_ABIS",
                "[Ljava/lang/String;");
            jobjectArray abis = static_cast<jobjectArray>(
                env->GetStaticObjectField(buildClass, supportedAbis));
            jstring firstAbi = static_cast<jstring>(env->GetObjectArrayElement(abis, 0));
            const char* abiStr = env->GetStringUTFChars(firstAbi, nullptr);
            std::string entryName = std::string("lib/") + abiStr + "/" + soName;
            env->ReleaseStringUTFChars(firstAbi, abiStr);
            jstring jEntry = env->NewStringUTF(entryName.c_str());
            jobject entry = env->CallObjectMethod(zip, getEntry, jEntry);
            if (entry) {
                jmethodID getInputStream = env->GetMethodID(zipClass, "getInputStream",
                    "(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;");
                jobject is = env->CallObjectMethod(zip, getInputStream, entry);
                jclass isClass = env->GetObjectClass(is);
                jmethodID readMethod = env->GetMethodID(isClass, "read", "([B)I");
                jbyteArray buf = env->NewByteArray(8192);
                std::vector<uint8_t> encBytes;
                jint n;
                while ((n = env->CallIntMethod(is, readMethod, buf)) > 0) {
                    jbyte* data = env->GetByteArrayElements(buf, nullptr);
                    encBytes.insert(encBytes.end(), data, data + n);
                    env->ReleaseByteArrayElements(buf, data, JNI_ABORT);
                }
                env->DeleteLocalRef(buf);
                env->DeleteLocalRef(isClass);
                env->DeleteLocalRef(is);
                if (!encBytes.empty()) {
                    size_t plen = encBytes.size() - 12 - 16;
                    std::vector<uint8_t> plain(plen);
                    if (ca::aes256_gcm_decrypt(soKey.data(), encBytes.data(),
                        encBytes.size(), plain.data())) {
                        (*g_protectedSo)[soName] = std::move(plain);
                        any = true;
                    }
                }
                env->DeleteLocalRef(entry);
            }
            env->DeleteLocalRef(jEntry);
            env->DeleteLocalRef(abis);
            env->DeleteLocalRef(firstAbi);
            env->DeleteLocalRef(buildClass);
            env->DeleteLocalRef(zip);
            env->DeleteLocalRef(zipClass);
        }
        env->DeleteLocalRef(sourceDir);
        env->DeleteLocalRef(appInfo);
        env->DeleteLocalRef(aiClass);
        env->DeleteLocalRef(ctxClass);
        if (any) installSoHook();
    }

    if (propFlag(props, "guard.logSuppression")) {
        static const HookReq reqs[] = {
            {"__android_log_print", reinterpret_cast<void*>(&logPrintNoop)},
            {"__android_log_write", reinterpret_cast<void*>(&logWriteNoop)},
            {"__android_log_buf_write", reinterpret_cast<void*>(&logBufWriteNoop)},
        };
        pltHookAll(reqs, 3);
    }

    std::string originalAppClass = propStr(props, "rscoders.originalApplication");
    if (!originalAppClass.empty()) {
        jobject realApp = createRealApp(env, context, originalAppClass);
        if (realApp) {
            g_realAppRef = env->NewGlobalRef(realApp);
            env->DeleteLocalRef(realApp);
        }
    }
}

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeOnCreate(JNIEnv* env, jclass, jobject stubApp) {
    if (g_realAppRef) {
        swapInRealApp(env, stubApp, g_realAppRef);
        jclass appClass = env->GetObjectClass(g_realAppRef);
        jmethodID onCreate = env->GetMethodID(appClass, "onCreate", "()V");
        env->CallVoidMethod(g_realAppRef, onCreate);
        env->DeleteLocalRef(appClass);
    }
}

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

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeInstallAntiPtrace(JNIEnv*, jclass) {
    installAntiPtrace();
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

JNIEXPORT jbyteArray JNICALL
Java_com_rscoders_stub_StubApp_nativeUnwrapDek(JNIEnv* env, jclass, jbyteArray wrapped) {
    jsize n = env->GetArrayLength(wrapped);
    if (n < 12 + 16) return nullptr;
    std::vector<uint8_t> in(static_cast<size_t>(n));
    env->GetByteArrayRegion(wrapped, 0, n, reinterpret_cast<jbyte*>(in.data()));
    uint8_t kek[KEK_LEN];
    loadKek(kek);
    size_t outLen = static_cast<size_t>(n) - 12 - 16;
    std::vector<uint8_t> out(outLen);
    bool ok = ca::aes256_gcm_decrypt(kek, in.data(), in.size(), out.data());
    memset(kek, 0, sizeof(kek));
    if (!ok) return nullptr;
    jbyteArray res = env->NewByteArray(static_cast<jsize>(outLen));
    env->SetByteArrayRegion(res, 0, static_cast<jsize>(outLen),
        reinterpret_cast<jbyte*>(out.data()));
    return res;
}

JNIEXPORT jbyteArray JNICALL
Java_com_rscoders_stub_StubApp_nativeGetPropsKey(JNIEnv* env, jclass) {
    uint8_t kek[KEK_LEN];
    loadKek(kek);
    uint8_t buf[KEK_LEN + 16];
    memcpy(buf, kek, KEK_LEN);
    memcpy(buf + KEK_LEN, "rscoders-props16", 16);
    memset(kek, 0, sizeof(kek));
    jbyteArray res = env->NewByteArray(sizeof(buf));
    env->SetByteArrayRegion(res, 0, sizeof(buf), reinterpret_cast<jbyte*>(buf));
    memset(buf, 0, sizeof(buf));
    return res;
}

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeRegisterProtectedAsset(JNIEnv* env, jclass,
                                                             jstring name, jbyteArray data) {
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
Java_com_rscoders_stub_StubApp_nativeInstallAssetHook(JNIEnv*, jclass) {
    installAssetHook();
    return (g_createFromFd && g_open) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_rscoders_stub_StubApp_nativeRegisterProtectedSo(JNIEnv* env, jclass,
                                                          jstring name, jbyteArray data) {
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
    installSoHook();
    return g_realDlopenExt ? JNI_TRUE : JNI_FALSE;
}

}
