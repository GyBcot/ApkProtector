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
    0x6a,0x8e,0x54,0xca,0x93,0x4e,0x50,0x3d,0x7b,0x20,0x79,0xf9,0xd8,0xde,0x88,0xf5,
    0x21,0x9b,0x3e,0x51,0xaa,0x44,0xd8,0x57,0xbe,0xfd,0x8d,0x2f,0xaa,0x97,0xe8,0x78};

namespace {

constexpr int KEK_LEN = 32;
static volatile bool g_screenCapturePrevention = false;
static volatile bool g_antiHijacking = false;
static volatile jobject g_realAppRef = nullptr;
static std::vector<std::string> g_sslPins;

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

static void installSslPinning(JNIEnv* env, jobject context, const std::string& pinsStr) {
    if (pinsStr.empty()) return;
    std::istringstream ss(pinsStr);
    std::string pin;
    while (std::getline(ss, pin, ',')) {
        if (!pin.empty()) g_sslPins.push_back(pin);
    }
    if (g_sslPins.empty()) return;
    jclass networkSecurityClass = env->FindClass("android/security/NetworkSecurityPolicy");
    if (networkSecurityClass && !env->ExceptionCheck()) {
        jmethodID getInstance = env->GetStaticMethodID(networkSecurityClass, "getInstance",
            "()Landroid/security/NetworkSecurityPolicy;");
        if (getInstance && !env->ExceptionCheck()) {
            jobject policy = env->CallStaticObjectMethod(networkSecurityClass, getInstance);
            jmethodID setCleartext = env->GetMethodID(networkSecurityClass,
                "setCleartextTrafficPermitted", "(Z)V");
            if (setCleartext && !env->ExceptionCheck()) {
                env->CallVoidMethod(policy, setCleartext, JNI_FALSE);
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(policy);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(networkSecurityClass);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    LOGW("SSL pinning installed via JNI: %zu pin(s)", g_sslPins.size());
}

static bool verifySslPinJni(JNIEnv* env, jobject chain) {
    if (g_sslPins.empty()) return true;
    jclass chainClass = env->GetObjectClass(chain);
    jmethodID getSize = env->GetMethodID(chainClass, "size", "()I");
    jmethodID get = env->GetMethodID(chainClass, "get", "(I)Ljava/lang/Object;");
    jint size = env->CallIntMethod(chain, getSize);
    env->DeleteLocalRef(chainClass);
    jclass x509Class = env->FindClass("java/security/cert/X509Certificate");
    jmethodID getPublicKey = env->GetMethodID(x509Class, "getPublicKey", "()Ljava/security/PublicKey;");
    jclass keyFactoryClass = env->FindClass("java/security/KeyFactory");
    jmethodID kfGetInstance = env->GetStaticMethodID(keyFactoryClass, "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyFactory;");
    jclass x509SpecClass = env->FindClass("java/security/spec/X509EncodedKeySpec");
    jmethodID x509SpecCtor = env->GetMethodID(x509SpecClass, "<init>", "([B)V");
    jclass pubKeyClass = env->FindClass("java/security/PublicKey");
    jmethodID getEncoded = env->GetMethodID(pubKeyClass, "getEncoded", "()[B");
    jclass mdClass = env->FindClass("java/security/MessageDigest");
    jmethodID mdGetInstance = env->GetStaticMethodID(mdClass, "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jmethodID digestMethod = env->GetMethodID(mdClass, "digest", "([B)[B");
    jstring sha256Str = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdClass, mdGetInstance, sha256Str);
    bool matched = false;
    for (jint i = 0; i < size && !matched; i++) {
        jobject cert = env->CallObjectMethod(chain, get, i);
        jobject pubKey = env->CallObjectMethod(cert, getPublicKey);
        jbyteArray encoded = static_cast<jbyteArray>(env->CallObjectMethod(pubKey, getEncoded));
        jbyteArray digest = static_cast<jbyteArray>(env->CallObjectMethod(md, digestMethod, encoded));
        jsize dlen = env->GetArrayLength(digest);
        std::vector<uint8_t> dbytes(static_cast<size_t>(dlen));
        env->GetByteArrayRegion(digest, 0, dlen, reinterpret_cast<jbyte*>(dbytes.data()));
        std::string hexPin = bytesToHex(dbytes);
        for (const auto& p : g_sslPins) {
            if (p == hexPin) { matched = true; break; }
        }
        env->DeleteLocalRef(digest);
        env->DeleteLocalRef(encoded);
        env->DeleteLocalRef(pubKey);
        env->DeleteLocalRef(cert);
    }
    env->DeleteLocalRef(sha256Str);
    env->DeleteLocalRef(md);
    env->DeleteLocalRef(mdClass);
    env->DeleteLocalRef(pubKeyClass);
    env->DeleteLocalRef(x509SpecClass);
    env->DeleteLocalRef(keyFactoryClass);
    env->DeleteLocalRef(x509Class);
    return matched;
}

static int getAndroidApiLevel(JNIEnv* env) {
    jclass buildVersionClass = env->FindClass("android/os/Build$VERSION");
    jfieldID sdkIntField = env->GetStaticFieldID(buildVersionClass, "SDK_INT", "I");
    jint apiLevel = env->GetStaticIntField(buildVersionClass, sdkIntField);
    env->DeleteLocalRef(buildVersionClass);
    return static_cast<int>(apiLevel);
}

static bool injectDexInMemory(JNIEnv* env, jobject context,
                               const std::vector<std::vector<uint8_t>>& dexBlobs) {
    jclass inMemoryClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!inMemoryClass || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getClassLoader = env->GetMethodID(ctxClass, "getClassLoader",
        "()Ljava/lang/ClassLoader;");
    jobject appLoader = env->CallObjectMethod(context, getClassLoader);
    jclass byteBufferClass = env->FindClass("java/nio/ByteBuffer");
    jmethodID wrapMethod = env->GetStaticMethodID(byteBufferClass, "wrap",
        "([B)Ljava/nio/ByteBuffer;");
    jclass classCls = env->FindClass("java/lang/Class");
    jobjectArray bufferArray = env->NewObjectArray(
        static_cast<jsize>(dexBlobs.size()), byteBufferClass, nullptr);
    for (int i = 0; i < (int)dexBlobs.size(); i++) {
        const auto& blob = dexBlobs[i];
        jbyteArray jBytes = env->NewByteArray(static_cast<jsize>(blob.size()));
        env->SetByteArrayRegion(jBytes, 0, static_cast<jsize>(blob.size()),
            reinterpret_cast<const jbyte*>(blob.data()));
        jobject byteBuffer = env->CallStaticObjectMethod(byteBufferClass, wrapMethod, jBytes);
        env->SetObjectArrayElement(bufferArray, i, byteBuffer);
        env->DeleteLocalRef(byteBuffer);
        env->DeleteLocalRef(jBytes);
    }
    jmethodID inMemoryCtor = env->GetMethodID(inMemoryClass, "<init>",
        "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!inMemoryCtor || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(bufferArray);
        env->DeleteLocalRef(byteBufferClass);
        env->DeleteLocalRef(classCls);
        env->DeleteLocalRef(appLoader);
        env->DeleteLocalRef(ctxClass);
        env->DeleteLocalRef(inMemoryClass);
        return false;
    }
    jobject tempLoader = env->NewObject(inMemoryClass, inMemoryCtor, bufferArray, appLoader);
    if (!tempLoader || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(bufferArray);
        env->DeleteLocalRef(byteBufferClass);
        env->DeleteLocalRef(classCls);
        env->DeleteLocalRef(appLoader);
        env->DeleteLocalRef(ctxClass);
        env->DeleteLocalRef(inMemoryClass);
        return false;
    }
    jclass fieldCls = env->FindClass("java/lang/reflect/Field");
    jmethodID getDeclaredField = env->GetMethodID(classCls, "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID setAccessible = env->GetMethodID(fieldCls, "setAccessible", "(Z)V");
    jmethodID fieldGet = env->GetMethodID(fieldCls, "get",
        "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID fieldSet = env->GetMethodID(fieldCls, "set",
        "(Ljava/lang/Object;Ljava/lang/Object;)V");
    jclass baseDexClass = env->FindClass("dalvik/system/BaseDexClassLoader");
    jstring pathListName = env->NewStringUTF("pathList");
    jobject pathListField = env->CallObjectMethod(baseDexClass, getDeclaredField, pathListName);
    bool ok = false;
    if (!env->ExceptionCheck() && pathListField) {
        env->CallVoidMethod(pathListField, setAccessible, JNI_TRUE);
        jobject appPathList = env->CallObjectMethod(pathListField, fieldGet, appLoader);
        jobject tempPathList = env->CallObjectMethod(pathListField, fieldGet, tempLoader);
        jclass dexPathListClass = env->GetObjectClass(appPathList);
        jstring elemName = env->NewStringUTF("dexElements");
        jobject elemField = env->CallObjectMethod(dexPathListClass, getDeclaredField, elemName);
        if (!env->ExceptionCheck() && elemField) {
            env->CallVoidMethod(elemField, setAccessible, JNI_TRUE);
            jobjectArray appElems = static_cast<jobjectArray>(
                env->CallObjectMethod(elemField, fieldGet, appPathList));
            jobjectArray tempElems = static_cast<jobjectArray>(
                env->CallObjectMethod(elemField, fieldGet, tempPathList));
            jint appLen  = env->GetArrayLength(appElems);
            jint tempLen = env->GetArrayLength(tempElems);
            jclass elemClass = env->FindClass("dalvik/system/DexPathList$Element");
            jobjectArray merged = env->NewObjectArray(appLen + tempLen, elemClass, nullptr);
            for (jint i = 0; i < appLen; i++)
                env->SetObjectArrayElement(merged, i,
                    env->GetObjectArrayElement(appElems, i));
            for (jint i = 0; i < tempLen; i++)
                env->SetObjectArrayElement(merged, appLen + i,
                    env->GetObjectArrayElement(tempElems, i));
            env->CallVoidMethod(elemField, fieldSet, appPathList, merged);
            ok = !env->ExceptionCheck();
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(merged);
            env->DeleteLocalRef(elemClass);
            env->DeleteLocalRef(appElems);
            env->DeleteLocalRef(tempElems);
            env->DeleteLocalRef(elemField);
        } else {
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        env->DeleteLocalRef(elemName);
        env->DeleteLocalRef(dexPathListClass);
        env->DeleteLocalRef(appPathList);
        env->DeleteLocalRef(tempPathList);
        env->DeleteLocalRef(pathListField);
    } else {
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    env->DeleteLocalRef(pathListName);
    env->DeleteLocalRef(baseDexClass);
    env->DeleteLocalRef(fieldCls);
    env->DeleteLocalRef(classCls);
    env->DeleteLocalRef(tempLoader);
    env->DeleteLocalRef(bufferArray);
    env->DeleteLocalRef(byteBufferClass);
    env->DeleteLocalRef(appLoader);
    env->DeleteLocalRef(ctxClass);
    env->DeleteLocalRef(inMemoryClass);
    return ok;
}

static void injectDexViaFile(JNIEnv* env, jobject context,
                              const std::vector<std::vector<uint8_t>>& dexBlobs) {
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

void injectDex(JNIEnv* env, jobject context, const std::vector<std::vector<uint8_t>>& dexBlobs) {
    int apiLevel = getAndroidApiLevel(env);
    if (apiLevel >= 26) {
        if (injectDexInMemory(env, context, dexBlobs)) return;
    }
    injectDexViaFile(env, context, dexBlobs);
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
    if (propFlag(props, "guard.signatureVerification"))
        verifySignature(env, context, propStr(props, "guard.certSha256"));
    std::string payloadAsset = propStr(props, "rscoders.payload", "rscoders.payload");
    std::vector<uint8_t> payload = readAssetNative(env, context, payloadAsset.c_str());
    if (payload.empty()) tamper("payload-missing");
    if (propFlag(props, "guard.fileIntegrityVerification"))
        verifyIntegrity(payload, propStr(props, "guard.payloadSha256"));
    auto dexBlobs = unpackPayload(payload);
    if (dexBlobs.empty()) tamper("payload-unpack");
    injectDex(env, context, dexBlobs);
    if (propFlag(props, "guard.sslPinning")) {
        installSslPinning(env, context, propStr(props, "guard.sslPins"));
    }
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

JNIEXPORT jboolean JNICALL
Java_com_rscoders_stub_StubApp_nativeVerifySslPin(JNIEnv* env, jclass, jobject chain) {
    return verifySslPinJni(env, chain) ? JNI_TRUE : JNI_FALSE;
}

}
