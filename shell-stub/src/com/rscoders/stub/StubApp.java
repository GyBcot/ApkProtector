package com.rscoders.stub;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.res.AssetManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.WindowManager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dalvik.system.InMemoryDexClassLoader;

public final class StubApp extends Application {

    static { System.loadLibrary("rscoders"); }

    private static native boolean nativeAntiDebug();
    private static native boolean nativeIsRooted();
    private static native boolean nativeIsEmulator();
    private static native boolean nativeIsReverseToolPresent();
    private static native void nativeInstallAntiPtrace();
    private static native void nativeSuppressLogs();
    private static native byte[] nativeUnwrapDek(byte[] wrapped);
    private static native byte[] nativeGetPropsKey();
    private static native void nativeRegisterProtectedAsset(String name, byte[] plaintext);
    private static native boolean nativeInstallAssetHook();
    private static native void nativeRegisterProtectedSo(String name, byte[] plaintext);
    private static native boolean nativeInstallSoHook();

    private static volatile String sFingerprint = "";
    public static String fingerprint() { return sFingerprint; }

    static volatile byte[] sAssetKey;
    private static volatile byte[] sDek;

    private Application realApp;
    private boolean screenCapturePrevention;
    private boolean antiHijacking;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            Properties g = readEncryptedProperties(base);
            sFingerprint = g.getProperty("rscoders.fingerprint", "");
            screenCapturePrevention = flag(g, "guard.screenCapturePrevention");
            antiHijacking = flag(g, "guard.antiHijacking");

            runGuards(base, g);

            byte[] payload = readAsset(base, g.getProperty("rscoders.payload", "rscoders.payload"));
            if (flag(g, "guard.fileIntegrityVerification")) {
                verifyIntegrity(payload, g.getProperty("guard.payloadSha256", ""));
            }

            List<byte[]> dexBlobs = decryptPayload(payload);
            injectDex(base, dexBlobs);

            installProtectedAssets(base, g);
            installProtectedSo(base, g);

            if (flag(g, "guard.logSuppression")) nativeSuppressLogs();

            String originalAppClass = g.getProperty("rscoders.originalApplication", "");
            if (originalAppClass != null && !originalAppClass.isEmpty()) {
                realApp = createRealApp(base, originalAppClass);
            }
        } catch (Throwable t) {
            throw new RuntimeException("RSCoders bootstrap failed", t);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (realApp != null) swapInRealApp(realApp);
        Application effective = (realApp != null) ? realApp : this;
        if (screenCapturePrevention || antiHijacking) applyWindowGuards(effective);
        if (realApp != null) realApp.onCreate();
    }

    private void runGuards(Context ctx, Properties g) {
        if (flag(g, "guard.debuggingDetection") && nativeAntiDebug()) tamper("debugger");
        if (flag(g, "guard.antiPtrace")) nativeInstallAntiPtrace();
        if (flag(g, "guard.antiReverseTools") && nativeIsReverseToolPresent()) tamper("reverse-tool");
        if (flag(g, "guard.rootDetection") && nativeIsRooted()) tamper("root");
        if (flag(g, "guard.emulatorDetection") && nativeIsEmulator()) tamper("emulator");
        if (flag(g, "guard.doubleOpenDetection") && isDoubleOpen(ctx)) tamper("double-open");
        if (flag(g, "guard.accessibilityDetection")) detectAccessibility(ctx);
        if (flag(g, "guard.signatureVerification")) verifySignature(ctx, g.getProperty("guard.certSha256", ""));
    }

    private boolean isDoubleOpen(Context ctx) {
        try {
            String pkg = ctx.getPackageName();
            String dataDir = ctx.getApplicationInfo().dataDir;
            String sourceDir = ctx.getApplicationInfo().sourceDir;
            if (dataDir != null && !dataDir.contains("/" + pkg)) return true;
            if (sourceDir != null && sourceDir.contains("/data/data/") && !sourceDir.contains(pkg)) return true;
        } catch (Throwable ignored) { }
        return false;
    }

    private void detectAccessibility(Context ctx) {
        try {
            String enabled = Settings.Secure.getString(
                    ctx.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (!TextUtils.isEmpty(enabled)) {
                android.util.Log.w("RSCoders", "accessibility services active: " + enabled);
            }
        } catch (Throwable ignored) { }
    }

    private void verifySignature(Context ctx, String expectedHex) {
        if (expectedHex == null || expectedHex.isEmpty()) return;
        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                sigs = pi.signingInfo.getApkContentsSigners();
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }
            for (Signature s : sigs) {
                if (sha256Hex(s.toByteArray()).equalsIgnoreCase(expectedHex)) return;
            }
        } catch (Throwable t) {
            tamper("signature-error");
        }
        tamper("signature-mismatch");
    }

    private void verifyIntegrity(byte[] payload, String expectedHex) {
        if (expectedHex == null || expectedHex.isEmpty()) return;
        if (!sha256Hex(payload).equalsIgnoreCase(expectedHex)) tamper("payload-integrity");
    }

    private void tamper(String reason) {
        android.util.Log.w("RSCoders", "guard triggered: " + reason);
        android.os.Process.killProcess(android.os.Process.myPid());
        System.exit(1);
    }

    private void applyWindowGuards(Application app) {
        final boolean secure = screenCapturePrevention;
        final boolean hijack = antiHijacking;
        app.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity a, Bundle b) {
                if (secure) {
                    a.getWindow().setFlags(
                            WindowManager.LayoutParams.FLAG_SECURE,
                            WindowManager.LayoutParams.FLAG_SECURE);
                }
                if (hijack) {
                    a.getWindow().getDecorView().setFilterTouchesWhenObscured(true);
                }
            }
            @Override public void onActivityStarted(Activity a) {}
            @Override public void onActivityResumed(Activity a) {}
            @Override public void onActivityPaused(Activity a) {}
            @Override public void onActivityStopped(Activity a) {}
            @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
            @Override public void onActivityDestroyed(Activity a) {}
        });
    }

    private void installProtectedAssets(Context ctx, Properties g) {
        String list = g.getProperty("guard.protectedAssets", "");
        if (list.isEmpty() || sAssetKey == null) return;
        boolean any = false;
        for (String name : list.split(",")) {
            if (name.isEmpty()) continue;
            try {
                byte[] enc = readAsset(ctx, "rscoders/enc/" + name);
                byte[] plain = aesGcmDecrypt(sAssetKey, enc);
                nativeRegisterProtectedAsset(name, plain);
                any = true;
            } catch (Throwable t) {
                android.util.Log.w("RSCoders", "protected asset failed: " + name);
            }
        }
        if (any) nativeInstallAssetHook();
    }

    private void installProtectedSo(Context ctx, Properties g) {
        String list = g.getProperty("guard.protectedSo", "");
        if (list.isEmpty() || sDek == null) return;
        try {
            byte[] soKey = deriveKey(sDek, "rscoders-so", getRuntimeCertSha256(ctx));
            String[] abis = Build.SUPPORTED_ABIS;
            String abi = (abis != null && abis.length > 0) ? abis[0] : "arm64-v8a";
            java.util.zip.ZipFile zip = new java.util.zip.ZipFile(ctx.getApplicationInfo().sourceDir);
            try {
                boolean any = false;
                for (String name : list.split(",")) {
                    if (name.isEmpty()) continue;
                    java.util.zip.ZipEntry e = zip.getEntry("lib/" + abi + "/" + name);
                    if (e == null) continue;
                    byte[] enc = readStream(zip.getInputStream(e));
                    nativeRegisterProtectedSo(name, aesGcmDecrypt(soKey, enc));
                    any = true;
                }
                if (any) nativeInstallSoHook();
            } finally {
                zip.close();
            }
        } catch (Throwable t) {
            android.util.Log.w("RSCoders", "SO protection init failed");
        }
    }

    private static String getRuntimeCertSha256(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                sigs = pi.signingInfo.getApkContentsSigners();
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }
            if (sigs != null && sigs.length > 0) return sha256Hex(sigs[0].toByteArray());
        } catch (Throwable ignored) { }
        return "";
    }

    static byte[] storageKey() {
        byte[] dek = sDek;
        if (dek == null) return null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(dek);
            md.update("rscoders-storage".getBytes("US-ASCII"));
            return md.digest();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] deriveKey(byte[] dek, String label, String certSha) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(dek);
        md.update(label.getBytes("US-ASCII"));
        md.update(certSha.getBytes("US-ASCII"));
        return md.digest();
    }

    private static byte[] readStream(InputStream in) throws Exception {
        try (InputStream s = in) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = s.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    private static List<byte[]> decryptPayload(byte[] payload) throws Exception {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
        byte[] magic = new byte[4]; in.readFully(magic);
        byte[] wrappedDek = new byte[in.readInt()]; in.readFully(wrappedDek);
        byte[] body = new byte[in.readInt()]; in.readFully(body);

        byte[] dek = nativeUnwrapDek(wrappedDek);
        if (dek == null) throw new IllegalStateException("DEK unwrap failed");
        sDek = dek;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(dek);
        md.update("rscoders-assets".getBytes("US-ASCII"));
        sAssetKey = md.digest();

        byte[] container = inflate(aesGcmDecrypt(dek, body));

        DataInputStream c = new DataInputStream(new ByteArrayInputStream(container));
        byte[] cmagic = new byte[4]; c.readFully(cmagic);
        int count = c.readInt();
        List<byte[]> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] dex = new byte[c.readInt()]; c.readFully(dex);
            out.add(dex);
        }
        return out;
    }

    private static byte[] inflate(byte[] data) throws Exception {
        java.util.zip.Inflater inf = new java.util.zip.Inflater();
        inf.setInput(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length * 2);
        byte[] buf = new byte[65536];
        while (!inf.finished()) {
            int n = inf.inflate(buf);
            if (n == 0 && inf.needsInput()) break;
            out.write(buf, 0, n);
        }
        inf.end();
        return out.toByteArray();
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] ivAndCt) throws Exception {
        byte[] iv = new byte[12];
        System.arraycopy(ivAndCt, 0, iv, 0, 12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(ivAndCt, 12, ivAndCt.length - 12);
    }

    private static void injectDex(Context ctx, List<byte[]> dexBlobs) throws Exception {
        ByteBuffer[] buffers = new ByteBuffer[dexBlobs.size()];
        for (int i = 0; i < dexBlobs.size(); i++) buffers[i] = ByteBuffer.wrap(dexBlobs.get(i));

        ClassLoader appLoader = ctx.getClassLoader();
        Object appPathList = pathList(appLoader);
        Field elementsField = appPathList.getClass().getDeclaredField("dexElements");
        elementsField.setAccessible(true);
        Object appElements = elementsField.get(appPathList);

        Object newElements;
        try {
            Method make = Class.forName("dalvik.system.DexPathList")
                    .getDeclaredMethod("makeInMemoryDexElements", ByteBuffer[].class, List.class);
            make.setAccessible(true);
            newElements = make.invoke(null, buffers, new ArrayList<java.io.IOException>());
        } catch (NoSuchMethodException e) {
            InMemoryDexClassLoader decrypted = new InMemoryDexClassLoader(buffers, appLoader.getParent());
            newElements = dexElements(decrypted);
        }

        elementsField.set(appPathList, concat(appElements, newElements));
    }

    private static Object pathList(ClassLoader loader) throws Exception {
        Field f = Class.forName("dalvik.system.BaseDexClassLoader").getDeclaredField("pathList");
        f.setAccessible(true);
        return f.get(loader);
    }

    private static Object dexElements(ClassLoader loader) throws Exception {
        Object pathList = pathList(loader);
        Field f = pathList.getClass().getDeclaredField("dexElements");
        f.setAccessible(true);
        return f.get(pathList);
    }

    private static Object concat(Object a, Object b) {
        int la = Array.getLength(a), lb = Array.getLength(b);
        Object merged = Array.newInstance(a.getClass().getComponentType(), la + lb);
        System.arraycopy(a, 0, merged, 0, la);
        System.arraycopy(b, 0, merged, la, lb);
        return merged;
    }

    private Application createRealApp(Context base, String className) throws Exception {
        Class<?> realClass = base.getClassLoader().loadClass(className);
        Application app = (Application) realClass.newInstance();
        Method attach = Application.class.getDeclaredMethod("attach", Context.class);
        attach.setAccessible(true);
        attach.invoke(app, base);
        return app;
    }

    @SuppressWarnings("unchecked")
    private void swapInRealApp(Application app) {
        try {
            Object activityThread = currentActivityThread();
            Object loadedApk = field(field(activityThread, "mBoundApplication"), "info");
            setField(loadedApk, "mApplication", app);
            setField(activityThread, "mInitialApplication", app);

            for (String mapField : new String[] {"mPackages", "mResourcePackages"}) {
                try {
                    Map<?, ?> pkgs = (Map<?, ?>) field(activityThread, mapField);
                    for (Object ref : pkgs.values()) {
                        Object apk = (ref instanceof java.lang.ref.Reference)
                                ? ((java.lang.ref.Reference<?>) ref).get() : ref;
                        if (apk == null) continue;
                        Object current = field(apk, "mApplication");
                        if (current == this || current == null) setField(apk, "mApplication", app);
                    }
                } catch (Throwable ignored) { }
            }

            List<Application> all = (List<Application>) field(activityThread, "mAllApplications");
            all.remove(this);
            all.add(app);
        } catch (Throwable t) {
            throw new RuntimeException("RSCoders app swap failed", t);
        }
    }

    private static Object currentActivityThread() throws Exception {
        Class<?> at = Class.forName("android.app.ActivityThread");
        Method m = at.getMethod("currentActivityThread");
        return m.invoke(null);
    }

    private static Object field(Object obj, String name) throws Exception {
        Field f = findField(obj.getClass(), name);
        f.setAccessible(true);
        return f.get(obj);
    }

    private static void setField(Object obj, String name, Object value) throws Exception {
        Field f = findField(obj.getClass(), name);
        f.setAccessible(true);
        f.set(obj, value);
    }

    private static Field findField(Class<?> cls, String name) throws NoSuchFieldException {
        for (Class<?> c = cls; c != null; c = c.getSuperclass()) {
            try { return c.getDeclaredField(name); } catch (NoSuchFieldException ignored) { }
        }
        throw new NoSuchFieldException(name);
    }

    private static boolean flag(Properties p, String key) {
        return "true".equalsIgnoreCase(p.getProperty(key, "false"));
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte x : d) sb.append(Character.forDigit((x >> 4) & 0xF, 16))
                               .append(Character.forDigit(x & 0xF, 16));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static Properties readEncryptedProperties(Context ctx) throws Exception {
        byte[] raw = nativeGetPropsKey();
        byte[] propsKey = MessageDigest.getInstance("SHA-256").digest(raw);
        Arrays.fill(raw, (byte) 0);
        byte[] enc = readAsset(ctx, "rscoders.bin");
        byte[] plain = aesGcmDecrypt(propsKey, enc);
        Arrays.fill(propsKey, (byte) 0);
        Properties p = new Properties();
        p.load(new ByteArrayInputStream(plain));
        return p;
    }

    private static Properties readProperties(Context ctx, String name) throws Exception {
        Properties p = new Properties();
        try (InputStream in = ctx.getAssets().open(name)) { p.load(in); }
        return p;
    }

    private static byte[] readAsset(Context ctx, String name) throws Exception {
        AssetManager am = ctx.getAssets();
        try (InputStream in = am.open(name)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }
}
