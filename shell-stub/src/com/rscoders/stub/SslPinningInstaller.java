package com.rscoders.stub;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public final class SslPinningInstaller {

    private static final String TAG = "RC.SSL";

    public interface PinProvider {
        String[] getPins();
        boolean isEnabled();
    }

    public static void install(Context context, PinProvider provider) {
        if (provider == null || !provider.isEnabled()) return;
        String[] pins = provider.getPins();
        if (pins == null || pins.length == 0) return;

        try {
            installHttpsUrlConnection(pins);
        } catch (Throwable t) {
            Log.w(TAG, "httpsUrlConnection install failed: " + t.getMessage());
        }

        try {
            installOkHttp3(context, pins);
        } catch (Throwable t) {
            Log.w(TAG, "okhttp3 install failed: " + t.getMessage());
        }

        try {
            installOkHttp3Singleton(pins);
        } catch (Throwable t) {
            Log.w(TAG, "okhttp3 singleton install failed: " + t.getMessage());
        }

        try {
            installRetrofit(pins);
        } catch (Throwable t) {
            Log.w(TAG, "retrofit install failed: " + t.getMessage());
        }

        try {
            installVolley(context, pins);
        } catch (Throwable t) {
            Log.w(TAG, "volley install failed: " + t.getMessage());
        }
    }

    private static X509TrustManager buildTrustManager(final String[] hexPins) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                verifyPins(chain, hexPins);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    private static SSLContext buildSslContext(String[] hexPins)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{ buildTrustManager(hexPins) }, new SecureRandom());
        return ctx;
    }

    private static HostnameVerifier buildHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }

    private static void verifyPins(X509Certificate[] chain, String[] hexPins)
            throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("empty chain");
        }
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException("SHA-256 not available");
        }
        for (X509Certificate cert : chain) {
            byte[] spki = cert.getPublicKey().getEncoded();
            byte[] digest = md.digest(spki);
            String hex = bytesToHex(digest);
            for (String pin : hexPins) {
                if (pin.equalsIgnoreCase(hex)) return;
            }
        }
        throw new CertificateException("SSL pin mismatch");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static void installHttpsUrlConnection(String[] pins)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx = buildSslContext(pins);
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(buildHostnameVerifier());
    }

    private static void installOkHttp3(Context context, String[] pins) throws Exception {
        ClassLoader cl = context.getClassLoader();
        Class<?> builderClass;
        try {
            builderClass = cl.loadClass("okhttp3.OkHttpClient$Builder");
        } catch (ClassNotFoundException e) {
            return;
        }

        Class<?> clientClass = cl.loadClass("okhttp3.OkHttpClient");
        Class<?> sslSocketFactoryClass = cl.loadClass("okhttp3.OkHttpClient$Builder");

        SSLContext ctx = buildSslContext(pins);
        X509TrustManager tm = buildTrustManager(pins);
        HostnameVerifier hv = buildHostnameVerifier();

        Object builder = builderClass.getDeclaredConstructor().newInstance();

        Method sslMethod = builderClass.getMethod(
            "sslSocketFactory",
            SSLSocketFactory.class,
            X509TrustManager.class
        );
        sslMethod.invoke(builder, ctx.getSocketFactory(), tm);

        Method hvMethod = builderClass.getMethod("hostnameVerifier", HostnameVerifier.class);
        hvMethod.invoke(builder, hv);

        Method buildMethod = builderClass.getMethod("build");
        Object client = buildMethod.invoke(builder);

        hookOkHttpClientInstance(cl, client, ctx.getSocketFactory(), tm, hv);
    }

    private static void hookOkHttpClientInstance(
            ClassLoader cl,
            Object newClient,
            SSLSocketFactory factory,
            X509TrustManager tm,
            HostnameVerifier hv
    ) throws Exception {
        Class<?> clientClass = cl.loadClass("okhttp3.OkHttpClient");

        for (Field field : clientClass.getDeclaredFields()) {
            String typeName = field.getType().getName();
            if (typeName.contains("SSLSocketFactory") || typeName.contains("sslSocketFactory")) {
                field.setAccessible(true);
                field.set(newClient, factory);
            }
            if (typeName.contains("HostnameVerifier") || typeName.contains("hostnameVerifier")) {
                field.setAccessible(true);
                field.set(newClient, hv);
            }
        }
    }

    private static void installOkHttp3Singleton(String[] pins) throws Exception {
        String[] candidateClasses = {
            "okhttp3.OkHttpClient",
            "com.android.okhttp.OkHttpClient",
        };

        SSLContext ctx = buildSslContext(pins);
        X509TrustManager tm = buildTrustManager(pins);
        HostnameVerifier hv = buildHostnameVerifier();

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) cl = SslPinningInstaller.class.getClassLoader();

        for (String className : candidateClasses) {
            try {
                Class<?> clazz = cl.loadClass(className);
                for (Field field : clazz.getDeclaredFields()) {
                    if (!java.lang.reflect.Modifier.isStatic(field.getModifiers())) continue;
                    field.setAccessible(true);
                    Object instance = field.get(null);
                    if (instance == null) continue;
                    if (!clazz.isInstance(instance)) continue;
                    patchOkHttpInstance(instance, ctx.getSocketFactory(), tm, hv);
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private static void patchOkHttpInstance(
            Object instance,
            SSLSocketFactory factory,
            X509TrustManager tm,
            HostnameVerifier hv
    ) throws Exception {
        Class<?> clazz = instance.getClass();
        while (clazz != null && clazz != Object.class) {
            for (Field field : clazz.getDeclaredFields()) {
                field.setAccessible(true);
                String typeName = field.getType().getName();
                if (typeName.contains("SSLSocketFactory")) {
                    field.set(instance, factory);
                }
                if (typeName.contains("HostnameVerifier")) {
                    field.set(instance, hv);
                }
                if (typeName.contains("X509TrustManager") || typeName.contains("TrustManager")) {
                    field.set(instance, tm);
                }
            }
            clazz = clazz.getSuperclass();
        }
    }

    private static void installRetrofit(String[] pins) throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) cl = SslPinningInstaller.class.getClassLoader();

        Class<?> retrofitClass;
        try {
            retrofitClass = cl.loadClass("retrofit2.Retrofit");
        } catch (ClassNotFoundException e) {
            return;
        }

        SSLContext ctx = buildSslContext(pins);
        X509TrustManager tm = buildTrustManager(pins);
        HostnameVerifier hv = buildHostnameVerifier();

        for (Field field : retrofitClass.getDeclaredFields()) {
            if (!java.lang.reflect.Modifier.isStatic(field.getModifiers())) continue;
            field.setAccessible(true);
            Object val = field.get(null);
            if (val == null) continue;
            patchOkHttpInstance(val, ctx.getSocketFactory(), tm, hv);
        }
    }

    private static void installVolley(Context context, String[] pins) throws Exception {
        ClassLoader cl = context.getClassLoader();
        Class<?> hurlStackClass;
        try {
            hurlStackClass = cl.loadClass("com.android.volley.toolbox.HurlStack");
        } catch (ClassNotFoundException e) {
            return;
        }

        SSLContext ctx = buildSslContext(pins);
        X509TrustManager tm = buildTrustManager(pins);

        for (Field field : hurlStackClass.getDeclaredFields()) {
            field.setAccessible(true);
            String typeName = field.getType().getName();
            if (typeName.contains("SSLSocketFactory")) {
                field.set(null, ctx.getSocketFactory());
            }
        }
    }
}
