package com.rscoders.stub;

import android.app.Application;
import android.content.Context;

public final class StubApp extends Application {

    static { System.loadLibrary("rscoders"); }

    static volatile byte[] sAssetKey;

    private static native void nativeBootstrap(Context base);
    private static native void nativeOnCreate(Application app);
    public static native boolean nativeAntiDebug();
    public static native boolean nativeIsRooted();
    public static native boolean nativeIsEmulator();
    public static native boolean nativeIsReverseToolPresent();
    public static native void nativeInstallAntiPtrace();
    public static native void nativeSuppressLogs();
    public static native byte[] nativeUnwrapDek(byte[] wrapped);
    public static native byte[] nativeGetPropsKey();
    public static native void nativeRegisterProtectedAsset(String name, byte[] data);
    public static native boolean nativeInstallAssetHook();
    public static native void nativeRegisterProtectedSo(String name, byte[] data);
    public static native boolean nativeInstallSoHook();
    public static native void nativeInstallSslPinning(String pinsJson, boolean enforce, boolean allowUserCerts);
    public static native boolean nativeVerifySslChain(String hostname, java.security.cert.X509Certificate[] certChain);

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        nativeBootstrap(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        nativeOnCreate(this);
    }

    public static final ThreadLocal<String> currentHost = new ThreadLocal<String>();

    public static class PinningTrustManager implements javax.net.ssl.X509TrustManager {
        private final javax.net.ssl.X509TrustManager systemTm;
        private final boolean allowUserCerts;

        public PinningTrustManager(javax.net.ssl.X509TrustManager systemTm, boolean allowUserCerts) {
            this.systemTm = systemTm;
            this.allowUserCerts = allowUserCerts;
        }

        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            systemTm.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            systemTm.checkServerTrusted(chain, authType);
            if (chain != null && chain.length > 0) {
                String host = currentHost.get();
                if (host != null && !nativeVerifySslChain(host, chain)) {
                    throw new java.security.cert.CertificateException("SSL pin mismatch for: " + host);
                }
            }
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return systemTm.getAcceptedIssuers();
        }
    }

    public static class PinningSSLSocketFactory extends javax.net.ssl.SSLSocketFactory {
        private final javax.net.ssl.SSLSocketFactory delegate;

        public PinningSSLSocketFactory(javax.net.ssl.SSLSocketFactory delegate) {
            this.delegate = delegate;
        }

        private java.net.Socket wrapSocket(java.net.Socket s, final String host) throws java.io.IOException {
            if (s instanceof javax.net.ssl.SSLSocket) {
                final javax.net.ssl.SSLSocket ssl = (javax.net.ssl.SSLSocket) s;
                ssl.addHandshakeCompletedListener(new javax.net.ssl.HandshakeCompletedListener() {
                    @Override
                    public void handshakeCompleted(javax.net.ssl.HandshakeCompletedEvent event) {
                        currentHost.remove();
                    }
                });
                currentHost.set(host);
            }
            return s;
        }

        @Override
        public String[] getDefaultCipherSuites() { return delegate.getDefaultCipherSuites(); }

        @Override
        public String[] getSupportedCipherSuites() { return delegate.getSupportedCipherSuites(); }

        @Override
        public java.net.Socket createSocket() throws java.io.IOException {
            return delegate.createSocket();
        }

        @Override
        public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose)
                throws java.io.IOException {
            return wrapSocket(delegate.createSocket(s, host, port, autoClose), host);
        }

        @Override
        public java.net.Socket createSocket(String host, int port)
                throws java.io.IOException, java.net.UnknownHostException {
            return wrapSocket(delegate.createSocket(host, port), host);
        }

        @Override
        public java.net.Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort)
                throws java.io.IOException, java.net.UnknownHostException {
            return wrapSocket(delegate.createSocket(host, port, localHost, localPort), host);
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress host, int port)
                throws java.io.IOException {
            return wrapSocket(delegate.createSocket(host, port), host.getHostName());
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress address, int port,
                java.net.InetAddress localAddress, int localPort) throws java.io.IOException {
            return wrapSocket(delegate.createSocket(address, port, localAddress, localPort),
                    address.getHostName());
        }
    }

    public static void installJavaSslPinning(boolean allowUserCerts) {
        try {
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance(
                    javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((java.security.KeyStore) null);
            javax.net.ssl.TrustManager[] tms = tmf.getTrustManagers();
            javax.net.ssl.X509TrustManager systemTm = null;
            for (javax.net.ssl.TrustManager tm : tms) {
                if (tm instanceof javax.net.ssl.X509TrustManager) {
                    systemTm = (javax.net.ssl.X509TrustManager) tm;
                    break;
                }
            }
            if (systemTm == null) return;

            PinningTrustManager pinTm = new PinningTrustManager(systemTm, allowUserCerts);
            javax.net.ssl.SSLContext sslCtx = javax.net.ssl.SSLContext.getInstance("TLS");
            sslCtx.init(null, new javax.net.ssl.TrustManager[]{pinTm}, null);

            javax.net.ssl.SSLContext.setDefault(sslCtx);
            javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(
                    new PinningSSLSocketFactory(sslCtx.getSocketFactory()));
            javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
                    new javax.net.ssl.HostnameVerifier() {
                        @Override
                        public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
                            currentHost.set(hostname);
                            return true;
                        }
                    });
        } catch (Exception ignored) {}
    }
}
