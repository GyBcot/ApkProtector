package com.rscoders.stub;

import android.app.Application;
import android.content.Context;

public final class StubApp extends Application {

    static { System.loadLibrary("rscoders"); }

    static volatile byte[] sAssetKey;

    private static native void nativeBootstrap(Context base);
    private static native void nativeOnCreate(Application app);
    static native boolean nativeVerifySslPin(Object chain);
    static native String[] nativeGetSslPins();
    static native boolean nativeIsSslPinningEnabled();

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        nativeBootstrap(base);
        SslPinningInstaller.install(base, new SslPinningInstaller.PinProvider() {
            @Override
            public String[] getPins() {
                return nativeGetSslPins();
            }
            @Override
            public boolean isEnabled() {
                return nativeIsSslPinningEnabled();
            }
        });
    }

    @Override
    public void onCreate() {
        super.onCreate();
        nativeOnCreate(this);
    }
}
