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
}
