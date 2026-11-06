package com.rscoders.stub;

import android.app.Application;
import android.content.Context;

public final class StubApp extends Application {

    static { System.loadLibrary("rscoders"); }

    static volatile byte[] sAssetKey;

    private static native void nativeBootstrap(Context base);
    private static native void nativeOnCreate(Application app);

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
