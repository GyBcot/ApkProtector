package com.rscoders.stub;

import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class RSCodersAssets {

    private RSCodersAssets() {}

    public static byte[] readBytes(Context ctx, String relativeName) throws Exception {
        byte[] key = StubApp.sAssetKey;
        if (key == null) throw new IllegalStateException("RSCoders not initialized");

        byte[] cipherBytes;
        try (InputStream in = ctx.getAssets().open("rscoders/enc/" + relativeName)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            cipherBytes = bos.toByteArray();
        }

        byte[] iv = new byte[12];
        System.arraycopy(cipherBytes, 0, iv, 0, 12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(cipherBytes, 12, cipherBytes.length - 12);
    }

    public static InputStream open(Context ctx, String relativeName) throws Exception {
        return new ByteArrayInputStream(readBytes(ctx, relativeName));
    }
}
