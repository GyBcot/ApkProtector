package com.rscoders.stub;

import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class RSCodersStorage {

    private static final String DIR = "rscoders-secure";
    private RSCodersStorage() {}

    public static void writeFile(Context ctx, String name, byte[] data) throws Exception {
        File dir = new File(ctx.getFilesDir(), DIR);
        if (!dir.exists() && !dir.mkdirs() && !dir.isDirectory())
            throw new java.io.IOException("cannot create secure dir");
        byte[] enc = encrypt(requireKey(), data);
        File tmp = new File(dir, name + ".tmp");
        try (FileOutputStream fos = new FileOutputStream(tmp)) { fos.write(enc); fos.getFD().sync(); }
        File dst = new File(dir, name);
        if (!tmp.renameTo(dst)) { 
            try (FileOutputStream fos = new FileOutputStream(dst)) { fos.write(enc); }
            tmp.delete();
        }
    }

    public static byte[] readFile(Context ctx, String name) throws Exception {
        File f = new File(new File(ctx.getFilesDir(), DIR), name);
        if (!f.isFile()) return null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[8192]; int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
        }
        return decrypt(requireKey(), bos.toByteArray());
    }

    public static boolean deleteFile(Context ctx, String name) {
        return new File(new File(ctx.getFilesDir(), DIR), name).delete();
    }

    public static Prefs prefs(Context ctx, String name) throws Exception {
        return new Prefs(ctx, "prefs_" + name + ".dat");
    }

    public static final class Prefs {
        private final Context ctx;
        private final String file;
        private final Properties props = new Properties();

        private Prefs(Context ctx, String file) throws Exception {
            this.ctx = ctx; this.file = file;
            byte[] raw = readFile(ctx, file);
            if (raw != null) props.load(new ByteArrayInputStream(raw));
        }

        public Prefs putString(String k, String v) { props.setProperty(k, v); return this; }
        public Prefs putInt(String k, int v) { props.setProperty(k, Integer.toString(v)); return this; }
        public Prefs putBoolean(String k, boolean v) { props.setProperty(k, Boolean.toString(v)); return this; }
        public Prefs remove(String k) { props.remove(k); return this; }

        public String getString(String k, String def) { return props.getProperty(k, def); }
        public int getInt(String k, int def) {
            String s = props.getProperty(k); return s == null ? def : Integer.parseInt(s);
        }
        public boolean getBoolean(String k, boolean def) {
            String s = props.getProperty(k); return s == null ? def : Boolean.parseBoolean(s);
        }

        public void apply() {
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                props.store(bos, "rscoders");
                writeFile(ctx, file, bos.toByteArray());
            } catch (Exception e) {
                android.util.Log.w("RSCoders", "secure prefs save failed");
            }
        }
    }

    private static byte[] requireKey() {
        byte[] k = StubApp.storageKey();
        if (k == null) throw new IllegalStateException("RSCoders not initialized");
        return k;
    }

    private static byte[] encrypt(byte[] key, byte[] plain) throws Exception {
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[12 + ct.length];
        System.arraycopy(iv, 0, out, 0, 12);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return out;
    }

    private static byte[] decrypt(byte[] key, byte[] ivAndCt) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, ivAndCt, 0, 12));
        return c.doFinal(ivAndCt, 12, ivAndCt.length - 12);
    }
}
