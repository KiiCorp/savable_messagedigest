package com.kii.qb.savable_messagedigest;

import java.io.ByteArrayOutputStream;

public final class Utils
{
    public static final String HEXDIGITS = "0123456789abcdef";

    public static String toString(byte[] buffer) {
        StringBuilder s = new StringBuilder();
        for (byte b : buffer) {
            s.append(HEXDIGITS.charAt((b >> 4) & 0xF))
                .append(HEXDIGITS.charAt((b >> 0) & 0xF));
        }
        return s.toString();
    }

    public static byte[] toByteArray(String s) {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        for (int i = 0; i + 1 < s.length(); i += 2) {
            int n0 = HEXDIGITS.indexOf(s.charAt(i + 0));
            int n1 = HEXDIGITS.indexOf(s.charAt(i + 1));
            if (n0 < 0 || n1 < 0) {
                break;
            }
            bout.write(n0 << 4 | n1);
        }
        return bout.toByteArray();
    }

    public static byte[] getBytes(int[] array)
    {
        ByteArrayOutputStream bout =
            new ByteArrayOutputStream(array.length * 4);
        for (int n : array) {
            bout.write((byte)((n >>> 0) & 0xff));
            bout.write((byte)((n >>> 8) & 0xff));
            bout.write((byte)((n >>> 16) & 0xff));
            bout.write((byte)((n >>> 24) & 0xff));
        }
        return bout.toByteArray();
    }

    public static void decodeInts(byte[] b, int[] n) {
        // FIXME: Expand this loop for speed.
        int bidx = 0;
        for (int nidx = 0, I = n.length; nidx < I; ++nidx) {
            n[nidx] =
                (((int)b[bidx + 0] & 0xFF) <<  0) |
                (((int)b[bidx + 1] & 0xFF) <<  8) |
                (((int)b[bidx + 2] & 0xFF) << 16) |
                (((int)b[bidx + 3] & 0xFF) << 24);
            bidx += 4;
        }
    }
}
