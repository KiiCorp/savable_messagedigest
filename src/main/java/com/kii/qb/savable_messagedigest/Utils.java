package com.kii.qb.savable_messagedigest;

import java.io.ByteArrayOutputStream;

public final class Utils
{
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
}
