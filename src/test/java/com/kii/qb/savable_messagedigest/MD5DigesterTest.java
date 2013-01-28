package com.kii.qb.savable_messagedigest;

import java.security.MessageDigest;

import org.junit.Test;
import static org.junit.Assert.*;

public class MD5DigesterTest
{
    public static String digestHex(MessageDigest d, String s) {
        d.update(Utils.toByteArray(s));
        return Utils.toString(d.digest());
    }

    public static String digestHex(String s) {
        return digestHex(new MD5Digester(), s);
    }

    @Test
    public void zero() throws Exception
    {
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", digestHex(""));
    }
}
