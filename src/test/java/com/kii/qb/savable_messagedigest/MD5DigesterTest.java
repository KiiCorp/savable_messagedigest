package com.kii.qb.savable_messagedigest;

import java.security.MessageDigest;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.ByteArrayOutputStream;
import java.util.Random;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.util.HashMap;

public class MD5DigesterTest
{
    public static String digestHex(MessageDigest d, byte[] b, int off, int len)
    {
        d.update(b, off, len);
        return Utils.toString(d.digest());
    }

    public static String digestHex(MessageDigest d, byte[] b, int len)
    {
        return digestHex(d, b, 0, len);
    }


    public static String digestHex(MessageDigest d, String s) {
        d.update(Utils.toByteArray(s));
        return Utils.toString(d.digest());
    }

    public static String digestHex(String s) {
        return digestHex(new MD5Digester(), s);
    }

    public void assertDigest(byte[] b, int len) throws Exception
    {
        String expected = digestHex(MessageDigest.getInstance("MD5"), b, len);
        String actual = digestHex(new MD5Digester(), b, len);
        assertEquals(expected, actual);
    }

    public void assertDigest(byte[] b, int len, int split) throws Exception
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DataOutputStream dout = new DataOutputStream(bout);
        MD5Digester d1 = new MD5Digester();
        d1.update(b, 0, split);
        d1.save(dout);
        dout.close();

        String exp1 = digestHex(MessageDigest.getInstance("MD5"), b, split);
        String act1 = Utils.toString(d1.digest());
        assertEquals(exp1, act1);

        DataInputStream din = new DataInputStream(
                new ByteArrayInputStream(bout.toByteArray()));
        MD5Digester d2 = new MD5Digester();
        d2.load(din);
        din.close();
        d2.update(b, split, len - split);

        String exp2 = digestHex(MessageDigest.getInstance("MD5"), b, len);
        String act2 = Utils.toString(d2.digest());
        assertEquals(exp2, act2);
    }

    public void testSplitedDigestByMap(byte[] b, int len, int split)
        throws Exception
    {
        HashMap<String, Object> map = new HashMap<String, Object>();

        MD5Digester d1 = new MD5Digester();
        d1.update(b, 0, split);
        d1.save(map);

        String exp1 = digestHex(MessageDigest.getInstance("MD5"), b, split);
        String act1 = Utils.toString(d1.digest());
        assertEquals(exp1, act1);

        MD5Digester d2 = new MD5Digester();
        d2.load(map);
        d2.update(b, split, len - split);

        String exp2 = digestHex(MessageDigest.getInstance("MD5"), b, len);
        String act2 = Utils.toString(d2.digest());
        assertEquals(exp2, act2);
    }

    @Test
    public void zero() throws Exception
    {
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", digestHex(""));
    }

    @Test
    public void zeroRunLength() throws Exception
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream(256);
        for (int i = 0; i < 256; ++i) {
            bout.write(0);
        }
        byte[] data = bout.toByteArray();

        assertDigest(data, 32);
        assertDigest(data, 55);
        assertDigest(data, 56);
        assertDigest(data, 57);
        assertDigest(data, 63);
        assertDigest(data, 64);
        assertDigest(data, 65);
        assertDigest(data, 119);
        assertDigest(data, 120);
        assertDigest(data, 121);
        assertDigest(data, 127);
        assertDigest(data, 128);
        assertDigest(data, 129);
    }

    @Test
    public void zeroRunSplit() throws Exception
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream(256);
        for (int i = 0; i < 256; ++i) {
            bout.write(0);
        }
        byte[] data = bout.toByteArray();

        assertDigest(data, 32, 0);
        assertDigest(data, 32, 1);
        assertDigest(data, 32, 16);
        assertDigest(data, 32, 31);
        assertDigest(data, 32, 32);

        assertDigest(data, 55, 52);
        assertDigest(data, 55, 53);
        assertDigest(data, 55, 54);
        assertDigest(data, 55, 55);

        assertDigest(data, 56, 52);
        assertDigest(data, 56, 53);
        assertDigest(data, 56, 54);
        assertDigest(data, 56, 55);
        assertDigest(data, 56, 56);

        assertDigest(data, 57, 52);
        assertDigest(data, 57, 53);
        assertDigest(data, 57, 54);
        assertDigest(data, 57, 55);
        assertDigest(data, 57, 56);
        assertDigest(data, 57, 57);

        assertDigest(data, 63, 55);
        assertDigest(data, 63, 56);
        assertDigest(data, 63, 57);
        assertDigest(data, 63, 62);
        assertDigest(data, 63, 63);

        assertDigest(data, 64, 55);
        assertDigest(data, 64, 56);
        assertDigest(data, 64, 57);
        assertDigest(data, 64, 62);
        assertDigest(data, 64, 63);
        assertDigest(data, 64, 64);

        assertDigest(data, 65, 55);
        assertDigest(data, 65, 56);
        assertDigest(data, 65, 57);
        assertDigest(data, 65, 62);
        assertDigest(data, 65, 63);
        assertDigest(data, 65, 64);
        assertDigest(data, 65, 65);
    }

    @Test
    public void zeroRunSplitByMap() throws Exception
    {
        ByteArrayOutputStream bout = new ByteArrayOutputStream(256);
        for (int i = 0; i < 256; ++i) {
            bout.write(0);
        }
        byte[] data = bout.toByteArray();

        testSplitedDigestByMap(data, 32, 0);
        testSplitedDigestByMap(data, 32, 1);
        testSplitedDigestByMap(data, 32, 16);
        testSplitedDigestByMap(data, 32, 31);
        testSplitedDigestByMap(data, 32, 32);

        testSplitedDigestByMap(data, 55, 52);
        testSplitedDigestByMap(data, 55, 53);
        testSplitedDigestByMap(data, 55, 54);
        testSplitedDigestByMap(data, 55, 55);

        testSplitedDigestByMap(data, 56, 52);
        testSplitedDigestByMap(data, 56, 53);
        testSplitedDigestByMap(data, 56, 54);
        testSplitedDigestByMap(data, 56, 55);
        testSplitedDigestByMap(data, 56, 56);

        testSplitedDigestByMap(data, 57, 52);
        testSplitedDigestByMap(data, 57, 53);
        testSplitedDigestByMap(data, 57, 54);
        testSplitedDigestByMap(data, 57, 55);
        testSplitedDigestByMap(data, 57, 56);
        testSplitedDigestByMap(data, 57, 57);

        testSplitedDigestByMap(data, 63, 55);
        testSplitedDigestByMap(data, 63, 56);
        testSplitedDigestByMap(data, 63, 57);
        testSplitedDigestByMap(data, 63, 62);
        testSplitedDigestByMap(data, 63, 63);

        testSplitedDigestByMap(data, 64, 55);
        testSplitedDigestByMap(data, 64, 56);
        testSplitedDigestByMap(data, 64, 57);
        testSplitedDigestByMap(data, 64, 62);
        testSplitedDigestByMap(data, 64, 63);
        testSplitedDigestByMap(data, 64, 64);

        testSplitedDigestByMap(data, 65, 55);
        testSplitedDigestByMap(data, 65, 56);
        testSplitedDigestByMap(data, 65, 57);
        testSplitedDigestByMap(data, 65, 62);
        testSplitedDigestByMap(data, 65, 63);
        testSplitedDigestByMap(data, 65, 64);
        testSplitedDigestByMap(data, 65, 65);
    }

    @Test
    public void randomRunLength() throws Exception
    {
        byte[] data = new byte[256];
        Random r = new Random(0);
        r.nextBytes(data);

        assertDigest(data, 32);
        assertDigest(data, 55);
        assertDigest(data, 56);
        assertDigest(data, 57);
        assertDigest(data, 63);
        assertDigest(data, 64);
        assertDigest(data, 65);
        assertDigest(data, 119);
        assertDigest(data, 120);
        assertDigest(data, 121);
        assertDigest(data, 127);
        assertDigest(data, 128);
        assertDigest(data, 129);
    }
}
