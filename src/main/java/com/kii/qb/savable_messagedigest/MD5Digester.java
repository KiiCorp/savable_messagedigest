package com.kii.qb.savable_messagedigest;

import java.security.MessageDigest;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.DataInputStream;

public final class MD5Digester extends MessageDigest
{
    private static final byte PADDING[] = {
        (byte)0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    private MD5State state;

    private MD5State finalState = null;

    public MD5Digester() {
        super("MD5");
        this.state = new MD5State();
    }

    private MD5Digester(MD5State state) {
        super("MD5");
        this.state = state;
    }

    @Override
    public Object clone()
    {
        return new MD5Digester(new MD5State(this.state));
    }

    protected byte[] engineDigest() {
        if (this.finalState == null) {
            this.finalState = getFinalState(this.state);
        }
        return this.finalState.getStateBytes();
    }

    protected void engineReset() {
        this.state = new MD5State();
    }

    protected void engineUpdate(byte input) {
        byte[] inbuf = new byte[] { input };
        engineUpdate(inbuf, 0, 1);
    }

    protected void engineUpdate(byte[] input, int offset, int len) {
        this.finalState = null;
        updateState(this.state, input, offset, len);
    }

    public void save(DataOutputStream output) throws IOException
    {
        this.state.save(output);
    }

    public void load(DataInputStream input) throws IOException
    {
        this.state.load(input);
    }

    public static MD5State getFinalState(MD5State state)
    {
        MD5State f = new MD5State(state);
        // Get head of padding data.
        int headOdd = (int)(f.count & 0x3F);
        int headLen = ((headOdd < 56) ? 56 : 120) - headOdd;
        // Get trail of padding data.
        int[] trailArray = new int[] {
            (int)(f.count << 3), (int)(f.count >> 29)
        };
        byte[] trailBytes = Utils.getBytes(trailArray);
        // Update final state.
        updateState(f, PADDING, 0, headLen);
        updateState(f, trailBytes, 0, trailBytes.length); 
        return f;
    }

    public static MD5State updateState(MD5State state,
            byte[] input, int offset, int len)
    {
        int[] work = new int[16];
        int end = Math.min(offset + len, input.length);
        while (offset < end)
        {
            // Add a block to MD5State.buffer.
            int blockOffset = state.getOffset();
            int blockLen = Math.min(state.buffer.length - blockOffset,
                    end - offset);
            // FIXME: suppress copy for speed.
            System.arraycopy(input, offset, state.buffer,
                    blockOffset, blockLen);
            state.count += blockLen;
            offset += blockLen;
            // Update MD5State.state.
            if (len > 0 && state.getOffset() == 0) {
                transform(state, work);
            }
        }
        return state;
    }

    public static MD5State transform(MD5State state, int[] work)
    {
        int a = state.state[0];
        int b = state.state[1];
        int c = state.state[2];
        int d = state.state[3];

        final int[] x = work;
        Utils.decodeInts(state.buffer, x);

        // Round #1

        a += ((b & c) | (~b & d)) + x[ 0] + 0xd76aa478;
        a = Integer.rotateLeft(a,  7) + b;
        d += ((a & b) | (~a & c)) + x[ 1] + 0xe8c7b756;
        d = Integer.rotateLeft(d, 12) + a;
        c += ((d & a) | (~d & b)) + x[ 2] + 0x242070db;
        c = Integer.rotateLeft(c, 17) + d;
        b += ((c & d) | (~c & a)) + x[ 3] + 0xc1bdceee;
        b = Integer.rotateLeft(b, 22) + c;

        a += ((b & c) | (~b & d)) + x[ 4] + 0xf57c0faf;
        a = Integer.rotateLeft(a,  7) + b;
        d += ((a & b) | (~a & c)) + x[ 5] + 0x4787c62a;
        d = Integer.rotateLeft(d, 12) + a;
        c += ((d & a) | (~d & b)) + x[ 6] + 0xa8304613;
        c = Integer.rotateLeft(c, 17) + d;
        b += ((c & d) | (~c & a)) + x[ 7] + 0xfd469501;
        b = Integer.rotateLeft(b, 22) + c;

        a += ((b & c) | (~b & d)) + x[ 8] + 0x698098d8;
        a = Integer.rotateLeft(a,  7) + b;
        d += ((a & b) | (~a & c)) + x[ 9] + 0x8b44f7af;
        d = Integer.rotateLeft(d, 12) + a;
        c += ((d & a) | (~d & b)) + x[10] + 0xffff5bb1;
        c = Integer.rotateLeft(c, 17) + d;
        b += ((c & d) | (~c & a)) + x[11] + 0x895cd7be;
        b = Integer.rotateLeft(b, 22) + c;

        a += ((b & c) | (~b & d)) + x[12] + 0x6b901122;
        a = Integer.rotateLeft(a,  7) + b;
        d += ((a & b) | (~a & c)) + x[13] + 0xfd987193;
        d = Integer.rotateLeft(d, 12) + a;
        c += ((d & a) | (~d & b)) + x[14] + 0xa679438e;
        c = Integer.rotateLeft(c, 17) + d;
        b += ((c & d) | (~c & a)) + x[15] + 0x49b40821;
        b = Integer.rotateLeft(b, 22) + c;

        // Round #2

        a += ((b & d) | (c & ~d)) + x[ 1] + 0xf61e2562;
        a = Integer.rotateLeft(a,  5) + b;
        d += ((a & c) | (b & ~c)) + x[ 6] + 0xc040b340;
        d = Integer.rotateLeft(d,  9) + a;
        c += ((d & b) | (a & ~b)) + x[11] + 0x265e5a51;
        c = Integer.rotateLeft(c, 14) + d;
        b += ((c & a) | (d & ~a)) + x[ 0] + 0xe9b6c7aa;
        b = Integer.rotateLeft(b, 20) + c;

        a += ((b & d) | (c & ~d)) + x[ 5] + 0xd62f105d;
        a = Integer.rotateLeft(a,  5) + b;
        d += ((a & c) | (b & ~c)) + x[10] + 0x02441453;
        d = Integer.rotateLeft(d,  9) + a;
        c += ((d & b) | (a & ~b)) + x[15] + 0xd8a1e681;
        c = Integer.rotateLeft(c, 14) + d;
        b += ((c & a) | (d & ~a)) + x[ 4] + 0xe7d3fbc8;
        b = Integer.rotateLeft(b, 20) + c;

        a += ((b & d) | (c & ~d)) + x[ 9] + 0x21e1cde6;
        a = Integer.rotateLeft(a,  5) + b;
        d += ((a & c) | (b & ~c)) + x[14] + 0xc33707d6;
        d = Integer.rotateLeft(d,  9) + a;
        c += ((d & b) | (a & ~b)) + x[ 3] + 0xf4d50d87;
        c = Integer.rotateLeft(c, 14) + d;
        b += ((c & a) | (d & ~a)) + x[ 8] + 0x455a14ed;
        b = Integer.rotateLeft(b, 20) + c;

        a += ((b & d) | (c & ~d)) + x[13] + 0xa9e3e905;
        a = Integer.rotateLeft(a,  5) + b;
        d += ((a & c) | (b & ~c)) + x[ 2] + 0xfcefa3f8;
        d = Integer.rotateLeft(d,  9) + a;
        c += ((d & b) | (a & ~b)) + x[ 7] + 0x676f02d9;
        c = Integer.rotateLeft(c, 14) + d;
        b += ((c & a) | (d & ~a)) + x[12] + 0x8d2a4c8a;
        b = Integer.rotateLeft(b, 20) + c;

        // Round #3

        a += (b ^ c ^ d) + x[ 5] + 0xfffa3942;
        a = Integer.rotateLeft(a,  4) + b;
        d += (a ^ b ^ c) + x[ 8] + 0x8771f681;
        d = Integer.rotateLeft(d, 11) + a;
        c += (d ^ a ^ b) + x[11] + 0x6d9d6122;
        c = Integer.rotateLeft(c, 16) + d;
        b += (c ^ d ^ a) + x[14] + 0xfde5380c;
        b = Integer.rotateLeft(b, 23) + c;

        a += (b ^ c ^ d) + x[ 1] + 0xa4beea44;
        a = Integer.rotateLeft(a,  4) + b;
        d += (a ^ b ^ c) + x[ 4] + 0x4bdecfa9;
        d = Integer.rotateLeft(d, 11) + a;
        c += (d ^ a ^ b) + x[ 7] + 0xf6bb4b60;
        c = Integer.rotateLeft(c, 16) + d;
        b += (c ^ d ^ a) + x[10] + 0xbebfbc70;
        b = Integer.rotateLeft(b, 23) + c;

        a += (b ^ c ^ d) + x[13] + 0x289b7ec6;
        a = Integer.rotateLeft(a,  4) + b;
        d += (a ^ b ^ c) + x[ 0] + 0xeaa127fa;
        d = Integer.rotateLeft(d, 11) + a;
        c += (d ^ a ^ b) + x[ 3] + 0xd4ef3085;
        c = Integer.rotateLeft(c, 16) + d;
        b += (c ^ d ^ a) + x[ 6] + 0x04881d05;
        b = Integer.rotateLeft(b, 23) + c;

        a += (b ^ c ^ d) + x[ 9] + 0xd9d4d039;
        a = Integer.rotateLeft(a,  4) + b;
        d += (a ^ b ^ c) + x[12] + 0xe6db99e5;
        d = Integer.rotateLeft(d, 11) + a;
        c += (d ^ a ^ b) + x[15] + 0x1fa27cf8;
        c = Integer.rotateLeft(c, 16) + d;
        b += (c ^ d ^ a) + x[ 2] + 0xc4ac5665;
        b = Integer.rotateLeft(b, 23) + c;

        // Round #4

        a += (c ^ (b | ~d)) + x[ 0] + 0xf4292244;
        a = Integer.rotateLeft(a,  6) + b;
        d += (b ^ (a | ~c)) + x[ 7] + 0x432aff97;
        d = Integer.rotateLeft(d, 10) + a;
        c += (a ^ (d | ~b)) + x[14] + 0xab9423a7;
        c = Integer.rotateLeft(c, 15) + d;
        b += (d ^ (c | ~a)) + x[ 5] + 0xfc93a039;
        b = Integer.rotateLeft(b, 21) + c;

        a += (c ^ (b | ~d)) + x[12] + 0x655b59c3;
        a = Integer.rotateLeft(a,  6) + b;
        d += (b ^ (a | ~c)) + x[ 3] + 0x8f0ccc92;
        d = Integer.rotateLeft(d, 10) + a;
        c += (a ^ (d | ~b)) + x[10] + 0xffeff47d;
        c = Integer.rotateLeft(c, 15) + d;
        b += (d ^ (c | ~a)) + x[ 1] + 0x85845dd1;
        b = Integer.rotateLeft(b, 21) + c;

        a += (c ^ (b | ~d)) + x[ 8] + 0x6fa87e4f;
        a = Integer.rotateLeft(a,  6) + b;
        d += (b ^ (a | ~c)) + x[15] + 0xfe2ce6e0;
        d = Integer.rotateLeft(d, 10) + a;
        c += (a ^ (d | ~b)) + x[ 6] + 0xa3014314;
        c = Integer.rotateLeft(c, 15) + d;
        b += (d ^ (c | ~a)) + x[13] + 0x4e0811a1;
        b = Integer.rotateLeft(b, 21) + c;

        a += (c ^ (b | ~d)) + x[ 4] + 0xf7537e82;
        a = Integer.rotateLeft(a,  6) + b;
        d += (b ^ (a | ~c)) + x[11] + 0xbd3af235;
        d = Integer.rotateLeft(d, 10) + a;
        c += (a ^ (d | ~b)) + x[ 2] + 0x2ad7d2bb;
        c = Integer.rotateLeft(c, 15) + d;
        b += (d ^ (c | ~a)) + x[ 9] + 0xeb86d391;
        b = Integer.rotateLeft(b, 21) + c;

        state.state[0] += a;
        state.state[1] += b;
        state.state[2] += c;
        state.state[3] += d;

        return state;
    }
}
