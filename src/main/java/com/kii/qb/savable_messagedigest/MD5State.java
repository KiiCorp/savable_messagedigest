package com.kii.qb.savable_messagedigest;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.DataInputStream;
import java.util.Map;

public final class MD5State
{
    public static final String LABEL_STATE = "state";
    public static final String LABEL_COUNT = "count";
    public static final String LABEL_BUFFER = "buffer";

    final int state[] = new int[4];
    long count;
    final byte buffer[] = new byte[64];

    public MD5State() {
        this.state[0] = 0x67452301;
        this.state[1] = 0xefcdab89;
        this.state[2] = 0X98badcfe;
        this.state[3] = 0x10325476;
    }

    public MD5State(MD5State src) {
        System.arraycopy(src.state, 0, this.state, 0, this.state.length);
        this.count = src.count;
        System.arraycopy(src.buffer, 0, this.buffer, 0, this.buffer.length);
    }

    public void save(DataOutputStream output) throws IOException
    {
        for (int i = 0; i < this.state.length; ++i) {
            output.writeInt(this.state[i]);
        }
        output.writeLong(count);
        output.write(this.buffer, 0, this.buffer.length);
    }

    public void load(DataInputStream input) throws IOException
    {
        for (int i = 0; i < this.state.length; ++i) {
            this.state[i] = input.readInt();
        }
        this.count = input.readLong();
        if (input.read(this.buffer, 0, this.buffer.length) !=
                this.buffer.length)
            throw new IOException("Too short to load buffer");
    }

    public void save(Map<String, Object> map) {
        map.put(LABEL_STATE, Utils.toString(Utils.getBytes(this.state)));
        map.put(LABEL_COUNT, Long.toString(this.count));
        map.put(LABEL_BUFFER, Utils.toString(this.buffer));
    }

    public void load(Map<String, Object> map) throws RuntimeException
    {
        // Decode each values.
        int[] loadState = new int[4];
        Utils.decodeInts(Utils.toByteArray(map.get(LABEL_STATE).toString()),
                loadState);
        long loadCount = Long.parseLong(map.get(LABEL_COUNT).toString());
        byte[] loadBuffer = Utils.toByteArray(
                map.get(LABEL_BUFFER).toString());
        // Extra check values.
        if (loadBuffer.length < this.buffer.length) {
            throw new RuntimeException("Too short buffer");
        }
        // Update this object.
        System.arraycopy(loadState, 0, this.state, 0, this.state.length);
        this.count = loadCount;
        System.arraycopy(loadBuffer, 0, this.buffer, 0, this.buffer.length);
    }

    public byte[] getStateBytes() {
        return Utils.getBytes(this.state);
    }

    public int getOffset() {
        return ((int)this.count) & 0x3F;
    }
}
