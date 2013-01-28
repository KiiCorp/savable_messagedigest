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
        if (this.finalState != null) {
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
        // TODO:
        return state;
    }
}
