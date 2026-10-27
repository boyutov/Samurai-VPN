package dev.samurai.vpn.server;

import java.nio.charset.StandardCharsets;

/** One-shot BLAKE2s (RFC 7693), used only to check WireGuard mac1 on relayed handshakes. */
final class Blake2s {
    private static final int[] IV = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
    private static final byte[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
    private static final byte[] MAC1_LABEL = "mac1----".getBytes(StandardCharsets.US_ASCII);
    private Blake2s() {}

    static byte[] hash(byte[] key, byte[] data, int offset, int length, int outLength) {
        if (outLength < 1 || outLength > 32 || key.length > 32 || offset < 0 || length < 0 || offset + length > data.length)
            throw new IllegalArgumentException("Invalid BLAKE2s parameters");
        int[] h = IV.clone();
        h[0] ^= 0x01010000 ^ (key.length << 8) ^ outLength;
        byte[] block = new byte[64];
        long counter = 0;
        int position = 0;
        boolean pendingKey = key.length > 0;
        if (pendingKey) System.arraycopy(key, 0, block, 0, key.length);
        // The key occupies a full first block; the last block (possibly empty) is compressed with the final flag.
        if (pendingKey && length > 0) { counter = 64; compress(h, block, 0, counter, false); pendingKey = false; }
        else if (pendingKey) { compress(h, block, 0, 64, true); return output(h, outLength); }
        while (length - position > 64) {
            counter += 64; compress(h, data, offset + position, counter, false); position += 64;
        }
        byte[] last = new byte[64];
        System.arraycopy(data, offset + position, last, 0, length - position);
        counter += length - position;
        compress(h, last, 0, counter, true);
        return output(h, outLength);
    }
    static byte[] hash(byte[] data) { return hash(new byte[0], data, 0, data.length, 32); }

    /** WireGuard mac1 for a handshake message addressed to the given 32-byte recipient public key. */
    static boolean validMac1(byte[] recipientPublicKey, byte[] message, int length) {
        if (length < 32) return false;
        byte[] label = new byte[MAC1_LABEL.length + recipientPublicKey.length];
        System.arraycopy(MAC1_LABEL, 0, label, 0, MAC1_LABEL.length);
        System.arraycopy(recipientPublicKey, 0, label, MAC1_LABEL.length, recipientPublicKey.length);
        byte[] expected = hash(hash(label), message, 0, length - 32, 16);
        int difference = 0;
        for (int i = 0; i < 16; i++) difference |= expected[i] ^ message[length - 32 + i];
        return difference == 0;
    }

    private static byte[] output(int[] h, int outLength) {
        byte[] out = new byte[outLength];
        for (int i = 0; i < outLength; i++) out[i] = (byte) (h[i / 4] >>> (8 * (i % 4)));
        return out;
    }
    private static void compress(int[] h, byte[] block, int offset, long counter, boolean last) {
        int[] m = new int[16], v = new int[16];
        for (int i = 0; i < 16; i++) {
            int p = offset + 4 * i;
            m[i] = (block[p] & 0xFF) | (block[p + 1] & 0xFF) << 8 | (block[p + 2] & 0xFF) << 16 | (block[p + 3] & 0xFF) << 24;
        }
        System.arraycopy(h, 0, v, 0, 8); System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= (int) counter; v[13] ^= (int) (counter >>> 32);
        if (last) v[14] = ~v[14];
        for (byte[] s : SIGMA) {
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]); g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]); g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]); g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]); g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }
    private static void g(int[] v, int a, int b, int c, int d, int x, int y) {
        v[a] += v[b] + x; v[d] = Integer.rotateRight(v[d] ^ v[a], 16);
        v[c] += v[d]; v[b] = Integer.rotateRight(v[b] ^ v[c], 12);
        v[a] += v[b] + y; v[d] = Integer.rotateRight(v[d] ^ v[a], 8);
        v[c] += v[d]; v[b] = Integer.rotateRight(v[b] ^ v[c], 7);
    }
}
