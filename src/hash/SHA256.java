package hash;

import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author moles
 */
public class SHA256 {

    private final byte[] block = new byte[64];
    private final int[] words = new int[64];
    private static final int[] H = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };
    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /**
     * SHA-256
     *
     * @param message string message
     * @return The 256 bit hash
     */
    public String digest(String message) {
        byte[] data=message.getBytes();
        byte[] p = prepareData(data);
        int tmp;
        int[] h = Arrays.copyOf(H, 8);
        for (int i = 0; i < p.length / 64; ++i) {
            int[] state = Arrays.copyOf(h, 8);
            tmp = 64 * i;
            for (int j = 0; j < 64; j++) {
                block[j] = p[tmp];
                tmp++;
            }
            setWords();
            for (int j = 0; j < 64; ++j) {
                transform(state,j);
            }
            for (int j = 0; j < 8; ++j) {
                h[j] += state[j];
            }
        }
        byte[] hash = new byte[32];
        for (int i = 0; i < 8; i++) {
            byte[] intToBytes = convertIntToByteArray(h[i]);
            tmp = 4 * i;
            for (int j = 0; j < 4; j++) {
                hash[tmp] = intToBytes[j];
                tmp++;
            }
        }
        String result = DatatypeConverter.printHexBinary(hash);
        return result;
    }

    /**
     * set words
     */
    private void setWords() {
        for (int j = 0; j < 16; j++) {
            words[j] = 0;
            for (int m = 0; m < 4; m++) {
                words[j] |= ((block[j * 4 + m] & 0x000000FF) << (24 - m * 8));
            }
        }
        for (int j = 16; j < 64; ++j) {
            int s0 = Integer.rotateRight(words[j - 15], 7)
                    ^ Integer.rotateRight(words[j - 15], 18)
                    ^ (words[j - 15] >>> 3);

            int s1 = Integer.rotateRight(words[j - 2], 17)
                    ^ Integer.rotateRight(words[j - 2], 19)
                    ^ (words[j - 2] >>> 10);

            words[j] = words[j - 16] + s0 + words[j - 7] + s1;
        }
    }
    /**
     * 
     * @param state state
     * @param words words
     * @param i index
     */
    private void transform(int[] state, int i) {
        int S0 = Integer.rotateRight(state[0], 2)
                ^ Integer.rotateRight(state[0], 13)
                ^ Integer.rotateRight(state[0], 22);

        int maj = (state[0] & state[1])
                ^ (state[0] & state[2])
                ^ (state[1] & state[2]);

        int tmp = S0 + maj;

        int S1 = Integer.rotateRight(state[4], 6)
                ^ Integer.rotateRight(state[4], 11)
                ^ Integer.rotateRight(state[4], 25);

        int ch = (state[4] & state[5])
                ^ (~state[4] & state[6]);

        int tmp2 = state[7] + S1 + ch + K[i] + words[i];

        state[7] = state[6];
        state[6] = state[5];
        state[5] = state[4];
        state[4] = state[3] + tmp2;
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = tmp + tmp2;
    }

    /**
     *
     * @param data
     * @return change data
     */
    private byte[] prepareData(byte[] data) {
        int n = data.length;
        int tmp = n % 64;
        int j;
        int p;
        long b = n * 8;
        if ((64 - tmp >= 9)) {
            p = 64 - tmp;
        } else {
            p = 128 - tmp;
        }
        byte[] result = new byte[n + p];
        byte[] added = new byte[p];
        added[0] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            added[p - i - 1] = (byte) ((b >>> (8 * i)) & 0xFF);
        }
        for (int i = 0; i < n; i++) {
            result[i] = data[i];
        }
        j = n;
        for (int i = 0; i < p; i++) {
            result[j] = added[i];
            j++;
        }
        return result;
    }

    /**
     *
     * @param i int value
     * @return byte value
     */
    public byte[] convertIntToByteArray(int i) {
        byte[] b = new byte[4];
        for (int j = 0; j < 4; j++) {
            b[j] = (byte) ((i >>> (56 - 8 * j)) & 0xff);
        }
        return b;
    }
}
