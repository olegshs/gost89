import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Gost89 {
    protected int[][] sbox;
    protected int[][] sbox_x;
    protected int[] key;
    protected int[] iv;
    protected int[] mac;

    public Gost89() {
        sbox = new int[8][16];
        sbox_x = new int[4][256];
        key = new int[8];
        iv = new int[2];
        mac = new int[2];
    }

    public void setSbox(int[][] sbox) {
        for (int i = 0; i < 8; i++) {
            System.arraycopy(sbox[i], 0, this.sbox[i], 0, 16);
        }

        expandSbox();
    }

    protected void expandSbox() {
        for (int i = 0; i < 256; i++) {
            int j = i / 16;
            int k = i % 16;

            sbox_x[0][i] = sbox[1][j] << 4 | sbox[0][k];
            sbox_x[1][i] = sbox[3][j] << 4 | sbox[2][k];
            sbox_x[2][i] = sbox[5][j] << 4 | sbox[4][k];
            sbox_x[3][i] = sbox[7][j] << 4 | sbox[6][k];
        }
    }

    public void setKey(int[] key) {
        System.arraycopy(key, 0, this.key, 0, 8);
    }

    public void setKey(byte[] key) {
        ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(this.key);
    }

    public void setIv(int[] iv) {
        this.iv[0] = iv[0];
        this.iv[1] = iv[1];
    }

    public void setIv(long iv) {
        this.iv[0] = (int)(iv & 0xFFFFFFFF);
        this.iv[1] = (int)(iv >> 32 & 0xFFFFFFFF);
    }

    public void setIv(byte[] iv) {
        ByteBuffer bb = ByteBuffer.wrap(iv).order(ByteOrder.LITTLE_ENDIAN);

        this.iv[0] = bb.getInt();
        this.iv[1] = bb.getInt();
    }

    public void resetMac() {
        this.mac[0] = 0;
        this.mac[1] = 0;
    }

    public int round(int block, int key) {
        int t = block + key;

        t = sbox_x[0][t & 0xFF] |
            sbox_x[1][t >> 8 & 0xFF] << 8 |
            sbox_x[2][t >> 16 & 0xFF] << 16 |
            sbox_x[3][t >> 24 & 0xFF] << 24;

        t = t << 11 | (t >> 21 & 0x7FF);

        return t;
    }

    public int[] encrypt(int[] plain) {
        int a = plain[0];
        int b = plain[1];
        int t;

        for (int i = 0; i < 3; i++) {
            /*
                b ^= round(a, key[0]);
                a ^= round(b, key[1]);
                b ^= round(a, key[2]);
                a ^= round(b, key[3]);
                b ^= round(a, key[4]);
                a ^= round(b, key[5]);
                b ^= round(a, key[6]);
                a ^= round(b, key[7]);
            */
            for (int j = 0; j < 8; j += 2) {
                t = a + key[j];
                t = sbox_x[0][t & 0xFF] |
                    sbox_x[1][t >> 8 & 0xFF] << 8 |
                    sbox_x[2][t >> 16 & 0xFF] << 16 |
                    sbox_x[3][t >> 24 & 0xFF] << 24;
                b ^= t << 11 | (t >> 21 & 0x7FF);

                t = b + key[j + 1];
                t = sbox_x[0][t & 0xFF] |
                    sbox_x[1][t >> 8 & 0xFF] << 8 |
                    sbox_x[2][t >> 16 & 0xFF] << 16 |
                    sbox_x[3][t >> 24 & 0xFF] << 24;
                a ^= t << 11 | (t >> 21 & 0x7FF);
            }
        }

        /*
            b ^= round(a, key[7]);
            a ^= round(b, key[6]);
            b ^= round(a, key[5]);
            a ^= round(b, key[4]);
            b ^= round(a, key[3]);
            a ^= round(b, key[2]);
            b ^= round(a, key[1]);
            a ^= round(b, key[0]);
        */
        for (int j = 7; j > 0; j -= 2) {
            t = a + key[j];
            t = sbox_x[0][t & 0xFF] |
                sbox_x[1][t >> 8 & 0xFF] << 8 |
                sbox_x[2][t >> 16 & 0xFF] << 16 |
                sbox_x[3][t >> 24 & 0xFF] << 24;
            b ^= t << 11 | (t >> 21 & 0x7FF);

            t = b + key[j - 1];
            t = sbox_x[0][t & 0xFF] |
                sbox_x[1][t >> 8 & 0xFF] << 8 |
                sbox_x[2][t >> 16 & 0xFF] << 16 |
                sbox_x[3][t >> 24 & 0xFF] << 24;
            a ^= t << 11 | (t >> 21 & 0x7FF);
        }

        return new int[]{b, a};
    }

    public byte[] encrypt(byte[] plain) {
        ByteBuffer bb = ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN);
        int[] encrypted = encrypt(new int[]{bb.getInt(), bb.getInt()});
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(encrypted[0]).putInt(encrypted[1]).array();
    }

    public int[] decrypt(int[] encrypted) {
        int a = encrypted[0];
        int b = encrypted[1];
        int t;

        for (int j = 0; j < 8; j += 2) {
            t = a + key[j];
            t = sbox_x[0][t & 0xFF] |
                sbox_x[1][t >> 8 & 0xFF] << 8 |
                sbox_x[2][t >> 16 & 0xFF] << 16 |
                sbox_x[3][t >> 24 & 0xFF] << 24;
            b ^= t << 11 | (t >> 21 & 0x7FF);

            t = b + key[j + 1];
            t = sbox_x[0][t & 0xFF] |
                sbox_x[1][t >> 8 & 0xFF] << 8 |
                sbox_x[2][t >> 16 & 0xFF] << 16 |
                sbox_x[3][t >> 24 & 0xFF] << 24;
            a ^= t << 11 | (t >> 21 & 0x7FF);
        }

        for (int i = 0; i < 3; i++) {
            for (int j = 7; j > 0; j -= 2) {
                t = a + key[j];
                t = sbox_x[0][t & 0xFF] |
                    sbox_x[1][t >> 8 & 0xFF] << 8 |
                    sbox_x[2][t >> 16 & 0xFF] << 16 |
                    sbox_x[3][t >> 24 & 0xFF] << 24;
                b ^= t << 11 | (t >> 21 & 0x7FF);

                t = b + key[j - 1];
                t = sbox_x[0][t & 0xFF] |
                    sbox_x[1][t >> 8 & 0xFF] << 8 |
                    sbox_x[2][t >> 16 & 0xFF] << 16 |
                    sbox_x[3][t >> 24 & 0xFF] << 24;
                a ^= t << 11 | (t >> 21 & 0x7FF);
            }
        }

        return new int[]{b, a};
    }

    public byte[] decrypt(byte[] encrypted) {
        ByteBuffer bb = ByteBuffer.wrap(encrypted).order(ByteOrder.LITTLE_ENDIAN);
        int[] plain = decrypt(new int[]{bb.getInt(), bb.getInt()});
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(plain[0]).putInt(plain[1]).array();
    }

    public int[] encryptECB(int[] plain) {
        int length = plain.length;
        int[] encrypted = new int[length];
        int[] block = new int[2];

        for (int i = 0; i < length; i += 2) {
            System.arraycopy(plain, i, block, 0, 2);
            block = encrypt(block);
            System.arraycopy(block, 0, encrypted, i, 2);
        }

        return encrypted;
    }

    public byte[] encryptECB(byte[] plain) {
        return intArrayToByteArray(
            encryptECB(
                byteArrayToIntArray(plain)
            )
        );
    }

    public int[] decryptECB(int[] encrypted) {
        int length = encrypted.length;
        int[] plain = new int[length];
        int[] block = new int[2];

        for (int i = 0; i < length; i += 2) {
            System.arraycopy(encrypted, i, block, 0, 2);
            block = decrypt(block);
            System.arraycopy(block, 0, plain, i, 2);
        }

        return plain;
    }

    public byte[] decryptECB(byte[] encrypted) {
        return intArrayToByteArray(
            decryptECB(
                byteArrayToIntArray(encrypted)
            )
        );
    }

    public void initCTR() {
        iv = encrypt(iv);
    }

    public int[] encryptCTR(int[] plain) {
        int length = plain.length;
        int[] encrypted = new int[length];
        int[] t;

        for (int i = 0; i < length; i += 2) {
            iv[0] += 0x1010101;

            if (iv[1] < 0 && iv[1] > 0xFFFFFFFF - 0x1010104) {
                iv[1] += 0x1010104 + 1;
            } else {
                iv[1] += 0x1010104;
            }

            t = encrypt(iv);

            encrypted[i] = plain[i] ^ t[0];
            encrypted[i + 1] = plain[i + 1] ^ t[1];
        }

        return encrypted;
    }

    public byte[] encryptCTR(byte[] plain) {
        return Arrays.copyOf(intArrayToByteArray(
            encryptCTR(
                byteArrayToIntArray(plain)
            )
        ), plain.length);
    }

    public int[] encryptCFB(int[] plain) {
        int length = plain.length;
        int[] encrypted = new int[length];
        int[] t;

        for (int i = 0; i < length; i += 2) {
            t = encrypt(iv);

            encrypted[i] = plain[i] ^ t[0];
            encrypted[i + 1] = plain[i + 1] ^ t[1];

            iv[0] = encrypted[i];
            iv[1] = encrypted[i + 1];
        }

        return encrypted;
    }

    public byte[] encryptCFB(byte[] plain) {
        return Arrays.copyOf(intArrayToByteArray(
            encryptCFB(
                byteArrayToIntArray(plain)
            )
        ), plain.length);
    }

    public int[] decryptCFB(int[] encrypted) {
        int length = encrypted.length;
        int[] plain = new int[length];
        int[] t;

        for (int i = 0; i < length; i += 2) {
            t = encrypt(iv);

            plain[i] = encrypted[i] ^ t[0];
            plain[i + 1] = encrypted[i + 1] ^ t[1];

            iv[0] = encrypted[i];
            iv[1] = encrypted[i + 1];
        }

        return plain;
    }

    public byte[] decryptCFB(byte[] encrypted) {
        return Arrays.copyOf(intArrayToByteArray(
            decryptCFB(
                byteArrayToIntArray(encrypted)
            )
        ), encrypted.length);
    }

    public int computeMac(int[] plain) {
        int length = plain.length;

        for (int i = 0; i < length; i += 2) {
            mac[0] ^= plain[i];
            mac[1] ^= plain[i + 1];

            mac = encrypt16(mac);
        }

        return mac[1];
    }

    public int computeMac(byte[] plain) {
        return computeMac(
            byteArrayToIntArray(plain)
        );
    }

    public int getMac() {
        return mac[1];
    }

    protected int[] encrypt16(int[] plain) {
        int a = plain[0];
        int b = plain[1];
        int t;

        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 8; j += 2) {
                t = a + key[j];
                t = sbox_x[0][t & 0xFF] |
                    sbox_x[1][t >> 8 & 0xFF] << 8 |
                    sbox_x[2][t >> 16 & 0xFF] << 16 |
                    sbox_x[3][t >> 24 & 0xFF] << 24;
                b ^= t << 11 | (t >> 21 & 0x7FF);

                t = b + key[j + 1];
                t = sbox_x[0][t & 0xFF] |
                    sbox_x[1][t >> 8 & 0xFF] << 8 |
                    sbox_x[2][t >> 16 & 0xFF] << 16 |
                    sbox_x[3][t >> 24 & 0xFF] << 24;
                a ^= t << 11 | (t >> 21 & 0x7FF);
            }
        }

        return new int[]{a, b};
    }

    protected byte[] intArrayToByteArray(int[] intArray) {
        ByteBuffer bb = ByteBuffer.allocate(intArray.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        bb.asIntBuffer().put(intArray);
        return bb.array();
    }

    protected int[] byteArrayToIntArray(byte[] byteArr) {
        int length = (byteArr.length - 1) / 4 + 1;
        int[] intArray = new int[length];
        byte[] t = Arrays.copyOf(byteArr, length * 4);
        ByteBuffer.wrap(t).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(intArray);
        return intArray;
    }

    /**
     * TODO: remove
     */
    public void printSbox() {
        for (int i = 0; i < 8; i++) {
            System.out.print("{ ");
            for (int j = 0; j < 16; j++) {
                System.out.print(sbox[i][j] + ", ");
            }
            System.out.print("}\n");
        }
    }

    public void printKey() {
        for (int i = 0; i < 8; i++) {
            System.out.printf("%08x ", key[i]);
        }
        System.out.println();
    }

    public void printIv() {
        System.out.printf("%08x%08x\n", iv[1], iv[0]);
    }

    public void printMac() {
        System.out.printf("%08x\n", mac[1]);
    }
}
