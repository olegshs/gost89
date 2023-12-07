import java.io.*;

public class Test {
    protected static int[][] defaultSbox = {
        {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
        {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
        {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
        {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
        {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
        {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
        {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
        {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
    };
    protected static String sampleText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod " +
        "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation " +
        "ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in " +
        "voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non " +
        "proident, sunt in culpa qui officia deserunt mollit anim id est laborum. OLOLO!!!11";

    protected static Gost89 gost89;

    public static void main(String[] args) {
        gost89 = new Gost89();

        gost89.setSbox(defaultSbox);
        gost89.printSbox();

        gost89.setKey(("01234567890123456789012345678912").getBytes());
        gost89.printKey();

        test();
        testECB();
        testCTR();
        testCFB();
        benchmark();
    }

    protected static void test() {
        int i;
        byte[] plain, encrypted;

        plain = ("ABCDEFGH").getBytes();
        for (i = 0; i < 8; i++) {
            System.out.printf("%02x ", plain[i]);
        }
        System.out.println();

        encrypted = gost89.encrypt(plain);
        for (i = 0; i < 8; i++) {
            System.out.printf("%02x ", encrypted[i]);
        }
        System.out.println();

        plain = gost89.decrypt(encrypted);
        for (i = 0; i < 8; i++) {
            System.out.printf("%02x ", plain[i]);
        }
        System.out.println();
    }

    protected static void testECB() {
        byte[] plain = sampleText.getBytes();
        byte[] encrypted = gost89.encryptECB(plain);
        byte[] decrypted = gost89.decryptECB(encrypted);

        System.out.printf("%08x\n", gost89.computeMac(plain));

        writeFile("ecb.0", plain);
        writeFile("ecb.1", encrypted);
        writeFile("ecb.2", decrypted);
    }

    protected static void testCTR() {
        byte[] plain = sampleText.getBytes();

        gost89.setIv(0xFF);
        gost89.printIv();
        gost89.initCTR();
        byte[] encrypted = gost89.encryptCTR(plain);

        gost89.setIv(0xFF);
        gost89.initCTR();
        byte[] decrypted = gost89.encryptCTR(encrypted);

        writeFile("ctr.0", plain);
        writeFile("ctr.1", encrypted);
        writeFile("ctr.2", decrypted);
    }

    protected static void testCFB() {
        byte[] plain = sampleText.getBytes();

        gost89.setIv(0xFF);
        gost89.printIv();
        byte[] encrypted = gost89.encryptCFB(plain);

        gost89.setIv(0xFF);
        byte[] decrypted = gost89.decryptCFB(encrypted);

        writeFile("cfb.0", plain);
        writeFile("cfb.1", encrypted);
        writeFile("cfb.2", decrypted);
    }

    protected static void benchmark() {
        int i;
        long t0, t1;
        byte[] a, b;
        a = ("ABCDEFGH").getBytes();

        t0 = System.currentTimeMillis();
        for (i = 0; i < 5000000; i++) {
            b = gost89.encrypt(a);
            a = gost89.encrypt(b);
        }
        for (i = 0; i < 5000000; i++) {
            b = gost89.decrypt(a);
            a = gost89.decrypt(b);
        }
        t1 = System.currentTimeMillis();

        for (i = 0; i < 8; i++) {
            System.out.printf("%02x ", a[i]);
        }
        System.out.println();

        System.out.printf("%f\n", (float)(t1 - t0) / 1000);
    }

    protected static boolean writeFile(String filename, byte[] content) {
        try {
            FileOutputStream stream = new FileOutputStream(filename);
            stream.write(content);
            stream.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}
