import java.util.Random;

public class SboxGenerator {
    protected int[][] sbox = new int[8][16];
    protected Random rnd = new Random();
    protected int totalRounds = 0;

    public void init() {
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 16; j++) {
                sbox[i][j] = j;
            }
        }
    }

    public void shuffle(int rounds) {
        for (int r = 0; r < rounds; r++) {
            rnd.setSeed(System.nanoTime() ^ rnd.nextLong());

            for (int i = 0; i < sbox.length; i++) {
                shuffleRow(sbox[i]);
            }
        }

        for (int i = 0; i < sbox.length; i++) {
            while (!checkRow(sbox[i])) {
                shuffleRow(sbox[i]);
            }
        }
    }

    protected void shuffleRow(int[] row) {
        for (int i = 0; i < row.length; i++) {
            int r = rnd.nextInt(row.length - 1);
            int t = row[r];
            row[r] = row[i];
            row[i] = t;
        }

        totalRounds++;
    }

    protected static boolean checkRow(int[] row) {
        float[][] p = new float[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int n = 0;
                for (int k = 0; k < 16; k++) {
                    n += (row[k] >> i & 1) ^ (k >> j & 1);
                }

                p[i][j] = 1 - (float)n / 8;

                if (Math.abs(p[i][j]) > 0.5) {
                    return false;
                }
            }
        }

        return true;
    }

    public void printSbox() {
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 16; j++) {
                System.out.printf("%2d  ", sbox[i][j]);
            }
            System.out.println();
        }
    }

    public static void main(String[] args) {
        long t0, t1;

        SboxGenerator generator = new SboxGenerator();
        generator.init();

        t0 = System.currentTimeMillis();
        generator.shuffle(1000);
        t1 = System.currentTimeMillis();

        generator.printSbox();

        System.out.println(t1 - t0);
        System.out.println(generator.totalRounds);
    }
}
