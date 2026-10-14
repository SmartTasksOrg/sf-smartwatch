package cloud.smarttasks.smartwatch;

/**
 * HyperLogLog with p = 14: 16,384 one-byte registers (spec/SEMANTICS.md section 5). The estimate sums
 * count[v] * 2^-v for v = 51 down to 0 in doubles, in that order, so that every engine gets the same bits.
 */
public final class HyperLogLog {
    public static final int P = 14;
    public static final int M = 1 << P;
    public static final int MAXRHO = 64 - P + 1; // 51
    static final double ALPHA = 0.7213 / (1 + 1.079 / M);
    private static final long W_MASK = (1L << (64 - P)) - 1;

    private final String seed;
    private final byte[] reg = new byte[M];

    public HyperLogLog(String seed) { this.seed = seed; }

    public void add(String item) {
        long h = Hashing.mix64(Hashing.fnv1a64(seed, item));
        int j = (int) (h >>> (64 - P));
        long w = h & W_MASK;
        int rho = MAXRHO - (64 - Long.numberOfLeadingZeros(w));
        if (rho > reg[j]) reg[j] = (byte) rho;
    }

    public long estimate() {
        int[] counts = new int[MAXRHO + 1];
        for (byte r : reg) counts[r]++;
        double z = 0.0;
        for (int v = MAXRHO; v >= 0; v--) {
            if (counts[v] > 0) z += counts[v] * Math.pow(2.0, -v);
        }
        double e = ALPHA * M * M / z;
        int zeros = counts[0];
        if (e <= 2.5 * M && zeros > 0) e = M * Math.log((double) M / zeros);
        double r = Math.floor(e + 0.5);
        return r >= Engine.MAX_INT ? Engine.MAX_INT : (long) r;
    }

    /** Lower-case hex SHA-256 of the 16,384 register bytes. */
    public String digest() { return Hashing.sha256Hex(reg.clone()); }
}
