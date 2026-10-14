package cloud.smarttasks.smartwatch;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Calibration thresholds from observed densities (spec/SEMANTICS.md section 7): nearest-rank percentiles in
 *  permille, made strictly increasing and at least 1. */
public final class Calibrate {
    private Calibrate() {}

    public static final List<Long> PROD = List.of(950L, 990L, 999L);
    public static final List<Long> STAGING = List.of(900L, 950L, 990L);

    /** Thresholds for the permille percentiles; IllegalArgumentException when densities is empty, a density is
     *  not an integer >= 0, or a percentile is not an integer from 1 to 1000. Takes parsed JSON values. */
    public static List<Long> thresholds(List<?> densities, List<?> permille) {
        long[] xs = new long[densities.size()];
        for (int k = 0; k < xs.length; k++) {
            if (!(densities.get(k) instanceof Long d) || d < 0) throw new IllegalArgumentException("densities are integers >= 0");
            xs[k] = d;
        }
        if (xs.length == 0) throw new IllegalArgumentException("no densities to calibrate from");
        Arrays.sort(xs);
        List<Long> out = new ArrayList<>();
        long prev = 0;
        for (Object o : permille) {
            if (!(o instanceof Long p) || p < 1 || p > 1000) {
                throw new IllegalArgumentException("percentiles are integers from 1 to 1000 (permille)");
            }
            long rank = (p * xs.length + 999) / 1000;
            long v = xs[(int) Math.max(rank, 1) - 1];
            v = Math.max(v, Math.max(prev + 1, 1));
            out.add(v);
            prev = v;
        }
        return out;
    }
}
