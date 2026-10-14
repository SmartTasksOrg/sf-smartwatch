namespace SmartWatch;

/// <summary>Calibration thresholds (spec/SEMANTICS.md, section 7): nearest-rank percentiles in permille, made
/// strictly increasing and at least 1.</summary>
public static class Calibrate
{
    /// <summary>prod: p95, p99, p99.9.</summary>
    public static readonly long[] Prod = { 950, 990, 999 };
    /// <summary>staging: p90, p95, p99.</summary>
    public static readonly long[] Staging = { 900, 950, 990 };

    /// <summary>Thresholds over parsed JSON values (see <see cref="Json"/>): a density that is not an integer &gt;= 0
    /// (1.5, true, "5", -2) or a percentile that is not an integer throws ArgumentException.</summary>
    public static List<long> Thresholds(IEnumerable<object?> densities, IEnumerable<object?> permille) =>
        Thresholds(densities.Select(d => d is long l && l >= 0 ? l : throw new ArgumentException("densities are integers >= 0")).ToList(),
            permille.Select(p => p is long l ? l : throw new ArgumentException("percentiles are integers from 1 to 1000 (permille)")).ToList());

    /// <summary>Throws ArgumentException when <paramref name="densities"/> is empty or a density is negative or a percentile is not 1 … 1000.</summary>
    public static List<long> Thresholds(IEnumerable<long> densities, IEnumerable<long> permille)
    {
        var xs = densities.ToList();
        if (xs.Count == 0) throw new ArgumentException("no densities to calibrate from");
        if (xs.Any(d => d < 0)) throw new ArgumentException("densities are integers >= 0");
        xs.Sort();
        long n = xs.Count, prev = 0;
        var outv = new List<long>();
        foreach (var p in permille)
        {
            if (p < 1 || p > 1000) throw new ArgumentException("percentiles are integers from 1 to 1000 (permille)");
            var rank = (p * n + 999) / 1000;
            var v = Math.Max(Math.Max(xs[(int)(Math.Max(rank, 1) - 1)], prev + 1), 1);
            outv.Add(v);
            prev = v;
        }
        return outv;
    }
}
