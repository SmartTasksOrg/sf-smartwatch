using System.Numerics;
using System.Security.Cryptography;

namespace SmartWatch;

/// <summary>HyperLogLog, p = 14 (spec/SEMANTICS.md, section 5): 16,384 one-byte registers.</summary>
public sealed class HyperLogLog
{
    public const int P = 14;
    public const int M = 1 << P;
    const int MaxRho = 64 - P + 1; // 51
    readonly string seed;
    readonly byte[] reg = new byte[M];

    public HyperLogLog(string seed) { this.seed = seed; }

    public void Add(string item)
    {
        var h = Hashing.Mix64(Hashing.Fnv1a64(seed, item));
        var j = (int)(h >> (64 - P));
        var w = h & ((1UL << (64 - P)) - 1);
        var bitLength = 64 - BitOperations.LeadingZeroCount(w); // 0 for w == 0
        var rho = (byte)(MaxRho - bitLength);
        if (rho > reg[j]) reg[j] = rho;
    }

    public long Estimate()
    {
        var counts = new long[MaxRho + 1];
        foreach (var r in reg) counts[r]++;
        var z = 0.0;
        for (var v = MaxRho; v >= 0; v--)
            if (counts[v] > 0) z += counts[v] * BitConverter.Int64BitsToDouble((long)(1023 - v) << 52); // exactly 2^-v
        double m = M;
        var alpha = 0.7213 / (1 + 1.079 / m);
        var e = alpha * m * m / z;
        var zeros = counts[0];
        if (e <= 2.5 * m && zeros > 0) e = m * Math.Log(m / zeros);
        var r2 = Math.Floor(e + 0.5);
        return r2 >= Engine.MaxInt ? Engine.MaxInt : (long)r2;
    }

    /// <summary>Lower-case hex SHA-256 of the 16,384 registers.</summary>
    public string Digest() => Convert.ToHexString(SHA256.HashData(reg)).ToLowerInvariant();
}
