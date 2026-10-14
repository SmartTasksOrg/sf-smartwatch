using System.Text;

namespace SmartWatch;

/// <summary>
/// Seeded FNV-1a hashes (32 and 64 bit) over UTF-8(seed) ‖ 0x00 ‖ UTF-8(text), and the MurmurHash3 fmix64
/// finalizer (spec/SEMANTICS.md, section 4). Unsigned arithmetic wrapping modulo 2^32 / 2^64.
/// </summary>
public static class Hashing
{
    static readonly UTF8Encoding Utf8 = new(false, true);

    static uint Feed32(uint h, byte[] bytes)
    {
        foreach (var b in bytes) h = unchecked((h ^ b) * 16777619u);
        return h;
    }

    static ulong Feed64(ulong h, byte[] bytes)
    {
        foreach (var b in bytes) h = unchecked((h ^ b) * 1099511628211UL);
        return h;
    }

    public static uint Fnv1a32(string seed, string text)
    {
        var h = Feed32(2166136261u, Utf8.GetBytes(seed));
        h = unchecked((h ^ 0u) * 16777619u);
        return Feed32(h, Utf8.GetBytes(text));
    }

    public static ulong Fnv1a64(string seed, string text)
    {
        var h = Feed64(14695981039346656037UL, Utf8.GetBytes(seed));
        h = unchecked((h ^ 0UL) * 1099511628211UL);
        return Feed64(h, Utf8.GetBytes(text));
    }

    public static ulong Mix64(ulong h)
    {
        unchecked
        {
            h ^= h >> 33;
            h *= 0xFF51AFD7ED558CCDUL;
            h ^= h >> 33;
            h *= 0xC4CEB9FE1A85EC53UL;
            h ^= h >> 33;
            return h;
        }
    }

    /// <summary>The bucket of a pair text: fnv1a32(seed, text) mod 2^20.</summary>
    public static int Bucket(string seed, string text) => (int)(Fnv1a32(seed, text) & 0xFFFFF);
}
