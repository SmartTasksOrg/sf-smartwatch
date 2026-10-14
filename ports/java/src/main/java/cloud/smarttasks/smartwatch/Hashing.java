package cloud.smarttasks.smartwatch;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Seeded FNV-1a (32 and 64 bit), MurmurHash3's fmix64 finalizer and SHA-256 (spec/SEMANTICS.md section 4).
 *
 * <p>The hashes run over UTF-8(seed) || 0x00 || UTF-8(text). Java's {@code long} is signed; the bits are those
 * of the unsigned value, so the 64-bit results print with {@link Long#toUnsignedString(long)} and shift with
 * {@code >>>}. The 32-bit hash is returned as a non-negative {@code long}.
 */
public final class Hashing {
    private Hashing() {}

    public static final long FNV32_OFFSET = 2166136261L;
    public static final long FNV32_PRIME = 16777619L;
    public static final long FNV64_OFFSET = 0xcbf29ce484222325L; // 14695981039346656037
    public static final long FNV64_PRIME = 0x100000001b3L;       // 1099511628211

    static byte[] seeded(String seed, String text) {
        byte[] s = seed.getBytes(StandardCharsets.UTF_8);
        byte[] t = text.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[s.length + 1 + t.length];
        System.arraycopy(s, 0, out, 0, s.length);
        System.arraycopy(t, 0, out, s.length + 1, t.length);
        return out;
    }

    /** FNV-1a 32 of UTF-8(seed) || 0x00 || UTF-8(text), 0 .. 2^32 - 1. */
    public static long fnv1a32(String seed, String text) {
        int h = (int) FNV32_OFFSET;
        for (byte b : seeded(seed, text)) {
            h ^= (b & 0xff);
            h *= (int) FNV32_PRIME;
        }
        return h & 0xffffffffL;
    }

    /** FNV-1a 64 of UTF-8(seed) || 0x00 || UTF-8(text); the bits of the unsigned value. */
    public static long fnv1a64(String seed, String text) {
        long h = FNV64_OFFSET;
        for (byte b : seeded(seed, text)) {
            h ^= (b & 0xff);
            h *= FNV64_PRIME;
        }
        return h;
    }

    /** MurmurHash3 fmix64 (all arithmetic modulo 2^64). */
    public static long mix64(long h) {
        h ^= h >>> 33;
        h *= 0xff51afd7ed558ccdL;
        h ^= h >>> 33;
        h *= 0xc4ceb9fe1a85ec53L;
        h ^= h >>> 33;
        return h;
    }

    /** A pair's bucket: fnv1a32(seed, text) mod 2^20. */
    public static int bucket(String seed, String text) { return (int) (fnv1a32(seed, text) & ((1 << 20) - 1)); }

    /** Lower-case hex SHA-256. */
    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("the JDK has no SHA-256", e);
        }
    }
}
