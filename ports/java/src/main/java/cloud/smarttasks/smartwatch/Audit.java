package cloud.smarttasks.smartwatch;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Audit chain verification (spec/SEMANTICS.md section 8). Each record carries seq, prev (the hash of the
 *  record before, 64 zeros for the first) and hash = lower-case hex SHA-256 of the canonical JSON of the record
 *  without "hash". */
public final class Audit {
    private Audit() {}

    public static final String GENESIS = "0".repeat(64);

    /** The result of {@link #verify}: ok, or the index of the first bad record. */
    public record Result(boolean ok, Long index, String message) {}

    /** SHA-256 of the canonical JSON of the record without its "hash"; IllegalArgumentException when the record
     *  has no canonical form. */
    public static String recordHash(Map<?, ?> record) {
        Map<Object, Object> body = new LinkedHashMap<>(record);
        body.remove("hash");
        return Hashing.sha256Hex(Json.canonicalBytes(body));
    }

    public static Result verify(List<?> records) {
        String prev = GENESIS;
        for (int i = 0; i < records.size(); i++) {
            Object o = records.get(i);
            if (!(o instanceof Map<?, ?> r) || !(r.get("seq") instanceof Long seq) || seq != i) {
                return new Result(false, (long) i, "record " + i + ": seq is not " + i);
            }
            if (!prev.equals(r.get("prev"))) {
                return new Result(false, (long) i, "record " + i + ": prev does not match the hash of record " + (i - 1));
            }
            String h;
            try {
                h = recordHash(r);
            } catch (IllegalArgumentException e) {
                return new Result(false, (long) i, "record " + i + ": has no canonical form");
            }
            if (!h.equals(r.get("hash"))) return new Result(false, (long) i, "record " + i + ": hash does not match its content");
            prev = h;
        }
        return new Result(true, null, records.size() + " records, chain intact, head " + prev);
    }
}
