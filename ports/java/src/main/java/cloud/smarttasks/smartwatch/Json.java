package cloud.smarttasks.smartwatch;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A small JSON reader and the canonical writer of spec/SEMANTICS.md. No dependencies.
 *
 * <p>Parsed values: objects are {@code LinkedHashMap<String, Object>}, arrays {@code ArrayList<Object>},
 * integers {@code Long}, every other number (a fraction, an exponent, or an integer outside the long range)
 * {@code Double}, strings {@code String}, {@code true}/{@code false} {@code Boolean}, {@code null} null.
 * The protocol only accepts {@code Long} where it needs an integer, so {@code 2.5}, {@code true} and
 * {@code "1"} are all refused there.
 *
 * <p>Arrays and objects may nest at most {@link #MAX_DEPTH} levels; deeper input is a parse error (the
 * parser is recursive, and a hostile answer must not exhaust the stack).
 */
public final class Json {
    /** The deepest nesting of arrays and objects the parser accepts. */
    public static final int MAX_DEPTH = 64;
    private final String s;
    private int i;
    private int depth;

    private Json(String s) { this.s = s; }

    /** Parse one JSON text; throws IllegalArgumentException on malformed input. */
    public static Object parse(String text) {
        Json p = new Json(text);
        try {
            p.ws();
            Object v = p.value();
            p.ws();
            if (p.i != p.s.length()) throw new IllegalArgumentException("trailing data at " + p.i);
            return v;
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
    }

    private void ws() { while (i < s.length() && " \n\r\t".indexOf(s.charAt(i)) >= 0) i++; }

    private char next() {
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end of JSON");
        return s.charAt(i++);
    }

    private Object value() {
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end of JSON");
        char c = s.charAt(i);
        if (c == 'n') return lit("null", null);
        if (c == 't') return lit("true", Boolean.TRUE);
        if (c == 'f') return lit("false", Boolean.FALSE);
        if (c == '"') return string();
        if (c == '[' || c == '{') {
            if (++depth > MAX_DEPTH) throw new IllegalArgumentException("JSON nested deeper than " + MAX_DEPTH + " levels");
            Object v = c == '[' ? array() : object();
            depth--;
            return v;
        }
        return number();
    }

    private Object array() {
        i++;
        List<Object> out = new ArrayList<>();
        ws();
        if (i < s.length() && s.charAt(i) == ']') { i++; return out; }
        while (true) {
            ws(); out.add(value()); ws();
            char d = next();
            if (d == ']') return out;
            if (d != ',') throw new IllegalArgumentException("bad array at " + (i - 1));
        }
    }

    private Object object() {
        i++;
        Map<String, Object> out = new LinkedHashMap<>();
        ws();
        if (i < s.length() && s.charAt(i) == '}') { i++; return out; }
        while (true) {
            ws();
            String k = string();
            ws();
            if (next() != ':') throw new IllegalArgumentException("expected : at " + (i - 1));
            ws();
            out.put(k, value());
            ws();
            char d = next();
            if (d == '}') return out;
            if (d != ',') throw new IllegalArgumentException("bad object at " + (i - 1));
        }
    }

    private Object lit(String w, Object v) {
        if (!s.startsWith(w, i)) throw new IllegalArgumentException("bad literal at " + i);
        i += w.length();
        return v;
    }

    private Object number() {
        int st = i;
        while (i < s.length() && "+-.eE0123456789".indexOf(s.charAt(i)) >= 0) i++;
        String t = s.substring(st, i);
        if (t.isEmpty()) throw new IllegalArgumentException("unexpected character at " + st);
        if (t.indexOf('.') < 0 && t.indexOf('e') < 0 && t.indexOf('E') < 0) {
            try { return Long.parseLong(t); } catch (NumberFormatException e) { /* too large: a Double */ }
        }
        try {
            return Double.parseDouble(t);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("bad number at " + st);
        }
    }

    private String string() {
        if (next() != '"') throw new IllegalArgumentException("expected a string at " + (i - 1));
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') return b.toString();
            if (c != '\\') { b.append(c); continue; }
            char e = next();
            switch (e) {
                case '"': b.append('"'); break;
                case '\\': b.append('\\'); break;
                case '/': b.append('/'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'n': b.append('\n'); break;
                case 'r': b.append('\r'); break;
                case 't': b.append('\t'); break;
                case 'u':
                    if (i + 4 > s.length()) throw new IllegalArgumentException("bad \\u escape");
                    try {
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    } catch (NumberFormatException x) {
                        throw new IllegalArgumentException("bad \\u escape");
                    }
                    i += 4;
                    break;
                default: throw new IllegalArgumentException("bad escape");
            }
        }
    }

    /** True when {@code x} has no unpaired UTF-16 surrogate (it is valid Unicode text). */
    public static boolean validText(String x) {
        for (int k = 0; k < x.length(); k++) {
            char c = x.charAt(k);
            if (Character.isHighSurrogate(c)) {
                if (k + 1 < x.length() && Character.isLowSurrogate(x.charAt(k + 1))) k++;
                else return false;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }

    private static void str(StringBuilder b, String x) {
        if (!validText(x)) throw new IllegalArgumentException("canonical JSON cannot encode an unpaired surrogate");
        b.append('"');
        for (int k = 0; k < x.length(); k++) {
            char c = x.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        b.append('"');
    }

    /** Canonical JSON text; throws IllegalArgumentException for non-integer numbers, non-ASCII keys and strings
     *  with an unpaired surrogate (they have no UTF-8 form). */
    public static String canonical(Object v) {
        StringBuilder b = new StringBuilder();
        canon(b, v);
        return b.toString();
    }

    /** The UTF-8 bytes of {@link #canonical}: what the audit chain hashes. */
    public static byte[] canonicalBytes(Object v) { return canonical(v).getBytes(StandardCharsets.UTF_8); }

    private static void canon(StringBuilder b, Object v) {
        if (v == null) b.append("null");
        else if (v instanceof Boolean x) b.append(x ? "true" : "false");
        else if (v instanceof Long || v instanceof Integer) b.append(v.toString());
        else if (v instanceof Number) throw new IllegalArgumentException("canonical JSON allows integers only");
        else if (v instanceof String x) str(b, x);
        else if (v instanceof List<?> l) {
            b.append('[');
            boolean first = true;
            for (Object x : l) { if (!first) b.append(','); first = false; canon(b, x); }
            b.append(']');
        } else if (v instanceof Map<?, ?> m) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!(e.getKey() instanceof String k)) throw new IllegalArgumentException("object keys must be strings");
                for (int j = 0; j < k.length(); j++) {
                    if (k.charAt(j) > 0x7f) throw new IllegalArgumentException("object keys must be ASCII");
                }
                sorted.put(k, e.getValue());
            }
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) b.append(',');
                first = false;
                str(b, e.getKey());
                b.append(':');
                canon(b, e.getValue());
            }
            b.append('}');
        } else throw new IllegalArgumentException("canonical JSON cannot encode " + v.getClass().getName());
    }
}
