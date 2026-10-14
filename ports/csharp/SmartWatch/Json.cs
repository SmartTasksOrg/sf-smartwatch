using System.Text;
using System.Text.Json;

namespace SmartWatch;

/// <summary>
/// JSON values as plain objects: null, bool, long (an integer), double (any number with a fraction or
/// exponent, or too large for a long), string, <see cref="List{T}"/> of values, and
/// <see cref="SortedDictionary{TKey,TValue}"/> with ordinal key order (the canonical order for ASCII keys).
/// Integers and floats stay distinct, so 2.5, true and "1" are never taken for integers.
/// </summary>
public static class Json
{
    public static SortedDictionary<string, object?> NewObj() => new(StringComparer.Ordinal);

    public static SortedDictionary<string, object?> Obj(params (string Key, object? Value)[] pairs)
    {
        var o = NewObj();
        foreach (var (k, v) in pairs) o[k] = v;
        return o;
    }

    /// <summary>Parse JSON text (System.Text.Json reader); a duplicated key keeps its last value.</summary>
    public static object? Parse(string text)
    {
        using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 128 });
        return From(doc.RootElement);
    }

    static object? From(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Null: return null;
            case JsonValueKind.True: return true;
            case JsonValueKind.False: return false;
            case JsonValueKind.String: return e.GetString();
            case JsonValueKind.Number:
                var raw = e.GetRawText();
                if (raw.IndexOfAny(new[] { '.', 'e', 'E' }) < 0 && e.TryGetInt64(out var l)) return l;
                return e.GetDouble();
            case JsonValueKind.Array:
                var a = new List<object?>();
                foreach (var x in e.EnumerateArray()) a.Add(From(x));
                return a;
            case JsonValueKind.Object:
                var o = NewObj();
                foreach (var p in e.EnumerateObject()) o[p.Name] = From(p.Value);
                return o;
            default: throw new JsonException("unexpected JSON value");
        }
    }

    public static SortedDictionary<string, object?>? AsObj(object? v) => v as SortedDictionary<string, object?>;
    public static List<object?>? AsArr(object? v) => v as List<object?>;
    public static string? Str(object? v) => v as string;

    /// <summary>The value of key <paramref name="k"/> of an object, or null.</summary>
    public static object? Get(object? v, string k) => v is SortedDictionary<string, object?> o && o.TryGetValue(k, out var x) ? x : null;

    /// <summary>True when <paramref name="v"/> is an object whose keys are exactly <paramref name="fields"/>.</summary>
    public static bool HasExactly(object? v, params string[] fields) =>
        v is SortedDictionary<string, object?> o && o.Count == fields.Length && fields.All(o.ContainsKey);

    /// <summary>An integer (not a bool, not a float) from lo to hi.</summary>
    public static bool IntIn(object? v, long lo, long hi) => v is long l && l >= lo && l <= hi;

    /// <summary>Structural equality of two JSON values (integers compare as integers, key order is irrelevant).</summary>
    public static bool DeepEquals(object? a, object? b)
    {
        switch (a)
        {
            case null: return b == null;
            case bool x: return b is bool yb && x == yb;
            case long x: return b is long yl && x == yl;
            case double x: return b is double yd && x.Equals(yd);
            case string x: return b is string ys && x == ys;
            case List<object?> x:
                if (b is not List<object?> ly || ly.Count != x.Count) return false;
                for (var i = 0; i < x.Count; i++) if (!DeepEquals(x[i], ly[i])) return false;
                return true;
            case SortedDictionary<string, object?> x:
                if (b is not SortedDictionary<string, object?> oy || oy.Count != x.Count) return false;
                foreach (var kv in x) if (!oy.TryGetValue(kv.Key, out var w) || !DeepEquals(kv.Value, w)) return false;
                return true;
            default: return false;
        }
    }

    static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Canonical JSON (spec/SEMANTICS.md, section 8). Throws ArgumentException for floats, non-ASCII
    /// keys and strings that are not valid Unicode.</summary>
    public static string Canonical(object? v)
    {
        var b = new StringBuilder();
        C(b, v);
        return b.ToString();
    }

    /// <summary>The UTF-8 bytes of the canonical form.</summary>
    public static byte[] CanonicalBytes(object? v)
    {
        try { return StrictUtf8.GetBytes(Canonical(v)); }
        catch (EncoderFallbackException e) { throw new ArgumentException("string is not valid Unicode", e); }
    }

    static void S(StringBuilder b, string s)
    {
        b.Append('"');
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '"': b.Append("\\\""); break;
                case '\\': b.Append("\\\\"); break;
                case '\b': b.Append("\\b"); break;
                case '\f': b.Append("\\f"); break;
                case '\n': b.Append("\\n"); break;
                case '\r': b.Append("\\r"); break;
                case '\t': b.Append("\\t"); break;
                default:
                    if (ch < 0x20) b.Append("\\u").Append(((int)ch).ToString("x4"));
                    else b.Append(ch); // everything else as is, surrogate pairs included
                    break;
            }
        }
        b.Append('"');
    }

    static void C(StringBuilder b, object? v)
    {
        switch (v)
        {
            case null: b.Append("null"); break;
            case bool x: b.Append(x ? "true" : "false"); break;
            case long x: b.Append(x.ToString(System.Globalization.CultureInfo.InvariantCulture)); break;
            case int x: b.Append(x.ToString(System.Globalization.CultureInfo.InvariantCulture)); break;
            case string x: S(b, x); break;
            case List<object?> a:
                b.Append('[');
                for (var i = 0; i < a.Count; i++)
                {
                    if (i > 0) b.Append(',');
                    C(b, a[i]);
                }
                b.Append(']');
                break;
            case SortedDictionary<string, object?> o:
                b.Append('{');
                var first = true;
                foreach (var kv in o)
                {
                    if (!kv.Key.All(c => c < 0x80)) throw new ArgumentException("object keys must be ASCII");
                    if (!first) b.Append(',');
                    first = false;
                    S(b, kv.Key);
                    b.Append(':');
                    C(b, kv.Value);
                }
                b.Append('}');
                break;
            case double: throw new ArgumentException("canonical JSON allows integers only");
            default: throw new ArgumentException("canonical JSON does not encode " + v.GetType().Name);
        }
    }

    /// <summary>Lower-case hex SHA-256 of a byte string.</summary>
    public static string Sha256Hex(byte[] data) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>sha256(canonical(v)); null when <paramref name="v"/> has no canonical form.</summary>
    public static string? DocHash(object? v)
    {
        try { return Sha256Hex(CanonicalBytes(v)); }
        catch (ArgumentException) { return null; }
    }
}
