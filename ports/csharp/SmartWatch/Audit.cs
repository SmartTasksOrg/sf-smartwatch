namespace SmartWatch;

/// <summary>Audit chain verification (spec/SEMANTICS.md, section 8). A record's <c>hash</c> is the lower-case hex
/// SHA-256 of the canonical JSON of the record without <c>hash</c>; <c>prev</c> is the hash of the record before
/// (64 zeros for record 0) and <c>seq</c> its index.</summary>
public static class Audit
{
    public static readonly string Genesis = new('0', 64);

    /// <summary>The hash of a record (its <c>hash</c> field left out), or null when it has no canonical form.</summary>
    public static string? RecordHash(object? record)
    {
        if (record is not SortedDictionary<string, object?> o) return null;
        var body = new SortedDictionary<string, object?>(o, StringComparer.Ordinal);
        body.Remove("hash");
        return Json.DocHash(body);
    }

    /// <summary>(ok, index of the first bad record or null, message).</summary>
    public static (bool Ok, int? Index, string Message) Verify(IReadOnlyList<object?> records)
    {
        var prev = Genesis;
        for (var i = 0; i < records.Count; i++)
        {
            var r = records[i];
            if (Json.Get(r, "seq") is not long seq || seq != i) return (false, i, $"record {i}: seq is not {i}");
            if (Json.Get(r, "prev") is not string p || p != prev) return (false, i, $"record {i}: prev does not match the hash of the record before");
            var h = RecordHash(r);
            if (h == null) return (false, i, $"record {i}: has no canonical form");
            if (Json.Get(r, "hash") is not string hv || hv != h) return (false, i, $"record {i}: hash does not match its content");
            prev = h;
        }
        return (true, null, $"{records.Count} records, chain intact, head {prev}");
    }
}
