using System.Text;
using SmartWatch;

// Runs spec/conformance against the .NET port: dotnet run -c Release --project Conformance -- <vectors dir>
// Prints each failure and a last line "csharp: N/N vectors passed"; exit 1 on any failure.
var dir = args.FirstOrDefault() ?? "../../spec/conformance";
object? Load(string n) => Json.Parse(File.ReadAllText(Path.Combine(dir, n)));
List<object?> Cases(object? v) => (List<object?>)Json.Get(v, "cases")!;
string S(object? v, string k) => (string)Json.Get(v, k)!;
long I(object? v, string k) => (long)Json.Get(v, k)!;
string Show(object? v)
{
    string t;
    try { t = Json.Canonical(v); } catch (ArgumentException) { t = v?.ToString() ?? "null"; }
    return t.Length > 300 ? t[..300] : t;
}
SortedDictionary<string, object?> Pick(object? c, params string[] keys)
{
    var o = Json.NewObj();
    foreach (var k in keys) if (Json.AsObj(c)!.TryGetValue(k, out var x)) o[k] = x;
    return o;
}
SortedDictionary<string, object?> Err(string code) => Json.Obj(("ok", false), ("code", code));
SortedDictionary<string, object?> Outputs(Func<List<SortedDictionary<string, object?>>> f)
{
    try { return Json.Obj(("ok", true), ("outputs", f().Cast<object?>().ToList())); }
    catch (EventException e) { return Err(e.Code); }
}

var total = 0;
var fails = new List<string>();
void Check(string name, object? got, object? want)
{
    total++;
    if (!Json.DeepEquals(got, want)) fails.Add($"{name}: got {Show(got)}, want {Show(want)}");
}

foreach (var c in Cases(Load("canonical.json")))
{
    object? got;
    try
    {
        var text = Json.Canonical(Json.Get(c, "input"));
        got = new List<object?> { text, Json.Sha256Hex(Encoding.UTF8.GetBytes(text)) };
    }
    catch (ArgumentException e) { got = "error: " + e.Message; }
    Check("canonical/" + S(c, "name"), got, new List<object?> { Json.Get(c, "canonical"), Json.Get(c, "sha256") });
}

var hashing = Cases(Load("hashing.json"));
for (var k = 0; k < hashing.Count; k++)
{
    var c = hashing[k];
    var (seed, text) = (S(c, "seed"), S(c, "text"));
    var h32 = Hashing.Fnv1a32(seed, text);
    var h64 = Hashing.Fnv1a64(seed, text);
    var got = Json.Obj(("fnv1a32", (long)h32), ("fnv1a64", h64.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        ("mix64", Hashing.Mix64(h64).ToString(System.Globalization.CultureInfo.InvariantCulture)), ("bucket", (long)(h32 % (1u << 20))));
    Check($"hashing/{k}", got, Pick(c, "fnv1a32", "fnv1a64", "mix64", "bucket"));
}

foreach (var c in Cases(Load("hll.json")))
{
    var h = new HyperLogLog(S(c, "seed"));
    var items = Json.Get(c, "items");
    if (items is List<object?> list) foreach (var x in list) h.Add((string)x!);
    else
    {
        var prefix = S(items, "prefix");
        for (long n = I(items, "from"); n < I(items, "to"); n++) h.Add(prefix + n.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }
    Check("hll/" + S(c, "name"), Json.Obj(("estimate", h.Estimate()), ("digest", h.Digest())), Pick(c, "estimate", "digest"));
}

var density = Cases(Load("density.json"));
for (var k = 0; k < density.Count; k++)
{
    var c = density[k];
    Check($"density/{k}", Engine.DensityMicro(I(c, "messages"), I(c, "possible_pairs"), I(c, "window_ms")), Json.Get(c, "density_micro"));
}

foreach (var c in Cases(Load("policies.json")))
{
    object got;
    try
    {
        _ = new Policy(Json.Get(c, "policy"));
        got = Json.Obj(("ok", true));
    }
    catch (PolicyException e) { got = Err(e.Code); }
    Check("policies/" + S(c, "name"), got, Pick(c, "ok", "code"));
}

foreach (var c in Cases(Load("calibration.json")))
{
    object got;
    try
    {
        var t = Calibrate.Thresholds((List<object?>)Json.Get(c, "densities")!, (List<object?>)Json.Get(c, "permille")!);
        got = Json.Obj(("ok", true), ("thresholds", t.Cast<object?>().ToList()));
    }
    catch (ArgumentException) { got = Json.Obj(("ok", false)); }
    Check("calibration/" + S(c, "name"), got, Pick(c, "ok", "thresholds"));
}

foreach (var c in Cases(Load("monitor.json")))
{
    var eng = new Engine(new Policy(Json.Get(c, "policy")));
    var steps = (List<object?>)Json.Get(c, "steps")!;
    for (var k = 0; k < steps.Count; k++)
    {
        var st = steps[k];
        var op = S(st, "op");
        object? got = op switch
        {
            "add" => Outputs(() =>
            {
                // a vector field of the wrong JSON type (1.5, true, a number for an id) is a bad event
                if (Json.Get(st, "src") is not string src || Json.Get(st, "dst") is not string dst ||
                    Json.Get(st, "ts_ms") is not long ts || Json.Get(st, "count") is not long count)
                    throw new EventException("src, dst must be strings; ts_ms and count integers");
                return eng.Add(src, dst, ts, count);
            }),
            "flush" => Outputs(() => Json.Get(st, "now_ms") is long now ? eng.Flush(now) : throw new EventException("now_ms must be an integer")),
            _ => eng.Snapshot(),
        };
        Check($"monitor/{S(c, "name")} step {k} ({op})", got, Json.Get(st, "expect"));
    }
}

foreach (var c in Cases(Load("audit.json")))
{
    var (ok, index, _) = Audit.Verify((List<object?>)Json.Get(c, "records")!);
    Check("audit/" + S(c, "name"), Json.Obj(("ok", ok), ("index", index.HasValue ? (long)index.Value : null)), Json.Get(c, "result"));
}

foreach (var f in fails) Console.WriteLine("FAIL " + f);
if (fails.Count == 0)
{
    Console.WriteLine($"csharp: {total}/{total} vectors passed");
    return 0;
}
Console.WriteLine($"csharp: {fails.Count} of {total} vectors failed");
return 1;
