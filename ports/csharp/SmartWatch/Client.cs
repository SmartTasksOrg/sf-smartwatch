using System.Net.Http.Headers;
using System.Text;

namespace SmartWatch;

/// <summary>The monitor answered with a status outside 2xx.</summary>
public sealed class MonitorError : Exception
{
    public int Status { get; }
    public string Body { get; }
    public MonitorError(int status, string body) : base($"HTTP {status}: {body}") { Status = status; Body = body; }
}

/// <summary>
/// A JSON client for the monitor's agent endpoints (spec/PORTING.md, items 9 and 10). HttpClient with redirects
/// switched off (a redirect would carry the bearer token elsewhere) and one connection per request. Thread-safe.
/// </summary>
public sealed class Client : IDisposable
{
    /// <summary>The largest 2xx answer read (32 MiB); a larger one is an error.</summary>
    public const int MaxResponse = 32 * 1024 * 1024;
    /// <summary>At most this much of an error answer is read (64 KiB).</summary>
    public const int MaxErrorBody = 64 * 1024;
    readonly HttpClient http;
    readonly string url;
    readonly string? token;

    public Client(string url, string? token, TimeSpan? timeout = null)
    {
        if (!url.StartsWith("http://", StringComparison.Ordinal) && !url.StartsWith("https://", StringComparison.Ordinal))
            throw new ArgumentException("the monitor URL must start with http:// or https://");
        this.url = url.TrimEnd('/');
        this.token = string.IsNullOrEmpty(token) ? null : token;
        http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false })
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(5),
            MaxResponseContentBufferSize = MaxResponse,
        };
    }

    /// <summary>Percent-encode one path segment: everything except ASCII letters, digits, '-', '.' and '_' ('/' becomes %2F).</summary>
    public static string QuoteId(string s)
    {
        var b = new StringBuilder();
        foreach (var x in Encoding.UTF8.GetBytes(s))
        {
            if (x < 0x80 && (char.IsAsciiLetterOrDigit((char)x) || x == '-' || x == '.' || x == '_')) b.Append((char)x);
            else b.Append('%').Append(x.ToString("X2"));
        }
        return b.ToString();
    }

    /// <summary>Send a request; the parsed JSON body of a 2xx answer. Throws <see cref="MonitorError"/> for other statuses
    /// and HttpRequestException / TaskCanceledException (timeout) for network failures.</summary>
    public object? Request(HttpMethod method, string path, object? body = null)
    {
        using var req = new HttpRequestMessage(method, url + path);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.ConnectionClose = true;
        if (token != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (method == HttpMethod.Post)
            req.Content = new ByteArrayContent(body == null ? Array.Empty<byte>() : Json.CanonicalBytes(body))
            { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } };
        // ResponseHeadersRead: the body is streamed and read with a bound below, never buffered whole by HttpClient.
        using var res = http.Send(req, HttpCompletionOption.ResponseHeadersRead);
        var status = (int)res.StatusCode;
        var ok = status >= 200 && status < 300;
        var limit = ok ? MaxResponse : MaxErrorBody;
        if (ok && res.Content.Headers.ContentLength > MaxResponse) throw new HttpRequestException("answer larger than 32 MiB");
        using var stream = res.Content.ReadAsStream();
        // read at most limit + 1 bytes into a buffer that never grows past that (not a MemoryStream, which doubles)
        var buf = new byte[(int)Math.Min(limit + 1L, Math.Max(8192L, res.Content.Headers.ContentLength ?? 0) + 1)];
        var n = 0;
        while (n <= limit)
        {
            if (n == buf.Length) Array.Resize(ref buf, (int)Math.Min(limit + 1L, 2L * buf.Length));
            var k = stream.Read(buf, n, buf.Length - n);
            if (k == 0) break;
            n += k;
        }
        if (n > limit)
        {
            if (ok) throw new HttpRequestException("answer larger than 32 MiB");
            n = limit; // an error body: keep the first 64 KiB, leave the rest unread
        }
        var text = Encoding.UTF8.GetString(buf, 0, n);
        if (status < 200 || status >= 300) throw new MonitorError(status, text.Length > 300 ? text[..300] : text);
        return text.StartsWith('{') || text.StartsWith('[') ? Json.Parse(text) : text;
    }

    /// <summary>POST /v1/events with {"events": [...]}.</summary>
    public object? Events(List<object?> events) => Request(HttpMethod.Post, "/v1/events", Json.Obj(("events", events)));

    /// <summary>GET /v1/agents/{id}/commands: the commands list.</summary>
    public List<object?> Commands(string agentId) =>
        Json.AsArr(Json.Get(Request(HttpMethod.Get, $"/v1/agents/{QuoteId(agentId)}/commands"), "commands"))
        ?? throw new HttpRequestException("the answer has no commands list");

    /// <summary>POST /v1/resets/{reset_id}/ack with {"agent_id": ...}.</summary>
    public object? Ack(string resetId, string agentId) =>
        Request(HttpMethod.Post, $"/v1/resets/{QuoteId(resetId)}/ack", Json.Obj(("agent_id", agentId)));

    public void Dispose() => http.Dispose();
}

/// <summary>
/// Adds up messages per (src, dst, second) in memory and sends them as POST /v1/events every second (± up to 200 ms
/// of jitter). <see cref="Record"/> never blocks on the network. Thread-safe.
/// <code>
/// using var rep = new Reporter(new Client("http://127.0.0.1:8730", token));
/// rep.Start();
/// rep.Record("planner", "coder");
/// rep.Close();                  // sends what is left; rep.Sent is the number of messages accepted
/// </code>
/// </summary>
public sealed class Reporter : IDisposable
{
    public const int Batch = 10_000;
    const long MaxCount = 1_000_000_000;
    readonly Client client;
    readonly object gate = new();
    readonly object sendGate = new();
    readonly ManualResetEventSlim stop = new(false);
    Dictionary<(string Src, string Dst, long Ts), long> buf = new();
    Thread? thread;
    long sent, dropped, rejected, errors;

    public TimeSpan Interval { get; }
    public TimeSpan Jitter { get; }
    public int MaxKeys { get; }
    public long BucketMs { get; }

    /// <summary>Messages the monitor accepted.</summary>
    public long Sent => Interlocked.Read(ref sent);
    /// <summary>Messages lost to the <see cref="MaxKeys"/> bound.</summary>
    public long Dropped => Interlocked.Read(ref dropped);
    /// <summary>Messages the monitor refused (bad ids, clock skew, 400/401/403/413).</summary>
    public long Rejected => Interlocked.Read(ref rejected);
    /// <summary>Failed sends (network errors and 5xx: their events were kept for the next send; unexpected 2xx answers: not).</summary>
    public long Errors => Interlocked.Read(ref errors);

    /// <param name="bucketMs">1 … 60000; keep it a divisor of the policy's window_ms.</param>
    public Reporter(Client client, TimeSpan? interval = null, TimeSpan? jitter = null, int maxKeys = 100_000, long bucketMs = 1000)
    {
        if (bucketMs < 1 || bucketMs > 60000) throw new ArgumentException("bucketMs must be from 1 to 60000");
        this.client = client;
        Interval = interval ?? TimeSpan.FromSeconds(1);
        Jitter = jitter ?? TimeSpan.FromMilliseconds(200);
        if (Jitter > Interval) throw new ArgumentException("the jitter must not exceed the interval");
        MaxKeys = maxKeys;
        BucketMs = bucketMs;
    }

    /// <summary>Record <paramref name="count"/> messages from src to dst now (or at tsMs); throws <see cref="EventException"/>.</summary>
    public void Record(string src, string dst, long count = 1, long? tsMs = null)
    {
        var ts = tsMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Engine.CheckEvent(src, dst, ts, count);
        Put((src, dst, ts - ts % BucketMs), count);
    }

    void Put((string, string, long) key, long count)
    {
        lock (gate)
        {
            if (buf.TryGetValue(key, out var c)) buf[key] = Math.Min(c + count, MaxCount);
            else if (buf.Count < MaxKeys) buf[key] = count;
            else dropped += count;
        }
    }

    /// <summary>Send everything recorded so far; returns the messages accepted.</summary>
    public long Flush()
    {
        lock (sendGate)
        {
            Dictionary<(string Src, string Dst, long Ts), long> taken;
            lock (gate)
            {
                taken = buf;
                buf = new();
            }
            var items = taken.ToList();
            items.Sort((x, y) =>
            {
                var c = x.Key.Ts.CompareTo(y.Key.Ts);
                if (c != 0) return c;
                c = string.CompareOrdinal(x.Key.Src, y.Key.Src);
                return c != 0 ? c : string.CompareOrdinal(x.Key.Dst, y.Key.Dst);
            });
            long accepted = 0;
            for (var i = 0; i < items.Count; i += Batch)
            {
                var part = items.GetRange(i, Math.Min(Batch, items.Count - i));
                var evs = part.Select(kv => (object?)Json.Obj(("src", kv.Key.Src), ("dst", kv.Key.Dst), ("ts_ms", kv.Key.Ts), ("count", kv.Value))).ToList();
                var total = part.Sum(kv => kv.Value);
                object? res;
                try
                {
                    res = client.Events(evs);
                }
                catch (MonitorError e) when (e.Status is 400 or 401 or 403 or 413)
                {
                    Console.Error.WriteLine($"smartwatch reporter: the monitor refused a batch: {e.Message}");
                    Interlocked.Add(ref rejected, total);
                    continue;
                }
                catch (System.Text.Json.JsonException e)
                {
                    // a 2xx answer that is not JSON: the events may have been counted, so they are not sent again
                    Interlocked.Increment(ref errors);
                    Console.Error.WriteLine($"smartwatch reporter: unexpected answer to POST /v1/events (events not resent): {e.Message}");
                    continue;
                }
                catch (Exception e) when (e is MonitorError or HttpRequestException or TaskCanceledException or IOException)
                {
                    Interlocked.Increment(ref errors);
                    Console.Error.WriteLine($"smartwatch reporter: sending to the monitor failed (kept for the next send): {e.Message}");
                    foreach (var kv in items.Skip(i)) Put(kv.Key, kv.Value);
                    break;
                }
                if (res is not SortedDictionary<string, object?>)
                {
                    Interlocked.Increment(ref errors);
                    Console.Error.WriteLine("smartwatch reporter: unexpected answer to POST /v1/events (events not resent)");
                    continue;
                }
                var bad = new HashSet<long>();
                foreach (var r in Json.AsArr(Json.Get(res, "rejected")) ?? new List<object?>())
                    if (Json.Get(r, "index") is long ix) bad.Add(ix);
                var nBad = bad.Where(j => j >= 0 && j < part.Count).Sum(j => part[(int)j].Value);
                Interlocked.Add(ref rejected, nBad);
                Interlocked.Add(ref sent, total - nBad);
                accepted += total - nBad;
            }
            return accepted;
        }
    }

    /// <summary>Start the background send loop.</summary>
    public void Start()
    {
        lock (gate)
        {
            if (thread != null) return;
            thread = new Thread(Run) { IsBackground = true, Name = "smartwatch-reporter" };
            thread.Start();
        }
    }

    void Run()
    {
        while (!stop.Wait(Interval + Jitter * (Random.Shared.NextDouble() * 2 - 1)))
        {
            try { Flush(); }
            catch (Exception e) { Console.Error.WriteLine($"smartwatch reporter: flush failed: {e.Message}"); }
        }
    }

    /// <summary>Stop the loop and send what is left.</summary>
    public void Close()
    {
        stop.Set();
        thread?.Join(TimeSpan.FromSeconds(10));
        Flush();
    }

    public void Dispose() => stop.Set();
}

/// <summary>
/// Pulls reset commands for one agent, runs the handler and acknowledges each command once the handler returned
/// without throwing. A command whose handler threw is not acknowledged and comes again on the next poll, so the handler
/// must tolerate repeats (compare <c>reset_id</c>).
/// </summary>
public sealed class CommandPoller : IDisposable
{
    readonly Client client;
    readonly Action<SortedDictionary<string, object?>> onReset;
    readonly ManualResetEventSlim stop = new(false);
    Thread? thread;

    public string AgentId { get; }
    public TimeSpan Interval { get; }

    public CommandPoller(Client client, string agentId, Action<SortedDictionary<string, object?>> onReset, TimeSpan? interval = null)
    {
        this.client = client;
        AgentId = agentId;
        this.onReset = onReset;
        Interval = interval ?? TimeSpan.FromSeconds(1);
    }

    /// <summary>One poll: the number of commands handled and acknowledged.</summary>
    public int PollOnce()
    {
        var n = 0;
        foreach (var c in client.Commands(AgentId))
        {
            if (c is not SortedDictionary<string, object?> cmd || Json.Get(cmd, "type") as string != "reset") continue;
            if (Json.Get(cmd, "reset_id") is not string rid) continue;
            try { onReset(cmd); }
            catch (Exception e)
            {
                Console.Error.WriteLine($"smartwatch poller: on_reset failed for {rid}; not acknowledged: {e.Message}");
                continue;
            }
            client.Ack(rid, AgentId);
            n++;
        }
        return n;
    }

    public void Start()
    {
        if (thread != null) return;
        thread = new Thread(() =>
        {
            while (!stop.Wait(Interval))
            {
                try { PollOnce(); }
                catch (Exception e) { Console.Error.WriteLine($"smartwatch poller: polling commands failed: {e.Message}"); }
            }
        }) { IsBackground = true, Name = "smartwatch-commands" };
        thread.Start();
    }

    public void Stop()
    {
        stop.Set();
        thread?.Join(TimeSpan.FromSeconds(10));
    }

    public void Dispose() => Stop();
}
