using SmartWatch;

// The interop program for ports/conformance/interop.py (spec/PORTING.md, "The interop program"):
//     dotnet Interop.dll URL AGENT_IDS SECONDS          (token in SMARTWATCH_INGEST_TOKEN)
// One command poller per agent (200 ms) prints "RESET <agent_id> <reset_id>" for every command and acknowledges it;
// SECONDS x 10 rounds of one message per ordered pair of agents every 100 ms go through the reporter; then
// "SENT <messages accepted>"; it keeps polling until standard input closes.
if (args.Length != 3 || !int.TryParse(args[2], out var seconds))
{
    Console.Error.WriteLine("usage: Interop URL AGENT_IDS SECONDS");
    return 2;
}
var token = Environment.GetEnvironmentVariable("SMARTWATCH_INGEST_TOKEN");
var ids = args[1].Split(',');
var outLock = new object();
using var client = new Client(args[0], token);
var pollers = ids.Select(a =>
{
    var p = new CommandPoller(client, a, cmd =>
    {
        lock (outLock)
        {
            Console.WriteLine($"RESET {a} {Json.Get(cmd, "reset_id")}");
            Console.Out.Flush();
        }
    }, TimeSpan.FromMilliseconds(200));
    p.Start();
    return p;
}).ToList();
var rep = new Reporter(client);
rep.Start();
var t0 = System.Diagnostics.Stopwatch.StartNew();
for (var r = 0; r < seconds * 10; r++)
{
    foreach (var a in ids)
        foreach (var b in ids)
            if (a != b) rep.Record(a, b, 1);
    var wait = (r + 1) * 100 - t0.ElapsedMilliseconds;
    if (wait > 0) Thread.Sleep((int)wait);
}
rep.Close();
lock (outLock)
{
    Console.WriteLine($"SENT {rep.Sent}");
    Console.Out.Flush();
}
try { Console.OpenStandardInput().CopyTo(Stream.Null); } catch (IOException) { }
foreach (var p in pollers) p.Stop();
return 0;
