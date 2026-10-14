//! The agent side (spec/PORTING.md, items 9 and 10): a plain-HTTP JSON client for the monitor, a
//! `Reporter` that adds up messages in memory and sends them every second, and a `CommandPoller` that
//! pulls reset commands for one agent and acknowledges them.
//!
//! The client speaks HTTP/1.1 over `std::net::TcpStream` only (no TLS), one connection per request
//! (`Connection: close`), and never follows redirects (a 3xx answer is an error).
use crate::engine::{check_event, EventError};
use crate::json::{self, canonical, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// At most this many events per POST /v1/events.
pub const BATCH: usize = 10_000;
const MAX_RESPONSE: usize = 32 << 20;
const MAX_COUNT: i64 = 1_000_000_000;

#[derive(Debug, Clone)]
pub enum Error {
    /// Connection, timeout or malformed response.
    Network(String),
    /// The monitor answered with a status outside 2xx (the body, at most 300 characters).
    Http(u16, String),
    /// A 2xx answer whose body is not the JSON expected.
    BadAnswer(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Network(m) => write!(f, "network: {}", m),
            Error::Http(s, b) => write!(f, "HTTP {}: {}", s, b),
            Error::BadAnswer(m) => write!(f, "bad answer: {}", m),
        }
    }
}

impl std::error::Error for Error {}

/// Percent-encode one path segment: everything except ASCII letters, digits, `-`, `.` and `_`
/// (so `/` becomes `%2F`).
pub fn quote_id(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._".contains(&b) { (b as char).to_string() } else { format!("%{:02X}", b) })
        .collect()
}

/// A plain-HTTP JSON client for the monitor.
#[derive(Clone, Debug)]
pub struct Client {
    host: String,
    port: u16,
    prefix: String,
    token: Option<String>,
    pub timeout: Duration,
}

impl Client {
    /// `url` must start with `http://` (no TLS in this client).
    pub fn new(url: &str, token: Option<&str>) -> Result<Client, String> {
        let rest = url.strip_prefix("http://").ok_or("only http:// URLs are supported by this client (no TLS)")?;
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let (host, port) = if let Some(end) = hostport.strip_prefix('[').and_then(|r| r.find(']')) {
            let port = match &hostport[end + 2..] {
                "" => 80,
                p => p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or("bad port")?,
            };
            (hostport[..end + 2].to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
                None => (hostport.to_string(), 80),
            }
        };
        if host.is_empty() {
            return Err("the URL has no host".into());
        }
        Ok(Client {
            host,
            port,
            prefix: path.to_string(),
            token: token.filter(|t| !t.is_empty()).map(str::to_string),
            timeout: Duration::from_secs(5),
        })
    }

    /// Send a request; the parsed JSON body of a 2xx answer (or a string when the body is not JSON).
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, Error> {
        let net = |e: std::io::Error| Error::Network(e.to_string());
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        let addr = (host, self.port).to_socket_addrs().map_err(net)?.next().ok_or(Error::Network("no address".into()))?;
        let mut s = TcpStream::connect_timeout(&addr, self.timeout).map_err(net)?;
        s.set_read_timeout(Some(self.timeout)).map_err(net)?;
        s.set_write_timeout(Some(self.timeout)).map_err(net)?;
        let data = match body {
            Some(v) => canonical(v).map_err(Error::Network)?.into_bytes(),
            None => vec![],
        };
        let mut req = format!(
            "{} {}{} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n",
            method, self.prefix, path, self.host, self.port
        );
        if method == "POST" {
            req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", data.len()));
        }
        if let Some(t) = &self.token {
            req.push_str(&format!("Authorization: Bearer {}\r\n", t));
        }
        req.push_str("\r\n");
        let mut msg = req.into_bytes();
        msg.extend_from_slice(&data);
        s.write_all(&msg).map_err(net)?;
        let deadline = Instant::now() + self.timeout;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut header_end = None;
        let mut want: Option<usize> = None;
        loop {
            if let (Some(h), Some(n)) = (header_end, want) {
                if buf.len() >= h + n {
                    break;
                }
            }
            if Instant::now() > deadline {
                return Err(Error::Network("timed out".into()));
            }
            let k = s.read(&mut chunk).map_err(net)?;
            if k == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..k]);
            if buf.len() > MAX_RESPONSE + 65536 {
                return Err(Error::Network("answer larger than 32 MiB".into()));
            }
            if header_end.is_none() {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(i + 4);
                    let head = String::from_utf8_lossy(&buf[..i]).to_string();
                    want = head.lines().skip(1).find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            v.trim().parse().ok()
                        } else {
                            None
                        }
                    });
                }
            }
        }
        let h = header_end.ok_or(Error::Network("incomplete response".into()))?;
        let head = String::from_utf8_lossy(&buf[..h]).to_string();
        let status: u16 =
            head.split_whitespace().nth(1).and_then(|x| x.parse().ok()).ok_or(Error::Network("bad status line".into()))?;
        let body = match want {
            Some(n) if buf.len() >= h + n => &buf[h..h + n],
            Some(_) => return Err(Error::Network("response shorter than Content-Length".into())),
            None => &buf[h..],
        };
        let text = String::from_utf8_lossy(body).to_string();
        if !(200..300).contains(&status) {
            return Err(Error::Http(status, text.chars().take(300).collect()));
        }
        if text.starts_with('{') || text.starts_with('[') {
            json::parse(&text).map_err(Error::BadAnswer)
        } else {
            Ok(Value::Str(text))
        }
    }

    /// POST /v1/events with `{"events": [...]}`.
    pub fn events(&self, events: Vec<Value>) -> Result<Value, Error> {
        self.request("POST", "/v1/events", Some(&Value::obj(vec![("events", Value::Arr(events))])))
    }

    /// GET /v1/agents/{id}/commands: the `commands` list.
    pub fn commands(&self, agent_id: &str) -> Result<Vec<Value>, Error> {
        let v = self.request("GET", &format!("/v1/agents/{}/commands", quote_id(agent_id)), None)?;
        v.get("commands").and_then(Value::as_arr).cloned().ok_or(Error::BadAnswer("the answer has no commands list".into()))
    }

    /// POST /v1/resets/{reset_id}/ack with `{"agent_id": ...}`.
    pub fn ack(&self, reset_id: &str, agent_id: &str) -> Result<Value, Error> {
        self.request(
            "POST",
            &format!("/v1/resets/{}/ack", quote_id(reset_id)),
            Some(&Value::obj(vec![("agent_id", Value::s(agent_id))])),
        )
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A small xorshift generator for the send jitter (not for anything secret).
struct Jitter(u64);

impl Jitter {
    fn new() -> Jitter {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1);
        let local = 0u8;
        Jitter((t ^ (&local as *const u8 as u64).rotate_left(32)) | 1)
    }
    /// Uniform in [-1, 1].
    fn next(&mut self) -> f64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0
    }
}

type Key = (String, String, i64);

struct Inner {
    client: Client,
    buf: Mutex<HashMap<Key, i64>>,
    send_lock: Mutex<()>,
    stop: Mutex<bool>,
    wake: Condvar,
    max_keys: usize,
    bucket_ms: i64,
    interval: Duration,
    jitter: Duration,
    sent: AtomicI64,
    dropped: AtomicI64,
    rejected: AtomicI64,
    errors: AtomicI64,
}

/// Adds up messages per (src, dst, second) in memory and sends them to the monitor every second
/// (± up to 200 ms of jitter). `record` never blocks on the network.
///
/// ```no_run
/// let rep = smartwatch::Reporter::new("http://127.0.0.1:8730", Some("token")).unwrap();
/// rep.start();
/// rep.record("planner", "coder", 1).unwrap();
/// rep.close();                       // sends what is left
/// println!("{} messages accepted", rep.sent());
/// ```
pub struct Reporter {
    inner: Arc<Inner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Reporter {
    pub fn new(url: &str, token: Option<&str>) -> Result<Reporter, String> {
        Reporter::with_options(Client::new(url, token)?, Duration::from_secs(1), Duration::from_millis(200), 100_000, 1000)
    }

    /// `bucket_ms` (1 … 60000) should divide the policy's `window_ms`.
    pub fn with_options(
        client: Client,
        interval: Duration,
        jitter: Duration,
        max_keys: usize,
        bucket_ms: i64,
    ) -> Result<Reporter, String> {
        if !(1..=60000).contains(&bucket_ms) {
            return Err("bucket_ms must be from 1 to 60000".into());
        }
        if jitter > interval {
            return Err("the jitter must not exceed the interval".into());
        }
        Ok(Reporter {
            inner: Arc::new(Inner {
                client,
                buf: Mutex::new(HashMap::new()),
                send_lock: Mutex::new(()),
                stop: Mutex::new(false),
                wake: Condvar::new(),
                max_keys,
                bucket_ms,
                interval,
                jitter,
                sent: AtomicI64::new(0),
                dropped: AtomicI64::new(0),
                rejected: AtomicI64::new(0),
                errors: AtomicI64::new(0),
            }),
            thread: Mutex::new(None),
        })
    }

    /// Record `count` messages from `src` to `dst` now.
    pub fn record(&self, src: &str, dst: &str, count: i64) -> Result<(), EventError> {
        self.record_at(src, dst, count, now_ms())
    }

    /// Record `count` messages from `src` to `dst` at `ts_ms`.
    pub fn record_at(&self, src: &str, dst: &str, count: i64, ts_ms: i64) -> Result<(), EventError> {
        check_event(src, dst, ts_ms, count)?;
        let key = (src.to_string(), dst.to_string(), ts_ms - ts_ms % self.inner.bucket_ms);
        self.inner.put(key, count);
        Ok(())
    }

    /// Send everything recorded so far; returns the messages accepted. Safe to call from any thread.
    pub fn flush(&self) -> i64 {
        self.inner.flush()
    }

    /// Start the background send loop.
    pub fn start(&self) {
        let mut t = self.thread.lock().unwrap_or_else(|e| e.into_inner());
        if t.is_none() {
            let inner = Arc::clone(&self.inner);
            *t = Some(std::thread::spawn(move || inner.run()));
        }
    }

    /// Stop the loop and send what is left.
    pub fn close(&self) {
        *self.inner.stop.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.inner.wake.notify_all();
        if let Some(t) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = t.join();
        }
        self.inner.flush();
    }

    /// Messages the monitor accepted.
    pub fn sent(&self) -> i64 {
        self.inner.sent.load(Ordering::SeqCst)
    }
    /// Messages lost to the `max_keys` bound.
    pub fn dropped(&self) -> i64 {
        self.inner.dropped.load(Ordering::SeqCst)
    }
    /// Messages the monitor refused (bad ids, clock skew, 400/401/403/413).
    pub fn rejected(&self) -> i64 {
        self.inner.rejected.load(Ordering::SeqCst)
    }
    /// Failed sends (network errors and 5xx: their events were kept for the next send; unexpected 2xx answers: not).
    pub fn errors(&self) -> i64 {
        self.inner.errors.load(Ordering::SeqCst)
    }
}

impl Inner {
    fn put(&self, key: Key, count: i64) {
        let mut buf = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = buf.get_mut(&key) {
            *c = (*c + count).min(MAX_COUNT);
        } else if buf.len() < self.max_keys {
            buf.insert(key, count);
        } else {
            self.dropped.fetch_add(count, Ordering::SeqCst);
        }
    }

    fn run(&self) {
        let mut rng = Jitter::new();
        loop {
            let wait = self.interval.as_secs_f64() + rng.next() * self.jitter.as_secs_f64();
            let deadline = Instant::now() + Duration::from_secs_f64(wait.max(0.0));
            {
                let mut stop = self.stop.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if *stop {
                        return;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    stop = self.wake.wait_timeout(stop, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
                }
            }
            self.flush();
        }
    }

    fn flush(&self) -> i64 {
        let _g = self.send_lock.lock().unwrap_or_else(|e| e.into_inner());
        let buf = std::mem::take(&mut *self.buf.lock().unwrap_or_else(|e| e.into_inner()));
        let mut items: Vec<(Key, i64)> = buf.into_iter().collect();
        items.sort_by(|x, y| x.0 .2.cmp(&y.0 .2).then_with(|| x.0 .0.cmp(&y.0 .0)).then_with(|| x.0 .1.cmp(&y.0 .1)));
        let mut accepted = 0;
        let mut i = 0;
        while i < items.len() {
            let part = &items[i..(i + BATCH).min(items.len())];
            let evs: Vec<Value> = part
                .iter()
                .map(|((s, d, t), c)| {
                    Value::obj(vec![("src", Value::s(s)), ("dst", Value::s(d)), ("ts_ms", Value::Int(*t)), ("count", Value::Int(*c))])
                })
                .collect();
            let total: i64 = part.iter().map(|(_, c)| *c).sum();
            match self.client.events(evs) {
                Ok(res) if res.as_obj().is_none() => {
                    // the monitor answered 2xx with something else than {"accepted", "rejected"}: the events may have
                    // been counted, so they are not sent again
                    self.errors.fetch_add(1, Ordering::SeqCst);
                    eprintln!("smartwatch reporter: unexpected answer to POST /v1/events (events not resent)");
                }
                Err(Error::BadAnswer(m)) => {
                    self.errors.fetch_add(1, Ordering::SeqCst);
                    eprintln!("smartwatch reporter: unexpected answer to POST /v1/events (events not resent): {}", m);
                }
                Ok(res) => {
                    let mut bad: Vec<usize> = res
                        .get("rejected")
                        .and_then(Value::as_arr)
                        .map(|a| a.iter().filter_map(|r| r.get("index").and_then(Value::as_int)).map(|x| x as usize).collect())
                        .unwrap_or_default();
                    bad.sort_unstable();
                    bad.dedup();
                    let n_bad: i64 = bad.iter().filter_map(|&j| part.get(j)).map(|(_, c)| *c).sum();
                    self.rejected.fetch_add(n_bad, Ordering::SeqCst);
                    accepted += total - n_bad;
                    self.sent.fetch_add(total - n_bad, Ordering::SeqCst);
                }
                Err(Error::Http(st, msg)) if matches!(st, 400 | 401 | 403 | 413) => {
                    eprintln!("smartwatch reporter: the monitor refused a batch: HTTP {}: {}", st, msg);
                    self.rejected.fetch_add(total, Ordering::SeqCst);
                }
                Err(e) => {
                    self.errors.fetch_add(1, Ordering::SeqCst);
                    eprintln!("smartwatch reporter: sending to the monitor failed (kept for the next send): {}", e);
                    for (k, c) in items[i..].iter().cloned() {
                        self.put(k, c);
                    }
                    break;
                }
            }
            i += BATCH;
        }
        accepted
    }
}

impl Drop for Reporter {
    fn drop(&mut self) {
        *self.inner.stop.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.inner.wake.notify_all();
    }
}

/// The reset handler: Ok(()) acknowledges the command, Err (or a panic) leaves it unacknowledged
/// (it comes again on the next poll, so the handler must tolerate repeats: compare `reset_id`).
pub type Handler = dyn Fn(&Value) -> Result<(), String> + Send + Sync;

struct PollerInner {
    client: Client,
    agent_id: String,
    on_reset: Box<Handler>,
    interval: Duration,
    stop: Mutex<bool>,
    wake: Condvar,
}

/// Pull reset commands for one agent, run the handler and acknowledge each command it accepted.
pub struct CommandPoller {
    inner: Arc<PollerInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl CommandPoller {
    pub fn new(client: Client, agent_id: &str, interval: Duration, on_reset: Box<Handler>) -> CommandPoller {
        CommandPoller {
            inner: Arc::new(PollerInner {
                client,
                agent_id: agent_id.to_string(),
                on_reset,
                interval,
                stop: Mutex::new(false),
                wake: Condvar::new(),
            }),
            thread: Mutex::new(None),
        }
    }

    /// One poll: the number of commands handled and acknowledged.
    pub fn poll_once(&self) -> Result<usize, Error> {
        self.inner.poll_once()
    }

    pub fn start(&self) {
        let mut t = self.thread.lock().unwrap_or_else(|e| e.into_inner());
        if t.is_none() {
            let inner = Arc::clone(&self.inner);
            *t = Some(std::thread::spawn(move || loop {
                {
                    let stop = inner.stop.lock().unwrap_or_else(|e| e.into_inner());
                    let (stop, _) = inner.wake.wait_timeout_while(stop, inner.interval, |s| !*s).unwrap_or_else(|e| e.into_inner());
                    if *stop {
                        return;
                    }
                }
                if let Err(e) = inner.poll_once() {
                    eprintln!("smartwatch poller: polling commands failed: {}", e);
                }
            }));
        }
    }

    pub fn stop(&self) {
        *self.inner.stop.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.inner.wake.notify_all();
        if let Some(t) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = t.join();
        }
    }
}

impl PollerInner {
    fn poll_once(&self) -> Result<usize, Error> {
        let mut n = 0;
        for cmd in self.client.commands(&self.agent_id)? {
            if cmd.get("type").and_then(Value::as_str) != Some("reset") {
                continue;
            }
            let rid = match cmd.get("reset_id").and_then(Value::as_str) {
                Some(r) => r.to_string(),
                None => continue,
            };
            let ok = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.on_reset)(&cmd))) {
                Ok(Ok(())) => true,
                Ok(Err(e)) => {
                    eprintln!("smartwatch poller: on_reset failed for {}; not acknowledged: {}", rid, e);
                    false
                }
                Err(_) => {
                    eprintln!("smartwatch poller: on_reset panicked for {}; not acknowledged", rid);
                    false
                }
            };
            if ok {
                self.client.ack(&rid, &self.agent_id)?;
                n += 1;
            }
        }
        Ok(n)
    }
}
