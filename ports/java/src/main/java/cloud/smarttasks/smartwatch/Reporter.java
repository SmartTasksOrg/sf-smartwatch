package cloud.smarttasks.smartwatch;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * The agent-side reporter (spec/PORTING.md item 9). {@link #record} adds to an in-memory map keyed by
 * (src, dst, ts_ms - ts_ms mod 1000) and never touches the network; a daemon thread sends the map every
 * second (plus or minus up to 200 ms of random jitter) as POST /v1/events, at most 10,000 events per request,
 * sorted by time, then src, then dst. A network failure or a 5xx answer puts the events back for the next
 * send; a 400/401/403/413 answer drops them (counted in {@link #rejected()}). At most {@code maxKeys} keys are
 * kept; messages beyond that are counted in {@link #dropped()}. {@link #close()} stops the thread and sends
 * what is left.
 */
public final class Reporter implements AutoCloseable {
    public static final int BATCH = 10_000;
    public static final long MAX_KEY_COUNT = 1_000_000_000L;

    private record Key(String src, String dst, long ts) {}

    private final Client client;
    private final long intervalMs;
    private final long jitterMs;
    private final int maxKeys;
    private final long bucketMs;
    private final Object lock = new Object();
    private final Object sendLock = new Object();
    private Map<Key, Long> buf = new HashMap<>();
    private Thread thread;
    private volatile boolean stop;
    private long sent, dropped, rejected, errors;

    public Reporter(Client client) { this(client, 1000, 200, 100_000, 1000); }

    public Reporter(String url, String token) { this(new Client(url, token, Duration.ofSeconds(5))); }

    public Reporter(Client client, long intervalMs, long jitterMs, int maxKeys, long bucketMs) {
        if (bucketMs < 1 || bucketMs > 60000) throw new IllegalArgumentException("bucketMs must be from 1 to 60000");
        this.client = client;
        this.intervalMs = intervalMs;
        this.jitterMs = jitterMs;
        this.maxKeys = maxKeys;
        this.bucketMs = bucketMs;
    }

    /** One message from src to dst now. */
    public void record(String src, String dst) { record(src, dst, 1, System.currentTimeMillis()); }

    /** {@code count} messages from src to dst now. */
    public void record(String src, String dst, long count) { record(src, dst, count, System.currentTimeMillis()); }

    /** {@code count} messages from src to dst at tsMs; WatchError(WATCH-BAD-EVENT) for an invalid event. */
    public void record(String src, String dst, long count, long tsMs) {
        Engine.checkEvent(src, dst, tsMs, count);
        Key k = new Key(src, dst, tsMs - tsMs % bucketMs);
        synchronized (lock) {
            put(k, count);
        }
    }

    private void put(Key k, long count) {   // with lock held
        Long have = buf.get(k);
        if (have != null) buf.put(k, Math.min(have + count, MAX_KEY_COUNT));
        else if (buf.size() < maxKeys) buf.put(k, count);
        else dropped += count;
    }

    /** Messages the monitor accepted. */
    public long sent() { synchronized (lock) { return sent; } }

    /** Messages lost to the maxKeys bound. */
    public long dropped() { synchronized (lock) { return dropped; } }

    /** Messages the monitor refused. */
    public long rejected() { synchronized (lock) { return rejected; } }

    /** Failed sends (their events were kept for the next one). */
    public long errors() { synchronized (lock) { return errors; } }

    /** Send everything recorded so far; returns the messages accepted. Safe to call from any thread. */
    public long flush() {
        synchronized (sendLock) {
            Map<Key, Long> mine;
            synchronized (lock) {
                mine = buf;
                buf = new HashMap<>();
            }
            List<Map.Entry<Key, Long>> items = new ArrayList<>(mine.entrySet());
            items.sort((x, y) -> {
                int c = Long.compare(x.getKey().ts(), y.getKey().ts());
                if (c == 0) c = x.getKey().src().compareTo(y.getKey().src());
                if (c == 0) c = x.getKey().dst().compareTo(y.getKey().dst());
                return c;
            });
            long accepted = 0;
            for (int i = 0; i < items.size(); i += BATCH) {
                List<Map.Entry<Key, Long>> part = items.subList(i, Math.min(items.size(), i + BATCH));
                List<Map<String, Object>> evs = new ArrayList<>();
                long sum = 0;
                for (Map.Entry<Key, Long> e : part) {
                    Map<String, Object> ev = new LinkedHashMap<>();
                    ev.put("src", e.getKey().src());
                    ev.put("dst", e.getKey().dst());
                    ev.put("ts_ms", e.getKey().ts());
                    ev.put("count", e.getValue());
                    evs.add(ev);
                    sum += e.getValue();
                }
                Object res;
                try {
                    res = client.events(evs);
                } catch (IOException e) {
                    if (e instanceof Client.ClientError ce && Set.of(400, 401, 403, 413).contains(ce.status)) {
                        System.err.println("smartwatch: the monitor refused a batch: " + e.getMessage());
                        synchronized (lock) { rejected += sum; }
                        continue;
                    }
                    System.err.println("smartwatch: sending to the monitor failed (kept for the next send): " + e.getMessage());
                    synchronized (lock) {
                        errors++;
                        for (Map.Entry<Key, Long> x : items.subList(i, items.size())) put(x.getKey(), x.getValue());
                    }
                    break;
                }
                Set<Long> bad = new HashSet<>();
                if (res instanceof Map<?, ?> m && m.get("rejected") instanceof List<?> rl) {
                    for (Object r : rl) {
                        if (r instanceof Map<?, ?> rm && rm.get("index") instanceof Long idx && idx >= 0 && idx < evs.size()) bad.add(idx);
                    }
                }
                long nBad = 0;
                for (Long idx : bad) nBad += (Long) evs.get((int) (long) idx).get("count");
                long acc = sum - nBad;
                accepted += acc;
                synchronized (lock) {
                    rejected += nBad;
                    sent += acc;
                }
            }
            return accepted;
        }
    }

    /** Start the sending thread (a daemon). */
    public synchronized Reporter start() {
        if (thread == null) {
            stop = false;
            thread = new Thread(this::run, "smartwatch-reporter");
            thread.setDaemon(true);
            thread.start();
        }
        return this;
    }

    private void run() {
        while (!stop) {
            long wait = intervalMs + (jitterMs > 0 ? ThreadLocalRandom.current().nextLong(-jitterMs, jitterMs + 1) : 0);
            synchronized (this) {
                long end = System.nanoTime() + Math.max(0, wait) * 1_000_000L;
                try {
                    while (!stop) {
                        long left = (end - System.nanoTime()) / 1_000_000L;
                        if (left <= 0) break;
                        wait(left);
                    }
                } catch (InterruptedException e) {
                    return;
                }
            }
            if (stop) return;
            try {
                flush();
            } catch (RuntimeException e) {
                System.err.println("smartwatch: reporter flush failed: " + e);
            }
        }
    }

    /** Stop the thread and send what is left. */
    @Override
    public void close() {
        Thread t;
        synchronized (this) {
            stop = true;
            notifyAll();
            t = thread;
            thread = null;
        }
        if (t != null) {
            try {
                t.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        flush();
    }
}
