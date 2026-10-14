package cloud.smarttasks.smartwatch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Pulls reset commands for one agent (spec/PORTING.md item 10): every {@code intervalMs} a GET
 * /v1/agents/{id}/commands; for each {"type": "reset", ...} command the handler runs, and when it returns
 * normally the command is acknowledged (POST /v1/resets/{reset_id}/ack). A handler that throws: no
 * acknowledgement, so the command comes again on the next poll (the handler must tolerate repeats; the
 * command's reset_id tells them apart).
 */
public final class CommandPoller implements AutoCloseable {
    /** Called with each reset command ({type, reset_id, reason, created_ms}). */
    @FunctionalInterface
    public interface Handler {
        void onReset(Map<?, ?> command) throws Exception;
    }

    private final Client client;
    public final String agentId;
    private final Handler handler;
    private final long intervalMs;
    private final List<String> handled = Collections.synchronizedList(new ArrayList<>());
    private Thread thread;
    private volatile boolean stop;

    public CommandPoller(Client client, String agentId, Handler handler, long intervalMs) {
        this.client = client;
        this.agentId = agentId;
        this.handler = handler;
        this.intervalMs = intervalMs;
    }

    /** The reset_ids handled and acknowledged so far. */
    public List<String> handled() { synchronized (handled) { return new ArrayList<>(handled); } }

    /** One poll; returns the number of commands handled and acknowledged. */
    public int pollOnce() throws IOException {
        int n = 0;
        for (Object o : client.commands(agentId)) {
            if (!(o instanceof Map<?, ?> cmd) || !"reset".equals(cmd.get("type")) || !(cmd.get("reset_id") instanceof String rid)) continue;
            try {
                handler.onReset(cmd);
            } catch (Exception e) {
                System.err.println("smartwatch: on_reset failed for " + rid + "; not acknowledged: " + e);
                continue;
            }
            client.ack(rid, agentId);
            handled.add(rid);
            n++;
        }
        return n;
    }

    /** Start polling in a daemon thread. */
    public synchronized CommandPoller start() {
        if (thread == null) {
            stop = false;
            thread = new Thread(this::run, "smartwatch-commands");
            thread.setDaemon(true);
            thread.start();
        }
        return this;
    }

    private void run() {
        while (true) {
            synchronized (this) {
                long end = System.nanoTime() + intervalMs * 1_000_000L;
                try {
                    while (!stop) {
                        long left = (end - System.nanoTime()) / 1_000_000L;
                        if (left <= 0) break;
                        wait(left);
                    }
                } catch (InterruptedException e) {
                    return;
                }
                if (stop) return;
            }
            try {
                pollOnce();
            } catch (IOException | RuntimeException e) {
                System.err.println("smartwatch: polling commands failed: " + e.getMessage());
            }
        }
    }

    /** Stop polling (waits up to 5 s for the thread). */
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
    }
}
