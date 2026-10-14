package cloud.smarttasks.smartwatch;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** The interop program for ports/conformance/interop.py (spec/PORTING.md, "The interop program"):
 *  URL AGENT_IDS SECONDS, the ingest token in SMARTWATCH_INGEST_TOKEN. */
public final class Interop {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: Interop URL AGENT_IDS SECONDS");
            System.exit(2);
        }
        String url = args[0];
        String[] ids = args[1].split(",");
        int seconds = Integer.parseInt(args[2]);
        String token = System.getenv("SMARTWATCH_INGEST_TOKEN");
        Object out = new Object();
        List<CommandPoller> pollers = new ArrayList<>();
        for (String a : ids) {
            pollers.add(new CommandPoller(new Client(url, token, Duration.ofSeconds(5)), a, cmd -> {
                synchronized (out) {
                    System.out.println("RESET " + a + " " + cmd.get("reset_id"));
                    System.out.flush();
                }
            }, 200).start());
        }
        Reporter rep = new Reporter(url, token).start();
        long t0 = System.nanoTime();
        for (int r = 0; r < seconds * 10; r++) {
            for (String a : ids) {
                for (String b : ids) {
                    if (!a.equals(b)) rep.record(a, b, 1);
                }
            }
            long left = t0 + (r + 1) * 100_000_000L - System.nanoTime();
            if (left > 0) Thread.sleep(left / 1_000_000L, (int) (left % 1_000_000L));
        }
        rep.close();
        synchronized (out) {
            System.out.println("SENT " + rep.sent());
            System.out.flush();
        }
        InputStream in = System.in;
        byte[] buf = new byte[4096];
        try {
            while (in.read(buf) >= 0) { /* wait for standard input to close */ }
        } catch (IOException e) {
            // treat as closed
        }
        for (CommandPoller p : pollers) p.close();
        System.exit(0);
    }
}
