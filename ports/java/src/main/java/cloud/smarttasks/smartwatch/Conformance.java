package cloud.smarttasks.smartwatch;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Runs spec/conformance/*.json against the Java port, exactly as the Python runner does.
 *  Usage: java -cp build/classes cloud.smarttasks.smartwatch.Conformance DIR */
public final class Conformance {
    private int total;
    private final List<String> fails = new ArrayList<>();

    private static String c(Object v) {
        try {
            return Json.canonical(v);
        } catch (IllegalArgumentException e) {
            return "<not canonical: " + e.getMessage() + ">";
        }
    }

    private void check(String name, Object got, Object want) {
        total++;
        String g = c(got), w = c(want);
        if (!g.equals(w)) fails.add(name + ": got " + cut(g) + ", want " + cut(w));
    }

    private static String cut(String s) { return s.length() > 300 ? s.substring(0, 300) : s; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static List<?> list(Object o) { return (List<?>) o; }

    private static Map<String, Object> load(String dir, String name) throws Exception {
        return map(Json.parse(Files.readString(Path.of(dir, name), StandardCharsets.UTF_8)));
    }

    private static Map<String, Object> pick(Map<String, Object> c, String... keys) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : keys) if (c.containsKey(k)) out.put(k, c.get(k));
        return out;
    }

    private static List<?> expand(Object items) {
        if (items instanceof Map<?, ?> m) {
            List<String> out = new ArrayList<>();
            for (long i = (Long) m.get("from"); i < (Long) m.get("to"); i++) out.add(m.get("prefix") + Long.toString(i));
            return out;
        }
        return list(items);
    }

    void run(String dir) throws Exception {
        for (Object o : list(load(dir, "canonical.json").get("cases"))) {
            Map<String, Object> cs = map(o);
            String text = c(cs.get("input"));
            check("canonical/" + cs.get("name"), List.of(text, Hashing.sha256Hex(text.getBytes(StandardCharsets.UTF_8))),
                List.of(cs.get("canonical"), cs.get("sha256")));
        }

        List<?> hashing = list(load(dir, "hashing.json").get("cases"));
        for (int i = 0; i < hashing.size(); i++) {
            Map<String, Object> cs = map(hashing.get(i));
            String seed = (String) cs.get("seed"), text = (String) cs.get("text");
            long h64 = Hashing.fnv1a64(seed, text);
            Map<String, Object> got = Engine.obj("fnv1a32", Hashing.fnv1a32(seed, text), "fnv1a64", Long.toUnsignedString(h64),
                "mix64", Long.toUnsignedString(Hashing.mix64(h64)), "bucket", (long) Hashing.bucket(seed, text));
            check("hashing/" + i, got, pick(cs, "fnv1a32", "fnv1a64", "mix64", "bucket"));
        }

        for (Object o : list(load(dir, "hll.json").get("cases"))) {
            Map<String, Object> cs = map(o);
            HyperLogLog h = new HyperLogLog((String) cs.get("seed"));
            for (Object x : expand(cs.get("items"))) h.add((String) x);
            check("hll/" + cs.get("name"), Engine.obj("estimate", h.estimate(), "digest", h.digest()), pick(cs, "estimate", "digest"));
        }

        List<?> density = list(load(dir, "density.json").get("cases"));
        for (int i = 0; i < density.size(); i++) {
            Map<String, Object> cs = map(density.get(i));
            check("density/" + i, Engine.densityMicro((Long) cs.get("messages"), (Long) cs.get("possible_pairs"), (Long) cs.get("window_ms")),
                cs.get("density_micro"));
        }

        for (Object o : list(load(dir, "policies.json").get("cases"))) {
            Map<String, Object> cs = map(o);
            Object got;
            try {
                Policy.validate(cs.get("policy"));
                got = Engine.obj("ok", true);
            } catch (WatchError e) {
                got = Engine.obj("ok", false, "code", e.code);
            }
            check("policies/" + cs.get("name"), got, pick(cs, "ok", "code"));
        }

        for (Object o : list(load(dir, "calibration.json").get("cases"))) {
            Map<String, Object> cs = map(o);
            Object got;
            try {
                got = Engine.obj("ok", true, "thresholds", Calibrate.thresholds(list(cs.get("densities")), list(cs.get("permille"))));
            } catch (IllegalArgumentException e) {
                got = Engine.obj("ok", false);
            }
            check("calibration/" + cs.get("name"), got, pick(cs, "ok", "thresholds"));
        }

        for (Object o : list(load(dir, "monitor.json").get("cases"))) {
            Map<String, Object> cs = map(o);
            Engine eng = new Engine(Policy.validate(cs.get("policy")));
            List<?> steps = list(cs.get("steps"));
            for (int i = 0; i < steps.size(); i++) {
                Map<String, Object> st = map(steps.get(i));
                String op = (String) st.get("op");
                Object got;
                try {
                    if (op.equals("add")) got = Engine.obj("ok", true, "outputs", eng.addValues(st.get("src"), st.get("dst"), st.get("ts_ms"), st.get("count")));
                    else if (op.equals("flush")) got = Engine.obj("ok", true, "outputs", eng.flushValue(st.get("now_ms")));
                    else got = eng.snapshot();
                } catch (WatchError e) {
                    got = Engine.obj("ok", false, "code", e.code);
                }
                check("monitor/" + cs.get("name") + " step " + i + " (" + op + ")", got, st.get("expect"));
            }
        }

        for (Object o : list(load(dir, "audit.json").get("cases"))) {
            Map<String, Object> cs = map(o);
            Audit.Result r = Audit.verify(list(cs.get("records")));
            check("audit/" + cs.get("name"), Engine.obj("ok", r.ok(), "index", r.index()), cs.get("result"));
        }
    }

    public static void main(String[] args) throws Exception {
        String dir = args.length > 0 ? args[0] : "../../spec/conformance";
        Conformance r = new Conformance();
        r.run(dir);
        for (String f : r.fails) System.out.println("FAIL " + f);
        if (!r.fails.isEmpty()) {
            System.out.println("java: " + r.fails.size() + " of " + r.total + " vectors FAILED");
            System.exit(1);
        }
        System.out.println("java: " + r.total + "/" + r.total + " vectors passed");
    }
}
