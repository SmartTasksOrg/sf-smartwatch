package cloud.smarttasks.smartwatch;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A validated policy document (spec/SEMANTICS.md section 3). {@link #validate(Object)} takes the parsed JSON
 * ({@link Json#parse}) and throws {@link WatchError} with code WATCH-BAD-POLICY on any violation.
 */
public final class Policy {
    public static final Pattern ID = Pattern.compile("[A-Za-z0-9._:@/-]{1,128}");
    public static final Pattern LEVEL_NAME = Pattern.compile("[a-z][a-z0-9_-]{0,31}");
    static final Set<String> FIELDS = Set.of("schema", "environment", "window_ms", "late_windows", "max_empty_windows",
        "min_agents", "levels", "hysteresis_permille", "reset", "limits", "hash_seed");
    static final Set<String> RESET_FIELDS = Set.of("level", "sustain_ms", "mode", "confirm_timeout_ms", "on_timeout",
        "cooldown_ms", "max_agents", "hot_pair_min_count");
    static final Set<String> LIMIT_FIELDS = Set.of("max_pairs_exact", "max_agents_exact", "top_k", "candidates");

    /** One grading level. */
    public record Level(String name, long minDensityMicro) {}

    public final String environment;
    public final long windowMs;
    public final int lateWindows;
    public final int maxEmptyWindows;
    public final long minAgents;
    public final List<Level> levels;
    public final long hysteresisPermille;
    public final String resetLevel;
    public final long sustainMs;
    public final String resetMode;
    public final long confirmTimeoutMs;
    public final String onTimeout;
    public final long cooldownMs;
    public final int resetMaxAgents;
    public final long hotPairMinCount;
    public final long maxPairsExact;
    public final long maxAgentsExact;
    public final int topK;
    public final int candidates;
    public final String hashSeed;
    /** The document as given (parsed JSON). */
    public final Map<String, Object> doc;

    private Policy(Map<String, Object> d) {
        doc = d;
        environment = (String) d.get("environment");
        windowMs = (Long) d.get("window_ms");
        lateWindows = (int) (long) (Long) d.get("late_windows");
        maxEmptyWindows = (int) (long) (Long) d.get("max_empty_windows");
        minAgents = (Long) d.get("min_agents");
        List<Level> lv = new ArrayList<>();
        for (Object o : (List<?>) d.get("levels")) {
            Map<?, ?> m = (Map<?, ?>) o;
            lv.add(new Level((String) m.get("name"), (Long) m.get("min_density_micro")));
        }
        levels = Collections.unmodifiableList(lv);
        hysteresisPermille = (Long) d.get("hysteresis_permille");
        Map<?, ?> r = (Map<?, ?>) d.get("reset");
        resetLevel = (String) r.get("level");
        sustainMs = (Long) r.get("sustain_ms");
        resetMode = (String) r.get("mode");
        confirmTimeoutMs = (Long) r.get("confirm_timeout_ms");
        onTimeout = (String) r.get("on_timeout");
        cooldownMs = (Long) r.get("cooldown_ms");
        resetMaxAgents = (int) (long) (Long) r.get("max_agents");
        hotPairMinCount = (Long) r.get("hot_pair_min_count");
        Map<?, ?> li = (Map<?, ?>) d.get("limits");
        maxPairsExact = (Long) li.get("max_pairs_exact");
        maxAgentsExact = (Long) li.get("max_agents_exact");
        topK = (int) (long) (Long) li.get("top_k");
        candidates = (int) (long) (Long) li.get("candidates");
        hashSeed = (String) d.get("hash_seed");
    }

    /** Index of a level name in {@link #levels}, -1 when absent. */
    public int levelIndex(String name) {
        for (int i = 0; i < levels.size(); i++) if (levels.get(i).name().equals(name)) return i;
        return -1;
    }

    private static WatchError bad(String msg) { return new WatchError("WATCH-BAD-POLICY", msg); }

    private static boolean isInt(Object v, long lo, long hi) {
        return v instanceof Long x && x >= lo && x <= hi;
    }

    private static boolean exactly(Object o, Set<String> fields) {
        return o instanceof Map<?, ?> m && m.keySet().equals(fields);
    }

    private static void ints(Map<?, ?> m, String prefix, Object[][] rules) {
        for (Object[] r : rules) {
            String k = (String) r[0];
            if (!isInt(m.get(k), (Long) r[1], (Long) r[2])) {
                throw bad(prefix + k + " must be an integer from " + r[1] + " to " + r[2]);
            }
        }
    }

    /** Validate a parsed policy document; returns the policy or throws WatchError(WATCH-BAD-POLICY). */
    @SuppressWarnings("unchecked")
    public static Policy validate(Object doc) {
        if (!exactly(doc, FIELDS)) throw bad("the policy must have exactly the fields " + new java.util.TreeSet<>(FIELDS));
        Map<String, Object> d = (Map<String, Object>) doc;
        if (!"smartwatch.policy/v1".equals(d.get("schema"))) throw bad("schema must be \"smartwatch.policy/v1\"");
        if (!(d.get("environment") instanceof String env) || !ID.matcher(env).matches()) {
            throw bad("environment must match [A-Za-z0-9._:@/-]{1,128}");
        }
        ints(d, "", new Object[][] {{"window_ms", 100L, 60000L}, {"late_windows", 0L, 60L}, {"max_empty_windows", 0L, 3600L},
            {"min_agents", 2L, 1_000_000L}, {"hysteresis_permille", 0L, 900L}});
        if (!(d.get("levels") instanceof List<?> lv) || lv.isEmpty() || lv.size() > 8) throw bad("levels must be a list of 1 to 8 levels");
        Set<String> names = new HashSet<>();
        long prev = 0;
        for (Object x : lv) {
            if (!exactly(x, Set.of("name", "min_density_micro"))) throw bad("each level must be {\"name\", \"min_density_micro\"}");
            Map<?, ?> m = (Map<?, ?>) x;
            if (!(m.get("name") instanceof String n) || !LEVEL_NAME.matcher(n).matches() || n.equals("normal") || names.contains(n)) {
                throw bad("level names must match [a-z][a-z0-9_-]{0,31}, be unique and not \"normal\"");
            }
            if (!isInt(m.get("min_density_micro"), 1, Engine.MAX_INT) || (Long) m.get("min_density_micro") <= prev) {
                throw bad("min_density_micro must be a positive integer, strictly increasing from level to level");
            }
            names.add(n);
            prev = (Long) m.get("min_density_micro");
        }
        if (!exactly(d.get("reset"), RESET_FIELDS)) throw bad("reset must have exactly the fields " + new java.util.TreeSet<>(RESET_FIELDS));
        Map<?, ?> r = (Map<?, ?>) d.get("reset");
        if (!(r.get("level") instanceof String rl) || !names.contains(rl)) throw bad("reset.level must be one of the level names");
        if (!List.of("auto", "confirm", "off").contains(r.get("mode"))) throw bad("reset.mode must be auto, confirm or off");
        if (!List.of("reset", "cancel").contains(r.get("on_timeout"))) throw bad("reset.on_timeout must be reset or cancel");
        ints(r, "reset.", new Object[][] {{"sustain_ms", 0L, 3_600_000L}, {"confirm_timeout_ms", 0L, 3_600_000L},
            {"cooldown_ms", 0L, 86_400_000L}, {"max_agents", 1L, 1000L}, {"hot_pair_min_count", 1L, 1_000_000_000L}});
        if (!exactly(d.get("limits"), LIMIT_FIELDS)) throw bad("limits must have exactly the fields " + new java.util.TreeSet<>(LIMIT_FIELDS));
        ints((Map<?, ?>) d.get("limits"), "limits.", new Object[][] {{"max_pairs_exact", 1L, 10_000_000L},
            {"max_agents_exact", 1L, 10_000_000L}, {"top_k", 1L, 100L}, {"candidates", 1L, 65536L}});
        if (!(d.get("hash_seed") instanceof String seed) || !Json.validText(seed)) throw bad("hash_seed must be a string of valid Unicode");
        int n = seed.getBytes(StandardCharsets.UTF_8).length;
        if (n < 1 || n > 256) throw bad("hash_seed must be a string of 1 to 256 bytes");
        return new Policy(d);
    }

    /** Read and validate a policy file (WatchError when invalid or not JSON). */
    public static Policy load(Path path) throws IOException {
        Object doc;
        try {
            doc = Json.parse(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw bad(path + ": not JSON (" + e.getMessage() + ")");
        }
        return validate(doc);
    }
}
