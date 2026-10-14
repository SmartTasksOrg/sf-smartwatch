package cloud.smarttasks.smartwatch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Calls to the Python monitor (java.net.HttpURLConnection, a new connection per request, redirects never
 * followed: they would carry the bearer token elsewhere). A network failure is an IOException; an answer
 * other than 2xx is a {@link ClientError} with its status.
 */
public final class Client {
    /** The largest answer read; a longer one is an error. */
    public static final int MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
    public final String url;
    private final String token;
    private final int timeoutMs;

    /** A non-2xx answer. */
    public static final class ClientError extends IOException {
        private static final long serialVersionUID = 1L;
        public final int status;
        public final transient Object body;

        ClientError(int status, Object body, String text) {
            super("HTTP " + status + ": " + text);
            this.status = status;
            this.body = body;
        }
    }

    public Client(String url, String token, Duration timeout) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new IllegalArgumentException("the monitor URL must start with http:// or https://");
        }
        this.url = url.replaceAll("/+$", "");
        this.token = token;
        this.timeoutMs = (int) Math.max(1, timeout.toMillis());
    }

    /** Percent-encode one path segment (RFC 3986 unreserved characters are kept; "/" becomes %2F). */
    public static String quoteId(String s) {
        StringBuilder b = new StringBuilder();
        for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
            int c = x & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
                b.append((char) c);
            } else {
                b.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return b.toString();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        if (in == null) return new byte[0];
        try (in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) >= 0) {
                if (out.size() + n > MAX_RESPONSE_BYTES) throw new IOException("the answer is longer than " + MAX_RESPONSE_BYTES + " bytes");
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    /** One request; {@code body} (a JSON value without fractions) is sent as JSON when not null. Returns the
     *  parsed JSON answer (or the text when it is not a JSON object or array). */
    public Object request(String method, String path, Object body) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(url + path).toURL().openConnection();
        try {
            c.setRequestMethod(method);
            c.setConnectTimeout(timeoutMs);
            c.setReadTimeout(timeoutMs);
            c.setUseCaches(false);
            c.setInstanceFollowRedirects(false);
            c.setRequestProperty("Accept", "application/json");
            c.setRequestProperty("Connection", "close");
            if (token != null && !token.isEmpty()) c.setRequestProperty("Authorization", "Bearer " + token);
            if (method.equals("POST")) {
                byte[] data = body == null ? new byte[0] : Json.canonicalBytes(body);
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json");
                c.setFixedLengthStreamingMode(data.length);
                try (OutputStream o = c.getOutputStream()) {
                    o.write(data);
                }
            }
            int status = c.getResponseCode();
            if (status < 200 || status >= 300) {
                String text = new String(readAll(c.getErrorStream()), StandardCharsets.UTF_8);
                Object parsed = text;
                try {
                    parsed = Json.parse(text);
                } catch (IllegalArgumentException e) {
                    // keep the text
                }
                throw new ClientError(status, parsed, text.length() > 300 ? text.substring(0, 300) : text);
            }
            String text = new String(readAll(c.getInputStream()), StandardCharsets.UTF_8);
            if (text.startsWith("{") || text.startsWith("[")) {
                try {
                    return Json.parse(text);
                } catch (IllegalArgumentException e) {
                    throw new IOException("the monitor answered with invalid JSON: " + e.getMessage(), e);
                }
            }
            return text;
        } finally {
            c.disconnect();
        }
    }

    /** POST /v1/events with {"events": [...]}: returns {"accepted", "rejected"}. */
    public Object events(List<Map<String, Object>> events) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("events", events);
        return request("POST", "/v1/events", body);
    }

    /** GET /v1/agents/{id}/commands: the list of pending commands. */
    public List<?> commands(String agentId) throws IOException {
        Object r = request("GET", "/v1/agents/" + quoteId(agentId) + "/commands", null);
        if (r instanceof Map<?, ?> m && m.get("commands") instanceof List<?> l) return l;
        throw new IOException("the monitor answered the commands request without a commands list");
    }

    /** POST /v1/resets/{reset_id}/ack with {"agent_id": id}. */
    public Object ack(String resetId, String agentId) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        if (agentId != null) body.put("agent_id", agentId);
        return request("POST", "/v1/resets/" + quoteId(resetId) + "/ack", body);
    }
}
