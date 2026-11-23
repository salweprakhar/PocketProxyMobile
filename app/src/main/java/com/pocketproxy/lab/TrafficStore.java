package com.pocketproxy.lab;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/** Ephemeral traffic history. Nothing is written to disk. */
public final class TrafficStore {
    private static final int LIMIT = 300;
    private static final ArrayDeque<Entry> HISTORY = new ArrayDeque<>();
    private static final AtomicLong NEXT_ID = new AtomicLong(1);
    private static long revision = 1;
    public static volatile boolean captureBodyPreview = false;
    public static volatile String lastError = "";
    public static volatile boolean proxyRunning = false;

    private TrafficStore() {}

    public static class Entry {
        public final long id = NEXT_ID.getAndIncrement();
        public final long createdAt = System.currentTimeMillis();
        public final String method;
        public final String url;
        public final String host;
        public volatile String status = "…";
        public volatile String requestHeaders = "";
        public volatile String rawRequestHeaders = "";
        public volatile String responseHeaders = "";
        public volatile String requestBody = "";
        public volatile String responseBody = "";
        public volatile long durationMs = 0;
        public volatile String forwardedRequest = "";

        Entry(String method, String url, String host) {
            this.method = method;
            this.url = sanitizeUrl(url);
            this.host = host;
        }

        public String timeLabel() {
            return new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date(createdAt));
        }

        public String detail() {
            return "#" + id + "  " + timeLabel() + "\n" + method + " " + url + "\n"
                    + "Host: " + host + "\nStatus: " + status + "\nDuration: " + durationMs + " ms"
                    + "\n\nREQUEST HEADERS (sensitive values redacted)\n" + requestHeaders
                    + "\n\nREQUEST BODY"
                    + (requestBody.isEmpty()
                        ? "\n[No body captured — enable 'Capture HTTP body previews' before sending the request]"
                        : "\n" + requestBody)
                    + "\n\nRESPONSE HEADERS (sensitive values redacted)\n" + responseHeaders
                    + "\n\nRESPONSE BODY"
                    + (responseBody.isEmpty()
                        ? "\n[No response body captured]"
                        : "\n" + responseBody)
                    + (forwardedRequest.isEmpty()
                        ? ""
                        : "\n\nFORWARDED REQUEST\n" + forwardedRequest);
        }
    }

    public static synchronized void add(Entry entry) {
        HISTORY.addFirst(entry);
        while (HISTORY.size() > LIMIT) HISTORY.removeLast();
        revision++;
    }

    public static synchronized void changed() { revision++; }
    public static synchronized long revision() { return revision; }
    public static synchronized List<Entry> snapshot() { return new ArrayList<>(HISTORY); }
    public static synchronized void clear() { HISTORY.clear(); revision++; }

    public static String sanitizeHeaders(List<String> raw) {
        StringBuilder out = new StringBuilder();
        int lines = 0;
        for (String line : raw) {
            if (++lines > 80) { out.append("[remaining headers omitted]\n"); break; }
            int colon = line.indexOf(':');
            if (colon >= 0) {
                String key = line.substring(0, colon).trim();
                String lower = key.toLowerCase(Locale.US);
                if (lower.equals("authorization") || lower.equals("proxy-authorization") ||
                    lower.equals("cookie") || lower.equals("set-cookie") ||
                    lower.equals("x-api-key") || lower.contains("token") ||
                    lower.contains("secret") || lower.contains("credential") ||
                    lower.contains("session")) {
                    out.append(key).append(": [REDACTED]\n");
                    continue;
                }
            }
            out.append(line.length() > 400 ? line.substring(0, 400) + "…" : line).append('\n');
        }
        return out.toString();
    }

    private static final Pattern SECRET_QUERY = Pattern.compile(
        "(?i)([?&](?:access_token|refresh_token|token|key|api_key|password|secret|auth|code|session|signature)=)[^&#]*");

    public static String sanitizeUrl(String url) {
        return SECRET_QUERY.matcher(url).replaceAll("$1[REDACTED]");
    }

    public static String exportSummary() {
        StringBuilder out = new StringBuilder("PocketProxy Lab - sanitized metadata export\n");
        out.append("No bodies, credentials or complete headers included.\n\n");
        for (Entry entry : snapshot()) {
            out.append(entry.timeLabel()).append("  ").append(entry.method).append("  ")
               .append(entry.status).append("  ").append(entry.url).append('\n');
        }
        return out.toString();
    }
}
