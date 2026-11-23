package com.pocketproxy.lab;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Small local-only HTTP forward proxy.
 * HTTPS CONNECT uses byte-for-byte tunneling; this app NEVER decrypts TLS.
 */
public final class ProxyService extends Service {
    public static final int PORT = 8888;
    private static final String CHANNEL = "pocketproxy_capture";
    private static final int NOTIFICATION_ID = 71;
    private static final int MAX_HEADERS_BYTES = 128 * 1024;
    private static final int PREVIEW_BYTES = 4096;

    private final ExecutorService pool = Executors.newFixedThreadPool(24);
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private volatile boolean active = false;
    private ServerSocket server;
    private Thread acceptThread;

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (active) return START_STICKY;
        startForegroundMode();
        try {
            server = new ServerSocket();
            server.setReuseAddress(true);
            // Explicitly loopback only: never expose this proxy to the local Wi-Fi network.
            server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), PORT));
            TrafficStore.lastError = "";
            active = true;
            TrafficStore.proxyRunning = true;
            TrafficStore.changed();
            acceptThread = new Thread(this::acceptLoop, "PocketProxy-Acceptor");
            acceptThread.start();
        } catch (Exception e) {
            TrafficStore.lastError = "Could not start on port " + PORT + ": " + e.getMessage();
            TrafficStore.proxyRunning = false;
            TrafficStore.changed();
            stopSelf();
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    private void startForegroundMode() {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL, "Local proxy", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("PocketProxy is listening only on this phone");
            manager.createNotificationChannel(channel);
        }
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setContentTitle("PocketProxy Lab is running")
                .setContentText("Local HTTP proxy: 127.0.0.1:" + PORT)
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setOngoing(true)
                .build();
        startForeground(NOTIFICATION_ID, notification);
    }

    private void acceptLoop() {
        while (active) {
            try {
                Socket client = server.accept();
                client.setSoTimeout(60000);
                sockets.add(client);
                pool.execute(() -> handleClient(client));
            } catch (IOException e) {
                if (active) {
                    TrafficStore.lastError = "Proxy listener error: " + e.getMessage();
                    TrafficStore.changed();
                }
                break;
            } catch (RuntimeException e) {
                if (active) {
                    TrafficStore.lastError = "Proxy is busy: " + e.getMessage();
                    TrafficStore.changed();
                }
            }
        }
    }

    private void handleClient(Socket client) {
        TrafficStore.Entry entry = null;
        long started = System.currentTimeMillis();
        try (Socket ignored = client) {
            BufferedInputStream input = new BufferedInputStream(client.getInputStream());
            BufferedOutputStream output = new BufferedOutputStream(client.getOutputStream());
            String startLine = readLine(input);
            if (startLine == null || startLine.trim().isEmpty()) return;
            String[] first = startLine.split(" ", 3);
            if (first.length < 3) {
                sendError(output, 400, "Invalid request line");
                return;
            }
            String method = first[0].toUpperCase(Locale.US);
            String target = first[1];
            List<String> headers = readHeaders(input);
            if ("CONNECT".equals(method)) {
                HostPort hp = HostPort.parse(target, 443);
                entry = new TrafficStore.Entry(method, "https://" + hp.host + ":" + hp.port, hp.host);
                entry.requestHeaders = TrafficStore.sanitizeHeaders(headers);
                TrafficStore.add(entry);
                tunnel(client, input, output, hp, entry);
            } else {
                String hostHeader = headerValue(headers, "host");
                URI uri = resolveTarget(target, hostHeader);
                if (!"http".equalsIgnoreCase(uri.getScheme())) {
                    sendError(output, 400, "Only plain HTTP is supported; HTTPS requires CONNECT");
                    return;
                }
                String host = uri.getHost();
                if (host == null || host.isEmpty()) {
                    sendError(output, 400, "Missing target host");
                    return;
                }
                int port = uri.getPort() > 0 ? uri.getPort() : 80;
                entry = new TrafficStore.Entry(method, uri.toString(), host);
                entry.requestHeaders = TrafficStore.sanitizeHeaders(headers);
                entry.rawRequestHeaders = joinHeaders(headers);
                TrafficStore.add(entry);
                if ("pocketproxy.test".equalsIgnoreCase(host)) {
                    localSelfTest(output, entry);
                } else {
                    forwardHttp(input, output, method, uri, host, port, headers, entry);
                }
            }
        } catch (Exception e) {
            if (entry != null) {
                entry.status = "ERROR";
                entry.responseHeaders = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
        } finally {
            if (entry != null) {
                entry.durationMs = System.currentTimeMillis() - started;
                TrafficStore.changed();
            }
            sockets.remove(client);
        }
    }

    private static URI resolveTarget(String target, String hostHeader) throws Exception {
        URI uri = new URI(target);
        if (uri.getScheme() != null) return uri;
        if (hostHeader == null || hostHeader.isEmpty() || !target.startsWith("/")) {
            throw new IOException("Missing absolute URI or Host header");
        }
        return new URI("http://" + hostHeader + target);
    }

    private static String joinHeaders(List<String> headers) {
        StringBuilder raw = new StringBuilder();
        for (String header : headers) {
            raw.append(header).append('\n');
        }
        return raw.toString();
    }

    private void localSelfTest(OutputStream output, TrafficStore.Entry entry) throws IOException {
        byte[] body = "PocketProxy Lab self-test succeeded. No internet required.\n"
                .getBytes(StandardCharsets.UTF_8);
        String response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + body.length + "\r\nConnection: close\r\n\r\n";
        output.write(response.getBytes(StandardCharsets.ISO_8859_1));
        output.write(body);
        output.flush();
        entry.status = "200";
        entry.responseHeaders = "Content-Type: text/plain; charset=utf-8\nContent-Length: " + body.length;
        if (TrafficStore.captureBodyPreview) entry.responseBody = new String(body, StandardCharsets.UTF_8);
        TrafficStore.changed();
    }

    private void tunnel(Socket client, InputStream input, OutputStream output,
                        HostPort destination, TrafficStore.Entry entry) throws Exception {
        try (Socket upstream = new Socket()) {
            upstream.connect(new InetSocketAddress(destination.host, destination.port), 10000);
            upstream.setSoTimeout(60000);
            sockets.add(upstream);
            try {
                output.write("HTTP/1.1 200 Connection Established\r\n\r\n"
                        .getBytes(StandardCharsets.ISO_8859_1));
                output.flush();
                entry.status = "TUNNEL";
                entry.responseHeaders = "TLS bytes passed through unchanged. HTTPS content is not inspected.";
                TrafficStore.changed();

                InputStream remoteInput = upstream.getInputStream();
                OutputStream remoteOutput = upstream.getOutputStream();
                Thread upload = new Thread(() -> {
                    try { copyUntilEof(input, remoteOutput, null); }
                    catch (IOException ignored) { }
                    try { upstream.shutdownOutput(); }
                    catch (IOException ignored) { }
                }, "PocketProxy-TunnelUp");
                upload.setDaemon(true);
                upload.start();
                try { copyUntilEof(remoteInput, output, null); }
                catch (IOException ignored) { }
            } finally {
                sockets.remove(upstream);
            }
        }
    }

    private void forwardHttp(InputStream input, OutputStream output, String method,
                             URI uri, String host, int port, List<String> headers,
                             TrafficStore.Entry entry) throws Exception {
        try (Socket upstream = new Socket()) {
            upstream.connect(new InetSocketAddress(host, port), 10000);
            upstream.setSoTimeout(60000);
            sockets.add(upstream);
            try {
                BufferedOutputStream upstreamOut = new BufferedOutputStream(upstream.getOutputStream());
                BufferedInputStream upstreamIn = new BufferedInputStream(upstream.getInputStream());
                String path = uri.getRawPath();
                if (path == null || path.isEmpty()) path = "/";
                if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
                writeLine(upstreamOut, method + " " + path + " HTTP/1.1");
                boolean hasHost = false;
                boolean hasExpectContinue = false;
                for (String header : headers) {
                    String name = headerName(header);
                    if ("host".equals(name)) hasHost = true;
                    if ("expect".equals(name) && header.toLowerCase(Locale.US).contains("100-continue")) {
                        hasExpectContinue = true;
                        continue;
                    }
                    if (isHopByHop(name)) continue;
                    writeLine(upstreamOut, header);
                }
                if (!hasHost) writeLine(upstreamOut, "Host: " + host + (port != 80 ? ":" + port : ""));
                writeLine(upstreamOut, "Connection: close");
                writeLine(upstreamOut, "");
                upstreamOut.flush();
                if (hasExpectContinue) {
                    output.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                    output.flush();
                }
                ByteArrayOutputStream requestPreview = TrafficStore.captureBodyPreview
                        ? new ByteArrayOutputStream() : null;
                sendBody(input, upstreamOut, headers, requestPreview, false);
                upstreamOut.flush();
                if (requestPreview != null) entry.requestBody = preview(requestPreview);

                // Some servers send informational 1xx responses before the final response.
                String statusLine;
                List<String> responseHeaders;
                do {
                    statusLine = readLine(upstreamIn);
                    if (statusLine == null) throw new IOException("Upstream closed without response");
                    responseHeaders = readHeaders(upstreamIn);
                    if (!statusLine.matches("HTTP/\\d\\.\\d 1\\d\\d.*")) break;
                    writeLine(output, statusLine);
                    for (String line : responseHeaders) writeLine(output, line);
                    writeLine(output, "");
                    output.flush();
                } while (true);
                writeLine(output, statusLine);
                for (String line : responseHeaders) {
                    if (!isHopByHop(headerName(line))) writeLine(output, line);
                }
                writeLine(output, "Connection: close");
                writeLine(output, "");
                output.flush();
                String[] statusParts = statusLine.split(" ", 3);
                entry.status = statusParts.length >= 2 ? statusParts[1] : "?";
                entry.responseHeaders = TrafficStore.sanitizeHeaders(responseHeaders);
                TrafficStore.changed();

                int code = statusParts.length >= 2 ? safeInt(statusParts[1], 0) : 0;
                if (!"HEAD".equals(method) && code != 204 && code != 304 && (code < 100 || code >= 200)) {
                    ByteArrayOutputStream responsePreview = TrafficStore.captureBodyPreview
                            ? new ByteArrayOutputStream() : null;
                    sendBody(upstreamIn, output, responseHeaders, responsePreview, true);
                    if (responsePreview != null) entry.responseBody = preview(responsePreview);
                }
                output.flush();
            } finally {
                sockets.remove(upstream);
            }
        }
    }

    private static void sendBody(InputStream from, OutputStream to, List<String> headers,
                                 ByteArrayOutputStream preview, boolean untilEofWhenUnknown)
            throws IOException {
        String transfer = headerValue(headers, "transfer-encoding");
        if (transfer != null && transfer.toLowerCase(Locale.US).contains("chunked")) {
            copyChunked(from, to, preview);
        } else {
            String contentLength = headerValue(headers, "content-length");
            if (contentLength != null) {
                long length;
                try { length = Long.parseLong(contentLength.trim()); }
                catch (NumberFormatException ex) { throw new IOException("Invalid Content-Length"); }
                if (length < 0) throw new IOException("Negative Content-Length");
                copyFixed(from, to, length, preview);
            } else if (untilEofWhenUnknown) {
                copyUntilEof(from, to, preview);
            }
        }
    }

    private static void copyChunked(InputStream from, OutputStream to,
                                    ByteArrayOutputStream preview) throws IOException {
        while (true) {
            String line = readLine(from);
            if (line == null) throw new IOException("Incomplete chunk header");
            writeLine(to, line);
            String hex = line.split(";", 2)[0].trim();
            long length;
            try { length = Long.parseLong(hex, 16); }
            catch (NumberFormatException ex) { throw new IOException("Invalid chunk size"); }
            if (length < 0) throw new IOException("Negative chunk size");
            if (length == 0) {
                while (true) {
                    String trailer = readLine(from);
                    if (trailer == null) throw new IOException("Incomplete chunk trailer");
                    writeLine(to, trailer);
                    if (trailer.isEmpty()) return;
                }
            }
            copyFixed(from, to, length, preview);
            String crlf = readLine(from);
            if (crlf == null || !crlf.isEmpty()) throw new IOException("Invalid chunk delimiter");
            writeLine(to, "");
        }
    }

    private static void copyFixed(InputStream from, OutputStream to, long size,
                                  ByteArrayOutputStream preview) throws IOException {
        byte[] buffer = new byte[8192];
        long remaining = size;
        while (remaining > 0) {
            int count = from.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (count < 0) throw new IOException("Unexpected end of HTTP body");
            if (count == 0) continue;
            to.write(buffer, 0, count);
            sample(preview, buffer, count);
            remaining -= count;
        }
    }

    private static void copyUntilEof(InputStream from, OutputStream to,
                                     ByteArrayOutputStream preview) throws IOException {
        byte[] buffer = new byte[8192];
        int count;
        while ((count = from.read(buffer)) != -1) {
            to.write(buffer, 0, count);
            to.flush();
            sample(preview, buffer, count);
        }
    }

    private static void sample(ByteArrayOutputStream preview, byte[] buffer, int count) {
        if (preview == null) return;
        int remaining = PREVIEW_BYTES - preview.size();
        if (remaining > 0) preview.write(buffer, 0, Math.min(count, remaining));
    }

    private static String preview(ByteArrayOutputStream data) {
        if (data.size() == 0) return "";
        String value = new String(data.toByteArray(), StandardCharsets.UTF_8);
        return value.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]", "�")
                + (data.size() == PREVIEW_BYTES ? "\n[preview truncated]" : "");
    }

    private static boolean isHopByHop(String name) {
        return "connection".equals(name) || "proxy-connection".equals(name)
                || "keep-alive".equals(name) || "proxy-authorization".equals(name)
                || "proxy-authenticate".equals(name) || "upgrade".equals(name)
                || "te".equals(name);
    }

    private static String headerName(String line) {
        int colon = line.indexOf(':');
        return colon < 0 ? "" : line.substring(0, colon).trim().toLowerCase(Locale.US);
    }

    private static String headerValue(List<String> headers, String key) {
        for (String line : headers) {
            int colon = line.indexOf(':');
            if (colon > 0 && key.equalsIgnoreCase(line.substring(0, colon).trim()))
                return line.substring(colon + 1).trim();
        }
        return null;
    }

    private static List<String> readHeaders(InputStream input) throws IOException {
        List<String> lines = new ArrayList<>();
        int total = 0;
        while (true) {
            String line = readLine(input);
            if (line == null) throw new IOException("Incomplete headers");
            total += line.length() + 2;
            if (total > MAX_HEADERS_BYTES) throw new IOException("HTTP headers too large");
            if (line.isEmpty()) return lines;
            lines.add(line);
        }
    }

    private static String readLine(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while (true) {
            int ch = input.read();
            if (ch < 0) return output.size() == 0 ? null : output.toString("ISO-8859-1");
            if (ch == '\n') break;
            if (ch != '\r') output.write(ch);
            if (output.size() > 16384) throw new IOException("HTTP line too long");
        }
        return output.toString("ISO-8859-1");
    }

    private static void writeLine(OutputStream output, String line) throws IOException {
        output.write(line.getBytes(StandardCharsets.ISO_8859_1));
        output.write('\r');
        output.write('\n');
    }

    private static void sendError(OutputStream output, int code, String message) throws IOException {
        byte[] body = (message + "\n").getBytes(StandardCharsets.UTF_8);
        writeLine(output, "HTTP/1.1 " + code + " Bad Request");
        writeLine(output, "Content-Type: text/plain; charset=utf-8");
        writeLine(output, "Content-Length: " + body.length);
        writeLine(output, "Connection: close");
        writeLine(output, "");
        output.write(body);
        output.flush();
    }

    private static int safeInt(String value, int fallback) {
        try { return Integer.parseInt(value); } catch (NumberFormatException e) { return fallback; }
    }

    private static final class HostPort {
        final String host;
        final int port;
        HostPort(String host, int port) { this.host = host; this.port = port; }
        static HostPort parse(String target, int fallbackPort) throws IOException {
            String host = target;
            int port = fallbackPort;
            if (target.startsWith("[")) {
                int end = target.indexOf(']');
                if (end < 0) throw new IOException("Invalid IPv6 CONNECT address");
                host = target.substring(1, end);
                if (target.length() > end + 1 && target.charAt(end + 1) == ':')
                    port = safeInt(target.substring(end + 2), -1);
            } else {
                int colon = target.lastIndexOf(':');
                if (colon > 0) {
                    host = target.substring(0, colon);
                    port = safeInt(target.substring(colon + 1), -1);
                }
            }
            if (host.isEmpty() || port < 1 || port > 65535)
                throw new IOException("Invalid CONNECT destination");
            return new HostPort(host, port);
        }
    }

    @Override public void onDestroy() {
        active = false;
        TrafficStore.proxyRunning = false;
        TrafficStore.changed();
        try { if (server != null) server.close(); } catch (IOException ignored) {}
        for (Socket socket : sockets) {
            try { socket.close(); } catch (IOException ignored) {}
        }
        sockets.clear();
        pool.shutdownNow();
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
