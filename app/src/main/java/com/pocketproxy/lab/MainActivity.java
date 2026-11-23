package com.pocketproxy.lab;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Small dependency-free native UI for the local proxy. */
public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(9, 17, 29);
    private static final int PANEL = Color.rgb(21, 33, 51);
    private static final int FG = Color.rgb(238, 245, 255);
    private static final int MUTED = Color.rgb(162, 177, 197);
    private static final int ACCENT = Color.rgb(57, 193, 159);
    private static final int BLUE = Color.rgb(74, 134, 244);

    private final Handler handler = new Handler(Looper.getMainLooper());
    private long lastRevision = -1;
    private boolean lastRunning = false;
    private String search = "";
    private TextView stateText;
    private TextView countText;
    private LinearLayout historyContainer;
    private Button startButton;
    private Button stopButton;
    private final Set<String> targetScope = new LinkedHashSet<>();
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            refreshUi(false);
            handler.postDelayed(this, 650);
        }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        buildUi();
        if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 100);
        }
    }

    private void buildUi() {
        ScrollView all = new ScrollView(this);
        all.setFillViewport(true);
        all.setBackgroundColor(BG);
        LinearLayout root = column();
        root.setPadding(dp(18), dp(22), dp(18), dp(32));
        all.addView(root);
        setContentView(all);

        TextView title = text("POCKETPROXY", 28, FG, true);
        title.setLetterSpacing(0.08f);
        root.addView(title);
        root.addView(text("Mobile HTTP security lab  •  v1.0", 13, MUTED, false));
        space(root, 20);

        LinearLayout statusCard = card();
        root.addView(statusCard);
        statusCard.addView(text("LOCAL LISTENER", 11, MUTED, true));
        space(statusCard, 8);
        stateText = text("Stopped", 20, FG, true);
        statusCard.addView(stateText);
        space(statusCard, 5);
        TextView endpoint = text("127.0.0.1:8888", 17, ACCENT, true);
        endpoint.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        endpoint.setOnClickListener(v -> copyEndpoint());
        statusCard.addView(endpoint);
        statusCard.addView(text("Tap address to copy • accessible only on this device", 11, MUTED, false));
        space(root, 14);

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        root.addView(controls);
        startButton = actionButton("Start proxy", ACCENT, BG);
        controls.addView(startButton, weightedButton());
        startButton.setOnClickListener(v -> {
            try {
                Intent intent = new Intent(this, ProxyService.class);
                if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
                else startService(intent);
                stateText.setText("Starting…");
            } catch (Exception e) {
                Toast.makeText(this, "Start error: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        });
        stopButton = actionButton("Stop", PANEL, FG);
        LinearLayout.LayoutParams stopParams = weightedButton();
        stopParams.leftMargin = dp(10);
        controls.addView(stopButton, stopParams);
        stopButton.setOnClickListener(v -> {
            stopService(new Intent(this, ProxyService.class));
            refreshUi(true);
        });
        space(root, 10);

        LinearLayout quick = new LinearLayout(this);
        quick.setOrientation(LinearLayout.HORIZONTAL);
        root.addView(quick);
        Button selfTest = actionButton("Run offline test", BLUE, FG);
        quick.addView(selfTest, weightedButton());
        selfTest.setOnClickListener(v -> runSelfTest());
        Button wifi = actionButton("Wi-Fi settings", PANEL, FG);
        LinearLayout.LayoutParams wifiParams = weightedButton();
        wifiParams.leftMargin = dp(10);
        quick.addView(wifi, wifiParams);
        wifi.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_WIFI_SETTINGS)));
        Button decoder = actionButton("Decoder", PANEL, FG);
        LinearLayout.LayoutParams decoderParams = weightedButton();
        decoderParams.leftMargin = dp(10);
        quick.addView(decoder, decoderParams);
        decoder.setOnClickListener(v -> openDecoder());
        space(root, 20);

        LinearLayout how = card();
        root.addView(how);
        how.addView(text("HOW TO USE", 12, ACCENT, true));
        space(how, 8);
        how.addView(text("1. Start the proxy and run the offline test.\n"
                + "2. For Wi-Fi apps that honor system proxy settings: set proxy to Manual, host 127.0.0.1, port 8888.\n"
                + "3. Browse a plain HTTP page; requests appear below.\n"
                + "4. Reset the Wi-Fi proxy to None when finished.", 13, FG, false));
        space(how, 10);
        how.addView(text("HTTPS CONNECT: destination host only; encrypted requests and responses cannot be viewed. "
                + "Apps may ignore Wi-Fi proxies or use certificate pinning.", 12, MUTED, false));
        space(root, 20);

        LinearLayout heading = new LinearLayout(this);
        heading.setOrientation(LinearLayout.HORIZONTAL);
        heading.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(heading);
        heading.addView(text("HTTP HISTORY", 16, FG, true),
                new LinearLayout.LayoutParams(0, dp(32), 1f));
        Button scopeButton = actionButton("Target", PANEL, FG);
        scopeButton.setLayoutParams(new LinearLayout.LayoutParams(dp(72), dp(32)));
        scopeButton.setOnClickListener(v -> openTargetScope());
        heading.addView(scopeButton);
        countText = text("0 entries", 12, MUTED, false);
        countText.setPadding(dp(8), 0, 0, 0);
        heading.addView(countText);
        space(root, 7);

        EditText searchBox = new EditText(this);
        searchBox.setSingleLine(true);
        searchBox.setTextSize(14);
        searchBox.setTextColor(FG);
        searchBox.setHintTextColor(MUTED);
        searchBox.setHint("Filter by host, method or status");
        searchBox.setPadding(dp(14), dp(10), dp(14), dp(10));
        searchBox.setBackground(rounded(PANEL, 12, 0));
        root.addView(searchBox, new LinearLayout.LayoutParams(-1, dp(46)));
        searchBox.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                search = s.toString().toLowerCase(Locale.US).trim();
                refreshUi(true);
            }
            @Override public void afterTextChanged(Editable e) {}
        });
        space(root, 10);
        historyContainer = column();
        root.addView(historyContainer);
        space(root, 12);

        CheckBox previewToggle = new CheckBox(this);
        previewToggle.setText("Capture HTTP body previews (sensitive)");
        previewToggle.setTextSize(12);
        previewToggle.setTextColor(FG);
        previewToggle.setButtonTintList(android.content.res.ColorStateList.valueOf(ACCENT));
        previewToggle.setChecked(TrafficStore.captureBodyPreview);
        previewToggle.setOnCheckedChangeListener((button, checked) -> {
            TrafficStore.captureBodyPreview = checked;
            Toast.makeText(this, checked
                ? "Body preview enabled for new plain HTTP requests only"
                : "Body preview disabled", Toast.LENGTH_SHORT).show();
        });
        root.addView(previewToggle);
        root.addView(text("Body previews may contain private information. Never export or share raw captures.",
                11, MUTED, false));
        space(root, 14);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        root.addView(actions);
        Button export = actionButton("Share safe summary", PANEL, FG);
        actions.addView(export, weightedButton());
        export.setOnClickListener(v -> shareSummary());
        Button intruder = actionButton("Intruder", PANEL, FG);
        LinearLayout.LayoutParams intruderParams = weightedButton();
        intruderParams.leftMargin = dp(10);
        actions.addView(intruder, intruderParams);
        intruder.setOnClickListener(v -> openIntruder(null));
        Button clear = actionButton("Clear history", PANEL, FG);
        LinearLayout.LayoutParams clearParams = weightedButton();
        clearParams.leftMargin = dp(10);
        actions.addView(clear, clearParams);
        clear.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Clear traffic history?")
                .setMessage("All in-memory entries will be removed from this app.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Clear", (dialog, which) -> {
                    TrafficStore.clear();
                    refreshUi(true);
                }).show());
        space(root, 16);
        root.addView(text("For your own devices, test accounts and authorized security assessments only. "
                + "No traffic is saved to disk by this application.", 12, MUTED, false));
        refreshUi(true);
    }

    private void refreshUi(boolean force) {
        if (stateText == null || historyContainer == null) return;
        boolean running = TrafficStore.proxyRunning;
        if (force || running != lastRunning) {
            String message = running ? "● Running" : "○ Stopped";
            if (!running && !TrafficStore.lastError.isEmpty())
                message += "\n" + TrafficStore.lastError;
            stateText.setText(message);
            stateText.setTextColor(running ? ACCENT : FG);
            startButton.setEnabled(!running);
            stopButton.setEnabled(running);
            startButton.setAlpha(running ? 0.5f : 1f);
            stopButton.setAlpha(running ? 1f : 0.5f);
            lastRunning = running;
        }
        long revision = TrafficStore.revision();
        if (!force && lastRevision == revision) return;
        lastRevision = revision;
        List<TrafficStore.Entry> entries = TrafficStore.snapshot();
        countText.setText(entries.size() + " entries");
        historyContainer.removeAllViews();
        int shown = 0;
        for (TrafficStore.Entry entry : entries) {
            String full = (entry.host + " " + entry.url + " " + entry.method + " " + entry.status)
                    .toLowerCase(Locale.US);
            if (!search.isEmpty() && !full.contains(search)) continue;
            if (!targetScope.isEmpty() && !targetScope.contains(entry.host)) continue;
            shown++;
            LinearLayout item = card();
            LinearLayout.LayoutParams itemParams = new LinearLayout.LayoutParams(-1, -2);
            itemParams.bottomMargin = dp(9);
            historyContainer.addView(item, itemParams);
            LinearLayout line = new LinearLayout(this);
            line.setGravity(Gravity.CENTER_VERTICAL);
            item.addView(line);
            TextView method = text(entry.method, 12,
                    "CONNECT".equals(entry.method) ? BLUE : ACCENT, true);
            line.addView(method);
            TextView status = text(entry.status + "  ·  " + entry.timeLabel(), 12, MUTED, false);
            LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(0, -2, 1f);
            statusParams.leftMargin = dp(12);
            line.addView(status, statusParams);
            TextView host = text(entry.host, 16, FG, true);
            host.setSingleLine(true);
            host.setEllipsize(android.text.TextUtils.TruncateAt.END);
            item.addView(host);
            TextView url = text(entry.url, 11, MUTED, false);
            url.setMaxLines(2);
            url.setEllipsize(android.text.TextUtils.TruncateAt.END);
            item.addView(url);
            item.setOnClickListener(v -> {
                AlertDialog.Builder builder = new AlertDialog.Builder(this)
                        .setTitle("Request " + entry.id)
                        .setMessage(entry.detail())
                        .setNeutralButton("Intruder", (dialog, which) -> openIntruder(entry))
                        .setNegativeButton("Close", null);
                if (!"CONNECT".equalsIgnoreCase(entry.method)
                        && entry.url.startsWith("http://")) {
                    builder.setPositiveButton("Repeater", (dialog, which) -> openRepeater(entry));
                }
                builder.show();
            });
        }
        if (shown == 0) {
            TextView empty = text(entries.isEmpty()
                    ? "No traffic yet. Start the proxy and run the offline test."
                    : "No entries match your filter.", 13, MUTED, false);
            empty.setPadding(dp(6), dp(15), dp(6), dp(15));
            historyContainer.addView(empty);
        }
    }

    private void openRepeater(TrafficStore.Entry entry) {
        ScrollView scroll = new ScrollView(this);
        LinearLayout form = column();
        form.setPadding(dp(20), dp(10), dp(20), dp(4));
        scroll.addView(form);

        form.addView(text("Plain HTTP only. Review the target and do not repeat requests to third-party or unauthorized endpoints.",
                12, MUTED, false));
        space(form, 10);

        EditText method = field("Method", entry.method);
        form.addView(method);
        space(form, 8);
        EditText url = field("URL", entry.url);
        form.addView(url);
        space(form, 8);
        String repeaterHeaders = entry.rawRequestHeaders.isEmpty()
                ? entry.requestHeaders : entry.rawRequestHeaders;
        EditText headers = field("Headers (one per line)", repeaterHeaders);
        headers.setMinLines(4);
        form.addView(headers);
        space(form, 8);
        EditText body = field("Request body", entry.requestBody);
        body.setMinLines(3);
        form.addView(body);

        new AlertDialog.Builder(this)
                .setTitle("Request Repeater")
                .setView(scroll)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Send", (dialog, which) ->
                        repeatRequest(method.getText().toString().trim().toUpperCase(Locale.US),
                                url.getText().toString().trim(),
                                headers.getText().toString(),
                                body.getText().toString()))
                .show();
    }

    private void openTargetScope() {
        StringBuilder message = new StringBuilder();
        if (targetScope.isEmpty()) {
            message.append("No target hosts are in scope.\n\nWhen scope is empty, all captured hosts are shown.");
        } else {
            message.append("In-scope hosts:\n");
            for (String host : targetScope) message.append("• ").append(host).append('\n');
        }
        EditText hostField = field("Add host (for example, example.com)", "");
        LinearLayout form = column();
        form.setPadding(dp(20), dp(10), dp(20), dp(4));
        form.addView(text(message.toString(), 13, FG, false));
        space(form, 10);
        form.addView(hostField);
        new AlertDialog.Builder(this)
                .setTitle("Target Scope")
                .setView(form)
                .setNegativeButton("Close", null)
                .setNeutralButton(targetScope.isEmpty() ? null : "Clear scope",
                        targetScope.isEmpty() ? null : (dialog, which) -> {
                            targetScope.clear();
                            refreshUi(true);
                        })
                .setPositiveButton("Add host", (dialog, which) -> {
                    String host = hostField.getText().toString().trim().toLowerCase(Locale.US);
                    if (host.isEmpty()) return;
                    targetScope.add(host);
                    refreshUi(true);
                    Toast.makeText(this, "Target scope added: " + host, Toast.LENGTH_SHORT).show();
                })
                .show();
    }

    private void openIntruder(TrafficStore.Entry entry) {
        ScrollView scroll = new ScrollView(this);
        LinearLayout form = column();
        form.setPadding(dp(20), dp(10), dp(20), dp(4));
        scroll.addView(form);
        form.addView(text("Use §payload§ in the URL, headers or body. The run is capped at 20 requests.",
                12, MUTED, false));
        space(form, 10);

        EditText method = field("Method", entry == null ? "GET" : entry.method);
        form.addView(method);
        space(form, 8);
        EditText url = field("URL template", entry == null ? "http://example.test/§payload§" : entry.url);
        form.addView(url);
        space(form, 8);
        EditText headers = field("Headers (one per line)", entry == null
                ? "Accept: */*" : entry.rawRequestHeaders);
        headers.setMinLines(3);
        form.addView(headers);
        space(form, 8);
        EditText body = field("Body template", entry == null ? "" : entry.requestBody);
        body.setMinLines(2);
        form.addView(body);
        space(form, 8);
        EditText payloads = field("Payloads (one per line)", "test1\ntest2\ntest3");
        payloads.setMinLines(4);
        form.addView(payloads);

        new AlertDialog.Builder(this)
                .setTitle("Intruder")
                .setView(scroll)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Run", (dialog, which) -> runIntruder(
                        method.getText().toString().trim().toUpperCase(Locale.US),
                        url.getText().toString().trim(),
                        headers.getText().toString(),
                        body.getText().toString(),
                        payloads.getText().toString()))
                .show();
    }

    private void runIntruder(String method, String templateUrl, String templateHeaders,
                             String templateBody, String payloadText) {
        List<String> payloadList = new java.util.ArrayList<>();
        for (String payload : payloadText.split("\\r?\\n")) {
            String value = payload.trim();
            if (!value.isEmpty()) payloadList.add(value);
            if (payloadList.size() == 20) break;
        }
        if (payloadList.isEmpty()) {
            Toast.makeText(this, "Add at least one payload", Toast.LENGTH_SHORT).show();
            return;
        }
        Toast.makeText(this, "Running " + payloadList.size() + " payload(s)", Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            StringBuilder results = new StringBuilder();
            results.append("Intruder results (plain HTTP only)\n");
            for (int i = 0; i < payloadList.size(); i++) {
                String payload = payloadList.get(i);
                String url = templateUrl.replace("§payload§", payload);
                String headers = templateHeaders.replace("§payload§", payload);
                String body = templateBody.replace("§payload§", payload);
                try {
                    URI uri = new URI(url);
                    if (!"http".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
                        results.append(i + 1).append(". FAILED invalid HTTP URL\n");
                        continue;
                    }
                    int port = uri.getPort() > 0 ? uri.getPort() : 80;
                    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
                    String path = uri.getRawPath();
                    if (path == null || path.isEmpty()) path = "/";
                    if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
                    StringBuilder request = new StringBuilder();
                    request.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
                    boolean hasHost = false;
                    boolean hasLength = false;
                    for (String line : headers.split("\\r?\\n")) {
                        line = line.trim();
                        if (line.isEmpty() || line.indexOf(':') <= 0) continue;
                        int colon = line.indexOf(':');
                        String name = line.substring(0, colon).trim();
                        String lower = name.toLowerCase(Locale.US);
                        if ("host".equals(lower)) hasHost = true;
                        if ("content-length".equals(lower)) hasLength = true;
                        if ("connection".equals(lower) || "transfer-encoding".equals(lower)
                                || "proxy-connection".equals(lower)) continue;
                        request.append(name).append(": ").append(line.substring(colon + 1).trim()).append("\r\n");
                    }
                    if (!hasHost) {
                        request.append("Host: ").append(uri.getHost());
                        if (port != 80) request.append(":").append(port);
                        request.append("\r\n");
                    }
                    if (!body.isEmpty() && !hasLength)
                        request.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
                    request.append("Connection: close\r\n\r\n");

                    try (Socket socket = new Socket(uri.getHost(), port);
                         OutputStream out = socket.getOutputStream();
                         BufferedReader reader = new BufferedReader(new InputStreamReader(
                                 socket.getInputStream(), StandardCharsets.ISO_8859_1))) {
                        socket.setSoTimeout(10000);
                        out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
                        if (!body.isEmpty()) out.write(bodyBytes);
                        out.flush();
                        String status = reader.readLine();
                        results.append(i + 1).append(". ")
                                .append(payload).append(" → ")
                                .append(status == null ? "NO RESPONSE" : status)
                                .append('\n');
                    }
                } catch (Exception e) {
                    results.append(i + 1).append(". ").append(payload)
                            .append(" → ERROR: ").append(e.getClass().getSimpleName())
                            .append('\n');
                }
            }
            runOnUiThread(() -> new AlertDialog.Builder(this)
                    .setTitle("Intruder Results")
                    .setMessage(results.toString())
                    .setNegativeButton("Close", null)
                    .setPositiveButton("Copy", (dialog, which) -> {
                        ClipboardManager manager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                        manager.setPrimaryClip(ClipData.newPlainText("intruder results", results.toString()));
                        Toast.makeText(this, "Results copied", Toast.LENGTH_SHORT).show();
                    })
                    .show());
        }, "PocketProxy-Intruder").start();
    }

    private EditText field(String hint, String value) {
        EditText field = new EditText(this);
        field.setHint(hint);
        field.setText(value);
        field.setTextSize(13);
        field.setTextColor(FG);
        field.setHintTextColor(MUTED);
        field.setPadding(dp(12), dp(10), dp(12), dp(10));
        field.setBackground(rounded(PANEL, 10, 0));
        return field;
    }

    private void repeatRequest(String method, String url, String headersText, String bodyText) {
        if (method.isEmpty()) {
            Toast.makeText(this, "Method is required", Toast.LENGTH_SHORT).show();
            return;
        }
        new Thread(() -> {
            String result;
            try {
                URI uri = new URI(url);
                if (!"http".equalsIgnoreCase(uri.getScheme())
                        || uri.getHost() == null || uri.getHost().isEmpty()) {
                    throw new IllegalArgumentException("Repeater accepts http:// URLs only");
                }
                int port = uri.getPort() > 0 ? uri.getPort() : 80;
                byte[] body = bodyText.getBytes(StandardCharsets.UTF_8);
                String path = uri.getRawPath();
                if (path == null || path.isEmpty()) path = "/";
                if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();

                StringBuilder request = new StringBuilder();
                request.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
                boolean hasHost = false;
                boolean hasContentLength = false;
                for (String line : headersText.split("\\r?\\n")) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    int colon = line.indexOf(':');
                    if (colon <= 0) continue;
                    String name = line.substring(0, colon).trim();
                    String lower = name.toLowerCase(Locale.US);
                    if ("host".equals(lower)) hasHost = true;
                    if ("content-length".equals(lower)) hasContentLength = true;
                    if ("connection".equals(lower) || "proxy-connection".equals(lower)
                            || "transfer-encoding".equals(lower) || "upgrade".equals(lower)) continue;
                    request.append(name).append(": ").append(line.substring(colon + 1).trim()).append("\r\n");
                }
                if (!hasHost) {
                    request.append("Host: ").append(uri.getHost());
                    if (port != 80) request.append(":").append(port);
                    request.append("\r\n");
                }
                if (!bodyText.isEmpty() && !hasContentLength) {
                    request.append("Content-Length: ").append(body.length).append("\r\n");
                }
                request.append("Connection: close\r\n\r\n");

                try (Socket socket = new Socket(uri.getHost(), port);
                     BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream());
                     BufferedInputStream in = new BufferedInputStream(socket.getInputStream())) {
                    socket.setSoTimeout(15000);
                    out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
                    if (!bodyText.isEmpty()) out.write(body);
                    out.flush();

                    BufferedReader reader = new BufferedReader(new InputStreamReader(
                            in, StandardCharsets.ISO_8859_1));
                    String status = reader.readLine();
                    if (status == null) throw new IllegalStateException("No response received");
                    StringBuilder response = new StringBuilder();
                    response.append(status).append('\n');
                    int contentLength = -1;
                    String line;
                    while ((line = reader.readLine()) != null && !line.isEmpty()) {
                        response.append(line).append('\n');
                        int colon = line.indexOf(':');
                        if (colon > 0 && "content-length".equalsIgnoreCase(line.substring(0, colon).trim())) {
                            try {
                                contentLength = Integer.parseInt(line.substring(colon + 1).trim());
                            } catch (NumberFormatException ignored) {}
                        }
                    }
                    response.append('\n');

                    if (contentLength >= 0) {
                        int remaining = Math.min(contentLength, 65536);
                        char[] buffer = new char[remaining];
                        int total = 0;
                        while (total < remaining) {
                            int read = reader.read(buffer, total, remaining - total);
                            if (read < 0) break;
                            total += read;
                        }
                        response.append(buffer, 0, total);
                        if (contentLength > 65536) response.append("\n[body truncated to 64 KB]");
                    } else {
                        char[] buffer = new char[4096];
                        int read;
                        int total = 0;
                        while (total < 65536 && (read = reader.read(buffer, 0,
                                Math.min(buffer.length, 65536 - total))) >= 0) {
                            response.append(buffer, 0, read);
                            total += read;
                        }
                        if (total == 65536) response.append("\n[body truncated to 64 KB]");
                    }
                    result = response.toString();
                }
            } catch (Exception e) {
                result = "Repeat failed: " + e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            String responseText = result;
            runOnUiThread(() -> new AlertDialog.Builder(this)
                    .setTitle("Repeater Response")
                    .setMessage(responseText)
                    .setNeutralButton("Copy", (dialog, which) -> {
                        ClipboardManager manager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                        manager.setPrimaryClip(ClipData.newPlainText("repeater response", responseText));
                        Toast.makeText(this, "Response copied", Toast.LENGTH_SHORT).show();
                    })
                    .setPositiveButton("Close", null)
                    .show());
        }, "PocketProxy-Repeater").start();
    }

    private void openDecoder() {
        String[] operations = {
                "Base64 decode", "Base64 encode",
                "URL decode", "URL encode",
                "Hex decode", "Hex encode"
        };
        new AlertDialog.Builder(this)
                .setTitle("Choose decoder")
                .setItems(operations, (dialog, which) -> openDecoderForm(operations[which]))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void openDecoderForm(String operation) {
        ScrollView scroll = new ScrollView(this);
        LinearLayout form = column();
        form.setPadding(dp(20), dp(10), dp(20), dp(4));
        scroll.addView(form);
        EditText input = field("Text to transform", "");
        input.setMinLines(4);
        form.addView(input);
        space(form, 8);
        TextView output = text("Result appears here", 13, FG, false);
        output.setTypeface(Typeface.MONOSPACE, Typeface.NORMAL);
        output.setPadding(dp(12), dp(10), dp(12), dp(10));
        output.setBackground(rounded(PANEL, 10, 0));
        form.addView(output);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(operation)
                .setView(scroll)
                .setNegativeButton("Close", null)
                .setNeutralButton("Copy", null)
                .setPositiveButton("Transform", null)
                .create();
        dialog.setOnShowListener(d -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v ->
                    output.setText(transform(operation, input.getText().toString())));
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                String value = output.getText().toString();
                if ("Result appears here".equals(value)) return;
                ClipboardManager manager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                manager.setPrimaryClip(ClipData.newPlainText(operation, value));
                Toast.makeText(this, "Result copied", Toast.LENGTH_SHORT).show();
            });
        });
        dialog.show();
    }

    private String transform(String operation, String input) {
        try {
            if ("Base64 decode".equals(operation)) {
                return new String(Base64.decode(input.trim(), Base64.DEFAULT), StandardCharsets.UTF_8);
            }
            if ("Base64 encode".equals(operation)) {
                return Base64.encodeToString(input.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
            }
            if ("URL decode".equals(operation)) {
                return java.net.URLDecoder.decode(input, "UTF-8");
            }
            if ("URL encode".equals(operation)) {
                return java.net.URLEncoder.encode(input, "UTF-8");
            }
            if ("Hex decode".equals(operation)) {
                String hex = input.replaceAll("\\s+", "").replaceFirst("^0x", "");
                if (hex.length() % 2 != 0) throw new IllegalArgumentException("Hex length must be even");
                byte[] bytes = new byte[hex.length() / 2];
                for (int i = 0; i < bytes.length; i++) {
                    int high = Character.digit(hex.charAt(i * 2), 16);
                    int low = Character.digit(hex.charAt(i * 2 + 1), 16);
                    if (high < 0 || low < 0) throw new IllegalArgumentException("Invalid hexadecimal character");
                    bytes[i] = (byte) ((high << 4) + low);
                }
                return new String(bytes, StandardCharsets.UTF_8);
            }
            if ("Hex encode".equals(operation)) {
                byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
                StringBuilder hex = new StringBuilder(bytes.length * 2);
                char[] digits = "0123456789abcdef".toCharArray();
                for (byte value : bytes) {
                    int unsigned = value & 0xff;
                    hex.append(digits[unsigned >>> 4]).append(digits[unsigned & 0xf]);
                }
                return hex.toString();
            }
            return "Unsupported operation";
        } catch (Exception e) {
            return "Transform failed: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    private void runSelfTest() {
        if (!TrafficStore.proxyRunning) {
            Toast.makeText(this, "Start the proxy first", Toast.LENGTH_SHORT).show();
            return;
        }
        new Thread(() -> {
            String result;
            try (Socket socket = new Socket("127.0.0.1", ProxyService.PORT)) {
                socket.setSoTimeout(5000);
                OutputStream out = socket.getOutputStream();
                out.write(("GET http://pocketproxy.test/ HTTP/1.1\r\n"
                        + "Host: pocketproxy.test\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                BufferedReader response = new BufferedReader(new InputStreamReader(
                        socket.getInputStream(), StandardCharsets.ISO_8859_1));
                String firstLine = response.readLine();
                result = firstLine != null && firstLine.contains(" 200 ")
                        ? "Test passed — HTTP 200 in history"
                        : "Unexpected test response: " + firstLine;
            } catch (Exception e) {
                result = "Test failed: " + e.getMessage();
            }
            String message = result;
            runOnUiThread(() -> {
                Toast.makeText(this, message, Toast.LENGTH_LONG).show();
                refreshUi(true);
            });
        }, "PocketProxy-SelfTest").start();
    }

    private void shareSummary() {
        Intent share = new Intent(Intent.ACTION_SEND);
        share.setType("text/plain");
        share.putExtra(Intent.EXTRA_SUBJECT, "PocketProxy Lab sanitized history");
        share.putExtra(Intent.EXTRA_TEXT, TrafficStore.exportSummary());
        startActivity(Intent.createChooser(share, "Share sanitized request summary"));
    }

    private void copyEndpoint() {
        ClipboardManager manager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        manager.setPrimaryClip(ClipData.newPlainText("proxy", "127.0.0.1:8888"));
        Toast.makeText(this, "Proxy address copied", Toast.LENGTH_SHORT).show();
    }

    @Override protected void onResume() {
        super.onResume();
        handler.removeCallbacks(refresh);
        handler.post(refresh);
    }

    @Override protected void onPause() {
        handler.removeCallbacks(refresh);
        super.onPause();
    }

    private LinearLayout card() {
        LinearLayout layout = column();
        layout.setPadding(dp(15), dp(14), dp(15), dp(14));
        layout.setBackground(rounded(PANEL, 14, Color.rgb(35, 50, 70)));
        return layout;
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private GradientDrawable rounded(int fill, int radius, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radius));
        if (stroke != 0) drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private TextView text(String content, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(content);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setLineSpacing(dp(2), 1.0f);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private Button actionButton(String title, int background, int foreground) {
        Button button = new Button(this);
        button.setText(title);
        button.setAllCaps(false);
        button.setTextSize(12);
        button.setTextColor(foreground);
        button.setBackground(rounded(background, 12, 0));
        return button;
    }

    private LinearLayout.LayoutParams weightedButton() {
        return new LinearLayout.LayoutParams(0, dp(44), 1f);
    }

    private void space(LinearLayout layout, int height) {
        View spacer = new View(this);
        layout.addView(spacer, new LinearLayout.LayoutParams(1, dp(height)));
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }
}
