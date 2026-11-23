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
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.GZIPInputStream;

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
    private String methodFilter = "All methods";
    private String statusFilter = "Any status";
    private TextView stateText;
    private TextView countText;
    private LinearLayout historyContainer;
    private LinearLayout interceptContainer;
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

        CheckBox interceptToggle = new CheckBox(this);
        interceptToggle.setText("Intercept plain HTTP requests");
        interceptToggle.setTextSize(14);
        interceptToggle.setTextColor(FG);
        interceptToggle.setButtonTintList(android.content.res.ColorStateList.valueOf(ACCENT));
        interceptToggle.setChecked(InterceptStore.enabled);
        interceptToggle.setOnCheckedChangeListener((button, checked) -> {
            InterceptStore.enabled = checked;
            if (!checked) InterceptStore.passPending();
            TrafficStore.changed();
            Toast.makeText(this, checked
                    ? "Intercept enabled: matching requests will pause for review"
                    : "Intercept disabled; pending requests are being forwarded",
                    Toast.LENGTH_SHORT).show();
        });
        root.addView(interceptToggle);
        root.addView(text("Pauses bodyless or Content-Length requests up to 64 KB. Chunked, larger, and HTTPS traffic passes through.",
                11, MUTED, false));
        interceptContainer = column();
        root.addView(interceptContainer);
        space(root, 14);

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
        searchBox.setHint("Search host, URL, headers or captured body");
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
        space(root, 8);
        LinearLayout filters = new LinearLayout(this);
        filters.setOrientation(LinearLayout.HORIZONTAL);
        root.addView(filters);
        Spinner methods = filterSpinner(
                new String[]{"All methods", "GET", "POST", "PUT", "DELETE", "PATCH", "CONNECT"});
        filters.addView(methods, new LinearLayout.LayoutParams(0, dp(44), 1f));
        methods.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(android.widget.AdapterView<?> parent, View view,
                                                 int position, long id) {
                methodFilter = methods.getSelectedItem().toString();
                refreshUi(true);
            }
            @Override public void onNothingSelected(android.widget.AdapterView<?> parent) {}
        });
        Spinner statuses = filterSpinner(
                new String[]{"Any status", "2xx", "3xx", "4xx", "5xx", "Errors", "Tunnels"});
        LinearLayout.LayoutParams statusFilterParams = new LinearLayout.LayoutParams(0, dp(44), 1f);
        statusFilterParams.leftMargin = dp(8);
        filters.addView(statuses, statusFilterParams);
        statuses.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(android.widget.AdapterView<?> parent, View view,
                                                 int position, long id) {
                statusFilter = statuses.getSelectedItem().toString();
                refreshUi(true);
            }
            @Override public void onNothingSelected(android.widget.AdapterView<?> parent) {}
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
        LinearLayout additionalActions = new LinearLayout(this);
        additionalActions.setOrientation(LinearLayout.HORIZONTAL);
        root.addView(additionalActions);
        Button compare = actionButton("Compare requests", PANEL, FG);
        additionalActions.addView(compare, weightedButton());
        compare.setOnClickListener(v -> chooseComparison());
        Button report = actionButton("Export test report", PANEL, FG);
        LinearLayout.LayoutParams reportParams = weightedButton();
        reportParams.leftMargin = dp(10);
        additionalActions.addView(report, reportParams);
        report.setOnClickListener(v -> shareTestReport());
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
        renderInterceptQueue();
        List<TrafficStore.Entry> entries = TrafficStore.snapshot();
        historyContainer.removeAllViews();
        int shown = 0;
        for (TrafficStore.Entry entry : entries) {
            String full = (entry.host + " " + entry.url + " " + entry.method + " " + entry.status
                    + " " + entry.requestHeaders + " " + entry.responseHeaders + " "
                    + entry.requestBody + " " + entry.responseBody).toLowerCase(Locale.US);
            if (!search.isEmpty() && !full.contains(search)) continue;
            if (!"All methods".equals(methodFilter) && !entry.method.equalsIgnoreCase(methodFilter)) continue;
            if (!matchesStatusFilter(entry.status)) continue;
            if (!targetScope.isEmpty() && !isEntryInTargetScope(entry)) continue;
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
        countText.setText(shown + " / " + entries.size() + " entries");
    }

    private boolean matchesStatusFilter(String status) {
        if ("Any status".equals(statusFilter)) return true;
        if ("Tunnels".equals(statusFilter)) return "TUNNEL".equalsIgnoreCase(status);
        if ("Errors".equals(statusFilter)) {
            return "ERROR".equalsIgnoreCase(status) || "DROPPED".equalsIgnoreCase(status)
                    || status.toUpperCase(Locale.US).contains("ERROR");
        }
        if (status.length() < 3 || !Character.isDigit(status.charAt(0))
                || statusFilter.isEmpty()) return false;
        return status.charAt(0) == statusFilter.charAt(0);
    }

    private Spinner filterSpinner(String[] options) {
        Spinner spinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, options);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        spinner.setBackground(rounded(PANEL, 10, 0));
        return spinner;
    }

    private void renderInterceptQueue() {
        interceptContainer.removeAllViews();
        List<InterceptStore.PendingRequest> requests = InterceptStore.snapshot();
        if (requests.isEmpty()) return;
        TextView heading = text("PAUSED REQUESTS (" + requests.size() + ")", 12, ACCENT, true);
        interceptContainer.addView(heading);
        for (InterceptStore.PendingRequest request : requests) {
            LinearLayout item = card();
            LinearLayout.LayoutParams itemParams = new LinearLayout.LayoutParams(-1, -2);
            itemParams.topMargin = dp(8);
            interceptContainer.addView(item, itemParams);
            item.addView(text(request.method + "  " + request.url, 13, FG, true));
            item.addView(text("Headers and body may include sensitive values.", 11, MUTED, false));
            LinearLayout buttons = new LinearLayout(this);
            buttons.setOrientation(LinearLayout.HORIZONTAL);
            item.addView(buttons);
            Button forward = actionButton("Forward", ACCENT, BG);
            buttons.addView(forward, weightedButton());
            forward.setOnClickListener(v -> InterceptStore.forward(
                    request, request.method, request.url, request.headers, request.body));
            Button edit = actionButton("Edit", PANEL, FG);
            LinearLayout.LayoutParams editParams = weightedButton();
            editParams.leftMargin = dp(6);
            buttons.addView(edit, editParams);
            edit.setOnClickListener(v -> editInterceptedRequest(request));
            Button drop = actionButton("Drop", PANEL, FG);
            LinearLayout.LayoutParams dropParams = weightedButton();
            dropParams.leftMargin = dp(6);
            buttons.addView(drop, dropParams);
            drop.setOnClickListener(v -> InterceptStore.drop(request));
        }
    }

    private void editInterceptedRequest(InterceptStore.PendingRequest request) {
        ScrollView scroll = new ScrollView(this);
        LinearLayout form = column();
        form.setPadding(dp(20), dp(10), dp(20), dp(4));
        scroll.addView(form);
        form.addView(text("Editing a paused request can change its destination. Only forward traffic to systems you are authorized to test.",
                12, MUTED, false));
        space(form, 10);
        EditText method = field("Method", request.method);
        form.addView(method);
        space(form, 8);
        EditText url = field("HTTP URL", request.url);
        form.addView(url);
        space(form, 8);
        EditText headers = field("Headers (one per line)", request.headers);
        headers.setMinLines(4);
        form.addView(headers);
        space(form, 8);
        EditText body = field("Body (UTF-8 text)", request.body);
        body.setMinLines(4);
        form.addView(body);
        new AlertDialog.Builder(this)
                .setTitle("Edit intercepted request")
                .setView(scroll)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Forward", (dialog, which) -> {
                    String updatedMethod = method.getText().toString().trim().toUpperCase(Locale.US);
                    String updatedUrl = url.getText().toString().trim();
                    if (updatedMethod.isEmpty() || !updatedUrl.startsWith("http://")) {
                        Toast.makeText(this, "Enter a method and a valid plain HTTP URL",
                                Toast.LENGTH_LONG).show();
                        return;
                    }
                    InterceptStore.forward(request, updatedMethod, updatedUrl,
                            headers.getText().toString(), body.getText().toString());
                })
                .setNeutralButton("Drop", (dialog, which) -> InterceptStore.drop(request))
                .show();
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
            message.append("No targets are in scope. Repeater and Intruder stay disabled until a host is added.\n\nA host entry includes its subdomains on the selected HTTP port; a host without a port means port 80.");
        } else {
            message.append("In-scope hosts:\n");
            for (String host : targetScope) message.append("• ").append(host).append('\n');
        }
        EditText hostField = field("Authorized host (example.com or example.com:8080)", "");
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
                    String host;
                    try {
                        host = normalizeScopeEntry(hostField.getText().toString());
                    } catch (IllegalArgumentException e) {
                        Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                        return;
                    }
                    if (host.isEmpty()) return;
                    targetScope.add(host);
                    refreshUi(true);
                    Toast.makeText(this, "Target scope added: " + host, Toast.LENGTH_SHORT).show();
                })
                .show();
    }

    private String normalizeScopeHost(String value) {
        String host = value.trim().toLowerCase(Locale.US);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty() || host.contains("/") || host.contains(":")
                || host.contains("@") || host.contains("?") || host.contains("#")
                || host.contains(" ")) {
            throw new IllegalArgumentException("Enter a hostname only, without scheme, path, or port");
        }
        try {
            host = IDN.toASCII(host);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Enter a valid hostname");
        }
        if (host.length() > 253 || host.contains("..")) {
            throw new IllegalArgumentException("Enter a valid hostname");
        }
        for (String label : host.split("\\.")) {
            if (label.isEmpty() || label.length() > 63
                    || !label.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) {
                throw new IllegalArgumentException("Enter a valid hostname");
            }
        }
        return host;
    }

    private String normalizeScopeEntry(String value) {
        String input = value.trim();
        int colon = input.lastIndexOf(':');
        String host = input;
        int port = 80;
        if (colon >= 0) {
            if (input.indexOf(':') != colon) {
                throw new IllegalArgumentException("IPv6 scope entries are not supported");
            }
            host = input.substring(0, colon);
            try {
                port = Integer.parseInt(input.substring(colon + 1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Enter a port from 1 to 65535");
            }
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Enter a port from 1 to 65535");
            }
        }
        return normalizeScopeHost(host) + ":" + port;
    }

    private boolean isTargetInScope(URI target, Set<String> scope) {
        if (target.getHost() == null) return false;
        String host;
        try {
            host = normalizeScopeHost(target.getHost());
        } catch (IllegalArgumentException e) {
            return false;
        }
        int port = target.getPort() > 0 ? target.getPort() : 80;
        if (target.getPort() == 0 || port > 65535) return false;
        for (String scopeEntry : scope) {
            int colon = scopeEntry.lastIndexOf(':');
            if (colon <= 0) continue;
            String allowedHost = scopeEntry.substring(0, colon);
            int allowedPort;
            try { allowedPort = Integer.parseInt(scopeEntry.substring(colon + 1)); }
            catch (NumberFormatException e) { continue; }
            if (port == allowedPort
                    && (host.equals(allowedHost) || host.endsWith("." + allowedHost))) return true;
        }
        return false;
    }

    private boolean isEntryInTargetScope(TrafficStore.Entry entry) {
        try {
            return isTargetInScope(new URI(entry.url), targetScope);
        } catch (Exception e) {
            return false;
        }
    }

    private void openIntruder(TrafficStore.Entry entry) {
        if (targetScope.isEmpty()) {
            Toast.makeText(this, "Add an authorized host to Target scope first",
                    Toast.LENGTH_LONG).show();
            return;
        }
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
        String scopeTarget = targetScope.iterator().next();
        String defaultTargetUrl = "http://" + scopeTarget + "/§payload§";
        EditText url = field("URL template", entry == null ? defaultTargetUrl : entry.url);
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
        Set<String> allowedHosts = new LinkedHashSet<>(targetScope);
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
                    if (!"http".equalsIgnoreCase(uri.getScheme())
                            || !isTargetInScope(uri, allowedHosts)) {
                        results.append(i + 1).append(". SKIPPED: host is not in Target scope\n");
                        continue;
                    }
                    int port = uri.getPort() > 0 ? uri.getPort() : 80;
                    if (port > 65535) throw new IllegalArgumentException("Invalid target port");
                    if (!method.matches("[A-Z][A-Z0-9-]*"))
                        throw new IllegalArgumentException("Invalid HTTP method");
                    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
                    if (bodyBytes.length > 65536)
                        throw new IllegalArgumentException("Request body exceeds 64 KB");
                    String path = uri.getRawPath();
                    if (path == null || path.isEmpty()) path = "/";
                    if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
                    StringBuilder request = new StringBuilder();
                    request.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
                    for (String line : headers.split("\\r?\\n")) {
                        line = line.trim();
                        if (line.isEmpty() || line.indexOf(':') <= 0) continue;
                        int colon = line.indexOf(':');
                        String name = line.substring(0, colon).trim();
                        String lower = name.toLowerCase(Locale.US);
                        if (!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))
                            throw new IllegalArgumentException("Invalid header name");
                        if ("host".equals(lower) || "content-length".equals(lower)) continue;
                        if ("connection".equals(lower) || "transfer-encoding".equals(lower)
                                || "proxy-connection".equals(lower) || "expect".equals(lower)
                                || "te".equals(lower) || "keep-alive".equals(lower)) continue;
                        String value = line.substring(colon + 1).trim();
                        for (int j = 0; j < value.length(); j++) {
                            char ch = value.charAt(j);
                            if ((ch < 0x20 && ch != '\t') || ch == 0x7f)
                                throw new IllegalArgumentException("Invalid header value");
                        }
                        request.append(name).append(": ").append(value).append("\r\n");
                    }
                    request.append("Host: ").append(uri.getHost());
                    if (port != 80) request.append(":").append(port);
                    request.append("\r\n");
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
        if (targetScope.isEmpty()) {
            Toast.makeText(this, "Add an authorized host to Target scope before sending",
                    Toast.LENGTH_LONG).show();
            return;
        }
        try {
            URI target = new URI(url);
            if (!"http".equalsIgnoreCase(target.getScheme())
                    || !isTargetInScope(target, targetScope)) {
                Toast.makeText(this, "Repeater target must be an in-scope plain HTTP host",
                        Toast.LENGTH_LONG).show();
                return;
            }
        } catch (Exception e) {
            Toast.makeText(this, "Enter a valid plain HTTP URL", Toast.LENGTH_SHORT).show();
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
                if (!method.matches("[A-Z][A-Z0-9-]*")) {
                    throw new IllegalArgumentException("Invalid HTTP method");
                }
                int port = uri.getPort() > 0 ? uri.getPort() : 80;
                byte[] body = bodyText.getBytes(StandardCharsets.UTF_8);
                String path = uri.getRawPath();
                if (path == null || path.isEmpty()) path = "/";
                if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();

                StringBuilder request = new StringBuilder();
                request.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
                for (String line : headersText.split("\\r?\\n")) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    int colon = line.indexOf(':');
                    if (colon <= 0) continue;
                    String name = line.substring(0, colon).trim();
                    String lower = name.toLowerCase(Locale.US);
                    if (!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))
                        throw new IllegalArgumentException("Invalid header name");
                    if ("host".equals(lower) || "content-length".equals(lower)) continue;
                    if ("connection".equals(lower) || "proxy-connection".equals(lower)
                            || "transfer-encoding".equals(lower) || "upgrade".equals(lower)
                            || "expect".equals(lower) || "te".equals(lower)
                            || "keep-alive".equals(lower)) continue;
                    String value = line.substring(colon + 1).trim();
                    for (int i = 0; i < value.length(); i++) {
                        char ch = value.charAt(i);
                        if ((ch < 0x20 && ch != '\t') || ch == 0x7f)
                            throw new IllegalArgumentException("Invalid header value");
                    }
                    request.append(name).append(": ").append(value).append("\r\n");
                }
                request.append("Host: ").append(uri.getHost());
                if (port != 80) request.append(":").append(port);
                request.append("\r\n");
                request.append("Content-Length: ").append(body.length).append("\r\n");
                request.append("Connection: close\r\n\r\n");

                try (Socket socket = new Socket(uri.getHost(), port);
                     BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream());
                     BufferedInputStream in = new BufferedInputStream(socket.getInputStream())) {
                    socket.setSoTimeout(15000);
                    out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
                    if (!bodyText.isEmpty()) out.write(body);
                    out.flush();

                    result = readRepeaterResponse(in, method);
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

    private String readRepeaterResponse(BufferedInputStream input, String method) throws IOException {
        StringBuilder interimResponses = new StringBuilder();
        String statusLine;
        List<String> headers;
        int statusCode;
        while (true) {
            statusLine = readHttpLine(input);
            if (statusLine == null) throw new IOException("Server closed without a response");
            headers = new ArrayList<>();
            String line = readHttpLine(input);
            if (line == null) throw new IOException("Incomplete response headers");
            int headerBytes = 0;
            while (!line.isEmpty()) {
                headerBytes += line.length();
                if (headerBytes > 65536 || headers.size() >= 100)
                    throw new IOException("Response headers exceed safety limit");
                headers.add(line);
                line = readHttpLine(input);
                if (line == null) throw new IOException("Incomplete response headers");
            }
            statusCode = parseStatusCode(statusLine);
            if (statusCode < 100 || statusCode >= 200 || statusCode == 101) break;
            interimResponses.append(statusLine).append('\n');
            for (String header : headers) interimResponses.append(header).append('\n');
            interimResponses.append('\n');
        }

        StringBuilder response = new StringBuilder(interimResponses)
                .append(statusLine).append('\n');
        for (String header : headers) response.append(header).append('\n');
        response.append('\n');

        byte[] body = new byte[0];
        boolean truncated = false;
        if (!"HEAD".equals(method) && statusCode != 204 && statusCode != 304
                && (statusCode < 100 || statusCode >= 200)) {
            String transferEncoding = responseHeader(headers, "transfer-encoding");
            String lengthHeader = responseHeader(headers, "content-length");
            if (transferEncoding != null && transferEncoding.toLowerCase(Locale.US).contains("chunked")) {
                BodyRead result = readChunkedBody(input, 65536);
                body = result.bytes;
                truncated = result.truncated;
                if (body.length > 65536) body = java.util.Arrays.copyOf(body, 65536);
            } else if (lengthHeader != null) {
                long length;
                try { length = Long.parseLong(lengthHeader.trim()); }
                catch (NumberFormatException e) { throw new IOException("Invalid response Content-Length"); }
                if (length < 0) throw new IOException("Negative response Content-Length");
                long bytesToRead = Math.min(length, 65537);
                BodyRead result = readBody(input, bytesToRead);
                if (result.bytes.length < bytesToRead)
                    throw new IOException("Response ended before Content-Length bytes arrived");
                body = result.bytes;
                truncated = length > 65536 || result.bytes.length > 65536;
                if (body.length > 65536) body = java.util.Arrays.copyOf(body, 65536);
            } else {
                BodyRead result = readBody(input, 65537);
                body = result.bytes;
                truncated = body.length > 65536;
                if (truncated) body = java.util.Arrays.copyOf(body, 65536);
            }
        }

        String contentEncoding = responseHeader(headers, "content-encoding");
        if (body.length > 0 && !truncated && contentEncoding != null
                && contentEncoding.toLowerCase(Locale.US).contains("gzip")) {
            try {
                BodyRead decoded = readBody(new GZIPInputStream(new ByteArrayInputStream(body)), 65537);
                body = decoded.bytes;
                truncated = body.length > 65536;
                if (truncated) body = java.util.Arrays.copyOf(body, 65536);
                response.append("[gzip response decoded]\n");
            } catch (IOException e) {
                response.append("[gzip decode failed: ").append(e.getMessage()).append("]\n");
            }
        }
        String contentType = responseHeader(headers, "content-type");
        if (body.length > 0) response.append(renderResponseBody(body, contentType));
        if (truncated) response.append("\n\n[response body truncated at 64 KB]");
        return response.toString();
    }

    private static String readHttpLine(InputStream input) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != -1) {
            if (value == '\n') break;
            if (line.size() >= 16384) throw new IOException("HTTP line exceeds 16 KB");
            line.write(value);
        }
        if (value == -1 && line.size() == 0) return null;
        byte[] bytes = line.toByteArray();
        int length = bytes.length > 0 && bytes[bytes.length - 1] == '\r' ? bytes.length - 1 : bytes.length;
        return new String(bytes, 0, length, StandardCharsets.ISO_8859_1);
    }

    private static BodyRead readBody(InputStream input, long limit) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) Math.min(limit, 8192));
        byte[] buffer = new byte[4096];
        long remaining = limit;
        while (remaining > 0) {
            int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (count < 0) break;
            bytes.write(buffer, 0, count);
            remaining -= count;
        }
        return new BodyRead(bytes.toByteArray());
    }

    private static BodyRead readChunkedBody(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String chunkLine = readHttpLine(input);
            if (chunkLine == null) throw new IOException("Incomplete chunked response");
            String chunkSize = chunkLine.split(";", 2)[0].trim();
            long size;
            try { size = Long.parseLong(chunkSize, 16); }
            catch (NumberFormatException e) { throw new IOException("Invalid chunk size"); }
            if (size < 0) throw new IOException("Invalid chunk size");
            if (size == 0) {
                int trailerCount = 0;
                int trailerBytes = 0;
                while (true) {
                    chunkLine = readHttpLine(input);
                    if (chunkLine == null) throw new IOException("Incomplete chunk trailers");
                    if (chunkLine.isEmpty()) break;
                    if (++trailerCount > 100 || (trailerBytes += chunkLine.length()) > 65536)
                        throw new IOException("Chunk trailers exceed safety limit");
                }
                return new BodyRead(body.toByteArray());
            }
            int capacity = limit + 1 - body.size();
            if (capacity <= 0) return new BodyRead(body.toByteArray(), true);
            int toRead = (int) Math.min(size, capacity);
            byte[] chunk = readExactly(input, toRead);
            body.write(chunk);
            if (size > toRead || body.size() > limit) return new BodyRead(body.toByteArray(), true);
            String delimiter = readHttpLine(input);
            if (delimiter == null || !delimiter.isEmpty()) throw new IOException("Invalid chunk delimiter");
        }
    }

    private static byte[] readExactly(InputStream input, int length) throws IOException {
        byte[] bytes = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = input.read(bytes, offset, length - offset);
            if (count < 0) throw new IOException("Incomplete response body");
            offset += count;
        }
        return bytes;
    }

    private static String responseHeader(List<String> headers, String name) {
        for (String header : headers) {
            int colon = header.indexOf(':');
            if (colon > 0 && name.equalsIgnoreCase(header.substring(0, colon).trim())) {
                return header.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private static int parseStatusCode(String statusLine) {
        String[] parts = statusLine.split(" ", 3);
        if (parts.length < 2) return 0;
        try { return Integer.parseInt(parts[1]); }
        catch (NumberFormatException e) { return 0; }
    }

    private static String renderResponseBody(byte[] body, String contentType) {
        String contentTypeLower = contentType == null ? "" : contentType.toLowerCase(Locale.US);
        boolean textContent = contentTypeLower.startsWith("text/")
                || contentTypeLower.contains("json") || contentTypeLower.contains("xml")
                || contentTypeLower.contains("javascript") || contentTypeLower.contains("form-urlencoded");
        if (!textContent && containsBinaryData(body)) {
            StringBuilder hex = new StringBuilder();
            int count = Math.min(body.length, 256);
            for (int i = 0; i < count; i++) {
                if (i > 0) hex.append(' ');
                hex.append(String.format(Locale.US, "%02x", body[i] & 0xff));
            }
            if (body.length > count) hex.append(" …");
            return "[non-text response body: " + body.length + " bytes; hex preview]\n" + hex;
        }
        Charset charset = StandardCharsets.UTF_8;
        if (contentType != null) {
            for (String part : contentType.split(";")) {
                String trimmed = part.trim();
                if (trimmed.toLowerCase(Locale.US).startsWith("charset=")) {
                    String name = trimmed.substring("charset=".length()).replace("\"", "").trim();
                    try { charset = Charset.forName(name); }
                    catch (Exception ignored) {}
                }
            }
        }
        return new String(body, charset).replace("\u0000", "�");
    }

    private static boolean containsBinaryData(byte[] data) {
        int controls = 0;
        int examined = Math.min(data.length, 1024);
        for (int i = 0; i < examined; i++) {
            int value = data[i] & 0xff;
            if (value == 0 || (value < 9) || (value > 13 && value < 32)) controls++;
        }
        return examined > 0 && controls * 10 > examined;
    }

    private static final class BodyRead {
        final byte[] bytes;
        final boolean truncated;
        BodyRead(byte[] bytes) { this(bytes, false); }
        BodyRead(byte[] bytes, boolean truncated) {
            this.bytes = bytes;
            this.truncated = truncated;
        }
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

    private void chooseComparison() {
        List<TrafficStore.Entry> entries = TrafficStore.snapshot();
        if (!targetScope.isEmpty()) entries.removeIf(entry -> !isEntryInTargetScope(entry));
        if (entries.size() < 2) {
            Toast.makeText(this, targetScope.isEmpty()
                    ? "Capture at least two requests to compare"
                    : "Capture at least two requests within Target scope", Toast.LENGTH_SHORT).show();
            return;
        }
        String[] labels = new String[entries.size()];
        for (int i = 0; i < entries.size(); i++) {
            TrafficStore.Entry entry = entries.get(i);
            labels[i] = "#" + entry.id + " " + entry.method + " " + entry.url + " [" + entry.status + "]";
        }
        new AlertDialog.Builder(this)
                .setTitle("Choose first request")
                .setItems(labels, (dialog, which) -> chooseSecondComparison(entries, labels, which))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void chooseSecondComparison(List<TrafficStore.Entry> entries, String[] labels, int firstIndex) {
        String[] choices = new String[entries.size() - 1];
        int[] indexes = new int[choices.length];
        int at = 0;
        for (int i = 0; i < entries.size(); i++) {
            if (i == firstIndex) continue;
            choices[at] = labels[i];
            indexes[at++] = i;
        }
        new AlertDialog.Builder(this)
                .setTitle("Choose request to compare")
                .setItems(choices, (dialog, which) ->
                        showComparison(entries.get(firstIndex), entries.get(indexes[which])))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showComparison(TrafficStore.Entry first, TrafficStore.Entry second) {
        StringBuilder diff = new StringBuilder();
        diff.append("A: #").append(first.id).append("  ").append(first.method).append(" ")
                .append(first.url).append("  [").append(first.status).append("]\n");
        diff.append("B: #").append(second.id).append("  ").append(second.method).append(" ")
                .append(second.url).append("  [").append(second.status).append("]\n\n");
        appendDiff(diff, "Request headers", first.requestHeaders, second.requestHeaders);
        appendDiff(diff, "Request body preview", first.requestBody, second.requestBody);
        appendDiff(diff, "Response headers", first.responseHeaders, second.responseHeaders);
        appendDiff(diff, "Response body preview", first.responseBody, second.responseBody);
        ScrollView scroll = new ScrollView(this);
        TextView result = text(diff.toString(), 12, FG, false);
        result.setTypeface(Typeface.MONOSPACE, Typeface.NORMAL);
        result.setPadding(dp(16), dp(12), dp(16), dp(12));
        scroll.addView(result);
        new AlertDialog.Builder(this)
                .setTitle("Request / response comparison")
                .setView(scroll)
                .setPositiveButton("Close", null)
                .show();
    }

    private void appendDiff(StringBuilder out, String title, String left, String right) {
        out.append("=== ").append(title).append(" ===\n");
        String[] a = (left == null ? "" : left).split("\\n", -1);
        String[] b = (right == null ? "" : right).split("\\n", -1);
        int limit = Math.min(Math.max(a.length, b.length), 120);
        boolean changed = false;
        for (int i = 0; i < limit; i++) {
            String av = i < a.length ? a[i] : null;
            String bv = i < b.length ? b[i] : null;
            if (java.util.Objects.equals(av, bv)) continue;
            changed = true;
            if (av != null && !av.isEmpty()) out.append("- ").append(av).append('\n');
            if (bv != null && !bv.isEmpty()) out.append("+ ").append(bv).append('\n');
        }
        if (!changed) out.append("[No difference or no body captured]\n");
        if (Math.max(a.length, b.length) > 120) out.append("[comparison truncated]\n");
        out.append('\n');
    }

    private void shareTestReport() {
        List<TrafficStore.Entry> entries = TrafficStore.snapshot();
        String reportText = buildTestReport(entries);
        new AlertDialog.Builder(this)
                .setTitle("Share sanitized test report?")
                .setMessage("The report contains request metadata only. It excludes headers and bodies, but includes hostnames and sanitized URLs.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Share", (dialog, which) -> {
                    Intent share = new Intent(Intent.ACTION_SEND);
                    share.setType("text/plain");
                    share.putExtra(Intent.EXTRA_SUBJECT, "PocketProxy Lab test report");
                    share.putExtra(Intent.EXTRA_TEXT, reportText);
                    startActivity(Intent.createChooser(share, "Share sanitized test report"));
                })
                .show();
    }

    private String buildTestReport(List<TrafficStore.Entry> entries) {
        StringBuilder report = new StringBuilder("PocketProxy Lab - test session report\n");
        report.append("Generated: ")
                .append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
                        .format(new java.util.Date()))
                .append('\n');
        report.append("Scope: ");
        if (targetScope.isEmpty()) {
            report.append("not configured (all captured metadata included)\n");
        } else {
            report.append(String.join(", ", targetScope)).append('\n');
        }
        int included = 0;
        Map<String, Integer> statusCounts = new TreeMap<>();
        Map<String, Integer> methodCounts = new TreeMap<>();
        for (TrafficStore.Entry entry : entries) {
            if (targetScope.isEmpty() || isEntryInTargetScope(entry)) {
                included++;
                statusCounts.put(entry.status, statusCounts.getOrDefault(entry.status, 0) + 1);
                methodCounts.put(entry.method, methodCounts.getOrDefault(entry.method, 0) + 1);
            }
        }
        report.append("Included entries: ").append(included).append('\n');
        report.append("Methods: ").append(methodCounts).append('\n');
        report.append("Statuses: ").append(statusCounts).append('\n');
        report.append("Headers and bodies excluded. Query secrets redacted where recognized.\n\n");
        for (TrafficStore.Entry entry : entries) {
            if (!targetScope.isEmpty() && !isEntryInTargetScope(entry)) continue;
            report.append(entry.timeLabel()).append("  ").append(entry.method).append("  ")
                    .append(entry.status).append("  ").append(TrafficStore.sanitizeUrl(entry.url))
                    .append("  ").append(entry.durationMs).append(" ms\n");
        }
        return report.toString();
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
