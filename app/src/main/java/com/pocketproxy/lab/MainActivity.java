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
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

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
        countText = text("0 entries", 12, MUTED, false);
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
            item.setOnClickListener(v -> new AlertDialog.Builder(this)
                    .setTitle("Request " + entry.id)
                    .setMessage(entry.detail())
                    .setPositiveButton("Close", null)
                    .show());
        }
        if (shown == 0) {
            TextView empty = text(entries.isEmpty()
                    ? "No traffic yet. Start the proxy and run the offline test."
                    : "No entries match your filter.", 13, MUTED, false);
            empty.setPadding(dp(6), dp(15), dp(6), dp(15));
            historyContainer.addView(empty);
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
