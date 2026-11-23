# PocketProxy Lab (Android)

A **local-only, Burp-style educational HTTP proxy** for Android phones. It is an independently developed starter app, **not an official Burp Suite product** and not affiliated with PortSwigger. It is intended solely for your own devices, test accounts, and expressly authorized security work.

## What works in version 1.0

- A foreground proxy service bound strictly to **127.0.0.1:8888** (not accessible over Wi-Fi or cellular from other devices).
- HTTP forwarding, including GET/POST and request bodies (Content-Length and chunked transfer).
- HTTPS **CONNECT tunnels**, preserving encryption: records destination host only, **never decrypts HTTPS content**.
- Searchable, tappable traffic history; request/response headers; HTTP response codes and durations.
- History search covers captured headers and enabled body previews, with method and status filters.
- Plain HTTP Request Repeater with editable method, URL, headers and body.
- Repeater displays response headers and a bounded response body, including gzip decoding and charset-aware text display.
- Side-by-side request/response comparison with line-level differences.
- Explicitly confirmed, metadata-only test report sharing.
- Optional manual plain HTTP interception with forward, edit-and-forward, and drop controls.
- Intercepted requests automatically pass through unchanged after 45 seconds if no action is taken.
- Captured HTTP request and response body previews in traffic details.
- Built-in Base64, URL and hex decode/encode tools.
- Target scope filtering with in-memory host-and-port allowlists. Repeater and Intruder require an explicit scope match.
- Intruder-style plain HTTP payload runner, capped at 20 requests.
- Automatically masks common authentication, cookie, and key **header values** in history, and common secrets in URL query parameters.
- Optional HTTP body-preview capture (OFF by default; this can expose secrets and should only be used for safe test traffic).
- A built-in **offline self-test** using `http://pocketproxy.test/` (handled inside the proxy; no DNS/network access required).
- A safe summary export through Android's share sheet.
- All captured traffic history stored **in memory only** (maximum 300 entries); no network uploads, analytics SDKs or file persistence.
- Build with Android Studio on a Mac, or with the included GitHub Actions workflow.

## Limitations / important caveats

- **This does not provide system-wide transparent interception.** Apps must honor the Android Wi-Fi proxy setting (or be explicitly configured to use the proxy). Many apps ignore it.
- **HTTPS is NOT decrypted.** There is no certificate authority, user CA install, certificate-pinning bypass or TLS man-in-the-middle feature.
- Android's Wi-Fi proxy setting is per Wi-Fi network. It may not work for cellular apps or all browsers, and some devices reject a loopback proxy host.
- Manual interception is limited to bodyless or UTF-8 text requests with Content-Length up to 64 KB. Chunked, larger, binary, and `Expect: 100-continue` requests pass through without pausing.
- Repeater and Intruder send only plain HTTP to explicitly scoped hosts and ports. A host-only scope entry means port 80; subdomains are included on that port. HTTPS, IPv6 scope entries, and requests outside the selected scope are not sent by those tools.
- This is a basic HTTP/1.x forward proxy, not an HTTP/2, HTTP/3, WebSocket inspection, scanner, or VPN-based proxy. It does not guarantee compatibility with all HTTP servers or long-running connections.
- The **manual Wi-Fi proxy must be reset to None** after testing; stopping the app while the system proxy is still enabled can interrupt browsing.
- Although sensitive headers are masked, URL paths and body previews can still contain secrets. Do not share raw captures. Export only the sanitized summary if needed.
- Source has been tested for Java compilation and basic proxy forwarding with local JVM stubs; the full Android project must be built and verified on a real Android phone or emulator.

## Build on MacBook using Android Studio

1. Unzip `PocketProxyMobile.zip` on your MacBook.
2. Open **Android Studio > Open** and select the `PocketProxyMobile` project directory.
3. Let Gradle sync and download Android SDK Platform 35 if prompted. The project uses **JDK 17**, **Android Gradle Plugin 8.7.3**, **Gradle 8.10.2**, and **compileSdk 35**.
4. Choose **Build > Build Bundle(s) / APK(s) > Build APK(s)**.
5. The resulting debug APK will be at `app/build/outputs/apk/debug/app-debug.apk`.
6. With USB debugging enabled on your own Redmi, run from your Mac:

   ```bash
   adb devices
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```

### Build APK using GitHub Actions (does not require Android Studio)

1. Create a GitHub repository (preferably private).
2. Upload **the contents of** the `PocketProxyMobile` directory to the repository root, including `.github/workflows/build-apk.yml`.
3. Open **Actions > Build PocketProxy Android APK > Run workflow**. A push to `main` or `master` also triggers a build.
4. After a successful run, open its **Artifacts** section, download `PocketProxyMobile-debug-apk`, unzip it, and install `app-debug.apk` on your phone.
5. Alternatively, install via Mac Terminal: `adb install -r app-debug.apk`.

Note: the GitHub-hosted build downloads Gradle dependencies and Android SDK components over the internet. It produces a **debug APK**, suitable for your own test device—not a Play Store release build.

## First run on your Redmi Note 8 Pro

1. Open **PocketProxy Lab** and tap **Start proxy**. Accept the foreground service notification prompt if Android asks.
2. Tap **Run offline test**. The app should display a `GET pocketproxy.test` request with HTTP status `200`.
3. For apps that honor Wi-Fi proxies, open **Android Settings > Wi-Fi > your connected network > Modify network / Advanced > Proxy > Manual**. Set:
   - Proxy host: `127.0.0.1`
   - Port: `8888`
4. Browse a **plain HTTP** endpoint you own or are authorized to test. Tap its entry in PocketProxy Lab to see the request and response metadata.
5. HTTPS CONNECT connections may be displayed as `TUNNEL`; their encrypted bodies are deliberately not visible.
6. When finished, restore your Wi-Fi network's proxy setting to **None**, then tap **Stop** in PocketProxy Lab.

## App structure

```text
PocketProxyMobile/
├── .github/workflows/build-apk.yml
├── app/
│   ├── build.gradle
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/pocketproxy/lab/
│       │   ├── MainActivity.java     # Native UI and offline self-test
│       │   ├── ProxyService.java     # Loopback HTTP proxy and CONNECT tunneling
│       │   ├── TrafficStore.java     # In-memory sanitized capture history
│       │   └── InterceptStore.java   # In-memory manual intercept queue
│       └── res/values/styles.xml
├── build.gradle
├── gradle.properties
└── settings.gradle
```

## Responsible testing

Only analyze traffic belonging to your own devices and accounts, and endpoints explicitly permitted by the applicable security testing rules. This proxy is not designed to evade pinning, exfiltrate credentials, or monitor someone else's device.
