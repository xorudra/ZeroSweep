/**
 * Prompt 17 — synthetic fixture application (§103–§115).
 *
 * `com.example.app` is a FICTIONAL application. Every issue is planted
 * deliberately: an exported unprotected component, a cleartext domain
 * exception, a SYNTHETIC hardcoded token (a fake string that is not,
 * and never was, a real credential), insecure test-data storage, a
 * WebView bridge, a debug signing certificate and a vulnerable test
 * dependency. No real application package is ever analyzed (§104).
 */
import type { ArchiveEntry } from "../code/archive";
import { sha256Hex } from "./intake";
import type { MobileApplicationRecord, MobileBuildRecord, MobileConnectorDeps } from "./types";

/** The planted synthetic token. It is FAKE — tests assert it never
 *  survives into any finding, event, log or API response (§106). */
export const FIXTURE_SECRET_VALUE = "FAKE_EXAMPLE_TOKEN_0123456789abcdef";

export const FIXTURE_PACKAGE_NAME = "com.example.app";
export const FIXTURE_BUILD_HASH = sha256Hex(new TextEncoder().encode("zerosweep-fixture-apk-bytes-com.example.app-1.2"));

export const FIXTURE_ANDROID_MANIFEST_XML = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:versionCode="102"
    android:versionName="1.2">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="com.example.app.permission.INTERNAL" />
    <application
        android:label="Example App"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/invite" />
                <data android:scheme="exampleapp" android:host="open" />
            </intent-filter>
        </activity>
        <activity android:name=".SettingsActivity" android:exported="false" />
        <service android:name=".SyncService" android:exported="true">
            <intent-filter>
                <action android:name="com.example.app.action.SYNC" />
            </intent-filter>
        </service>
        <service android:name=".GuardedService" android:exported="true" android:permission="com.example.app.permission.INTERNAL" />
        <provider android:name=".DataProvider" android:exported="true" android:grantUriPermissions="true" />
    </application>
</manifest>`;

export const FIXTURE_NETWORK_SECURITY_CONFIG_XML = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">api.example.com</domain>
    </domain-config>
</network-security-config>`;

export const FIXTURE_DECOMPILED_SOURCES: { path: string; text: string }[] = [
  {
    path: "com/example/app/MainActivity.java",
    text: [
      "package com.example.app;",
      "public class MainActivity extends Activity {",
      "  void onCreate() {",
      "    WebView web = findViewById(R.id.web);",
      "    web.getSettings().setJavaScriptEnabled(true);",
      "    web.getSettings().setAllowFileAccessFromFileURLs(true);",
      "    web.addJavascriptInterface(new Bridge(), \"AppBridge\");",
      "    String API_TOKEN = \"" + FIXTURE_SECRET_VALUE + "\";",
      "    loadUrl(\"https://api.example.com/v1/home\");",
      "  }",
      "}",
    ].join("\n"),
  },
  {
    path: "com/example/app/SessionStore.java",
    text: [
      "package com.example.app;",
      "public class SessionStore {",
      "  void save(Context ctx, String token) {",
      "    SharedPreferences prefs = ctx.getSharedPreferences(\"session\", Context.MODE_WORLD_READABLE);",
      "    prefs.edit().putString(\"session_token\", token).apply();",
      "    Log.d(\"auth\", \"saved token=\" + token);",
      "    String legacy = \"http://api.example.com/legacy/ping\";",
      "  }",
      "}",
    ].join("\n"),
  },
];

export const FIXTURE_MOBSF_REPORT = JSON.stringify({
  app_name: "Example App",
  package_name: FIXTURE_PACKAGE_NAME,
  version_name: "1.2",
  version_code: 102,
  min_sdk: "24",
  target_sdk: "34",
  permissions: {
    "android.permission.INTERNET": { status: "normal" },
    "android.permission.CAMERA": { status: "dangerous" },
    "android.permission.READ_CONTACTS": { status: "dangerous" },
  },
  manifest_analysis: {
    manifest_findings: [
      { title: "Application is debuggable", severity: "high", description: "android:debuggable is enabled for this build.", cwe: "CWE-489" },
      { title: "Cleartext traffic allowed", severity: "high", description: "The application permits cleartext traffic.", cwe: "CWE-319" },
    ],
  },
  code_analysis: {
    findings: {
      "hardcoded_token": {
        metadata: { description: "Hardcoded secret found in code", severity: "high", cwe: "CWE-798" },
        files: { "com/example/app/MainActivity.java": "14" },
      },
    },
  },
  certificate_analysis: {
    certificate_info: {
      subject: "CN=Android Debug, O=Example",
      issuer: "CN=Android Debug, O=Example",
      fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
      algorithm: "SHA256withRSA",
    },
    certificate_findings: [],
  },
  urls: ["https://api.example.com/v1/home", "http://api.example.com/legacy/ping"],
  trackers: [{ name: "Example Analytics SDK" }],
});

export const FIXTURE_JADX_OUTPUT = JSON.stringify({
  sourceFiles: FIXTURE_DECOMPILED_SOURCES,
});

export const FIXTURE_APKTOOL_OUTPUT = JSON.stringify({
  manifestXml: FIXTURE_ANDROID_MANIFEST_XML,
  networkSecurityConfigXml: FIXTURE_NETWORK_SECURITY_CONFIG_XML,
  files: [
    "AndroidManifest.xml",
    "classes.dex",
    "res/xml/network_security_config.xml",
    "lib/arm64-v8a/libexample.so",
    "lib/armeabi-v7a/libexample.so",
    "assets/config.json",
  ],
  dependencyHints: ["maven:com.example:example-json-lib:1.0.0"],
});

export const FIXTURE_GHIDRA_REPORT = JSON.stringify({
  libraries: [
    {
      path: "lib/arm64-v8a/libexample.so",
      architecture: "arm64-v8a",
      sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      hardening: { pie: false, nx: true, stackCanary: false, relro: "PARTIAL", stripped: false },
    },
  ],
});

/** iOS fixture (§37–§41): the same fictional product on iOS. */
export const FIXTURE_INFO_PLIST_XML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.iosapp</string>
    <key>CFBundleShortVersionString</key>
    <string>1.2</string>
    <key>MinimumOSVersion</key>
    <string>15.0</string>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>exampleios</string>
            </array>
        </dict>
    </array>
    <key>NSCameraUsageDescription</key>
    <string>Used to scan invite codes (fixture).</string>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <false/>
        <key>NSExceptionDomains</key>
        <dict>
            <key>legacy.example.com</key>
            <dict>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <true/>
                <key>NSIncludesSubdomains</key>
                <false/>
            </dict>
        </dict>
    </dict>
</dict>
</plist>`;

export const FIXTURE_IOS_ENTITLEMENTS: Record<string, unknown> = {
  "application-identifier": "TEAMID0000.com.example.iosapp",
  "com.apple.developer.associated-domains": ["applinks:app.example.com"],
};

export const FIXTURE_MOBILE_MITMPROXY_FLOWS = JSON.stringify({
  flows: [
    { host: "api.example.com", scheme: "https", method: "GET", path: "/v1/home", status: 200 },
    { host: "api.example.com", scheme: "http", method: "GET", path: "/legacy/ping", status: 200 },
  ],
});

export const FIXTURE_MOBILE_APP_RECORD: MobileApplicationRecord = {
  id: "mobile-app-1",
  workspaceId: "ws-1",
  name: "Example App (fixture)",
  platform: "ANDROID",
  packageName: FIXTURE_PACKAGE_NAME,
  environment: "PRODUCTION",
  criticality: "HIGH",
  status: "REGISTERED",
};

/** The build's registered analysis artifacts (§6): the bounded
 *  extracted artifacts the static pipeline consumes. */
export function fixtureAnalysisArtifacts(): Record<string, unknown> {
  return {
    manifestXml: FIXTURE_ANDROID_MANIFEST_XML,
    networkSecurityConfigXml: FIXTURE_NETWORK_SECURITY_CONFIG_XML,
    sourceSnippets: FIXTURE_DECOMPILED_SOURCES,
    nativeLibraries: [
      {
        path: "lib/arm64-v8a/libexample.so", architecture: "arm64-v8a",
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        pie: false, nx: true, stackCanary: false, relro: "PARTIAL", stripped: false,
      },
    ],
    signing: [
      {
        subject: "CN=Android Debug, O=Example", issuer: "CN=Android Debug, O=Example",
        fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
        algorithm: "SHA256withRSA", debug: true,
      },
    ],
    dependencies: [
      { name: "example-json-lib", version: "1.0.0", ecosystem: "maven" },
      { name: "example-net-lib", version: "2.3.1", ecosystem: "maven" },
    ],
    sdkNames: [{ name: "Example Analytics SDK", category: "ANALYTICS" }],
  };
}

export const FIXTURE_MOBILE_BUILD_RECORD: MobileBuildRecord = {
  id: "mobile-build-1",
  applicationId: "mobile-app-1",
  workspaceId: "ws-1",
  versionName: "1.2",
  versionCode: 102,
  artifactHash: FIXTURE_BUILD_HASH,
  artifactFormat: "APK",
  artifactReference: `mobile-artifacts/mobile-app-1/${FIXTURE_BUILD_HASH}`,
  analysisArtifacts: fixtureAnalysisArtifacts(),
};

/** §107 attack fixtures: entry listings that MUST be rejected. */
export const ATTACK_ARCHIVE_ENTRIES: Record<string, ArchiveEntry[]> = {
  traversal: [{ name: "../escape.txt", uncompressedSize: 10, compressedSize: 10, isDirectory: false, isSymlink: false }],
  absolute: [{ name: "/etc/passwd", uncompressedSize: 10, compressedSize: 10, isDirectory: false, isSymlink: false }],
  symlink: [{ name: "lib/link.so", uncompressedSize: 10, compressedSize: 10, isDirectory: false, isSymlink: true, unixMode: 0o120777 }],
  bomb: [{ name: "classes.dex", uncompressedSize: 2 * 1024 * 1024 * 1024, compressedSize: 1024, isDirectory: false, isSymlink: false }],
  nested: [{ name: "assets/inner.zip", uncompressedSize: 100, compressedSize: 100, isDirectory: false, isSymlink: false }],
};

/** Fixture connector deps (§104): the recorded MobSF report + the
 *  managed emulator + the recorded proxy flows. No network, no real
 *  device, no real scanner. */
export function createFixtureMobileDeps(build: MobileBuildRecord = FIXTURE_MOBILE_BUILD_RECORD): MobileConnectorDeps {
  return {
    applications: {
      async getApplication(id: string) {
        return id === FIXTURE_MOBILE_APP_RECORD.id ? FIXTURE_MOBILE_APP_RECORD : undefined;
      },
      async getBuild(id: string) {
        return id === build.id ? build : undefined;
      },
      async getLatestBuild(applicationId: string) {
        return applicationId === FIXTURE_MOBILE_APP_RECORD.id ? build : undefined;
      },
    },
    transports: {
      mobsf: {
        async fetchReport(artifactHash: string) {
          return artifactHash === FIXTURE_BUILD_HASH ? FIXTURE_MOBSF_REPORT : undefined;
        },
      },
      devices: {
        async listDevices() {
          return [{
            id: "lab-emulator-1", name: "Fixture Emulator (API 34)", platform: "ANDROID" as const,
            deviceKind: "EMULATOR" as const, osVersion: "14", availability: "AVAILABLE",
            health: "HEALTHY", dedicatedNetwork: true,
          }];
        },
        async installApprovedBuild(_deviceId: string, buildHash: string) {
          // §60: the build hash is verified before install — a
          // mismatched hash is refused, never installed.
          return { installed: buildHash === FIXTURE_BUILD_HASH, verifiedHash: buildHash === FIXTURE_BUILD_HASH };
        },
        async collectLogs() { return undefined; },
        async resetDevice() { return { reset: true }; },
      },
      traffic: {
        async readSession(sessionId: string) {
          return sessionId === "fixture-traffic-1" ? FIXTURE_MOBILE_MITMPROXY_FLOWS : undefined;
        },
      },
    },
  };
}
