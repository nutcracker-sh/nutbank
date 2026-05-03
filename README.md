<img width="1536" height="1024" alt="D82A3018-6034-4B56-A12B-CDEC14104903" src="https://github.com/user-attachments/assets/32069080-39d4-4170-b3ce-34ea61880359" />

# 🥜 NutBank — Intentionally Vulnerable Android App

> ⚠️ **WARNING**: This application is intentionally vulnerable. It is designed **exclusively** for security research, education, and testing purposes. **Do NOT use in production environments.**

![Platform](https://img.shields.io/badge/Platform-Android-3DDC84?logo=android)
![Language](https://img.shields.io/badge/Kotlin-1.9-7F52FF?logo=kotlin)
![Purpose](https://img.shields.io/badge/Purpose-Security%20Research-red)
[![GitHub Stars](https://img.shields.io/github/stars/nutcracker-sh/nutbank?style=social)](https://github.com/nutcracker-sh/nutbank/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/nutcracker-sh/nutbank)](https://github.com/nutcracker-sh/nutbank/issues)
[![GitHub License](https://img.shields.io/github/license/nutcracker-sh/nutbank)](https://github.com/nutcracker-sh/nutbank/blob/main/LICENSE)
![GitHub last commit](https://img.shields.io/github/last-commit/nutcracker-sh/nutbank)
![API](https://img.shields.io/badge/API-26%2B-brightgreen)

## 📖 About

NutBank is part of [**nutcracker.sh**](https://nutcracker.sh) — an Android security analysis platform. It is a deliberately insecure Android application that simulates a banking app with multiple intentional vulnerabilities and real-world RASP protections.

This app allows security researchers, pentesters, and students to practice identifying and exploiting real-world mobile vulnerabilities in a safe, controlled environment.

🔗 **[nutcracker.sh](https://nutcracker.sh)** — Android mobile security testing platform

## 🔐 Intentional Vulnerabilities

### Hardcoded Secrets (MASVS-CODE-9)
- API keys, database credentials, Stripe keys, Firebase config, AWS credentials, and more — all hardcoded in plaintext inside `Secrets.kt`.

### Insecure Data Storage (MASVS-PLATFORM-2)
- Session tokens stored in **SharedPreferences** in plaintext.
- Sensitive data written to **external storage**, **cache**, and an **insecure SQLite database**.

### Weak Cryptography (MASVS-CRYPTO-1)
- **ECB mode** encryption.
- **MD5** and **SHA-1** hashing for passwords and integrity checks.

### Insecure Network Communication (MASVS-NETWORK)
- **No certificate pinning**.
- **No hostname verification**.
- HTTP endpoints used alongside HTTPS.

### Exported Components (MASVS-PLATFORM-1)
- **ContentProvider** exported with sensitive data accessible to any app.
- **BroadcastReceiver** accepting implicit intents from any application.
- **Activities** exported without proper permission checks.

### Insecure Logging (MASVS-CODE-4)
- Credentials, session tokens, API keys, and database connection strings logged to **Logcat**.

### Insecure WebView (MASVS-PLATFORM-5)
- JavaScript enabled with no restrictions.
- Mixed content allowed.

### Weak Biometric Authentication (MASVS-AUTH-8)
- Biometric check that can be bypassed.

### Deep Link Vulnerabilities (MASVS-PLATFORM-6)
- Implicit intents with sensitive data (credentials, API keys) sent through insecure deep links.

## 🛡️ RASP Protection

NutBank implements **Runtime Application Self-Protection (RASP)** with multiple layers of defense that aim to resist bypass attempts. These protections serve as a real-world challenge for security researchers and mobile app pentesters.

### Detection Mechanisms
- 🌱 **Root Detection** — via RootBeer library: `su` binary, root management apps (Magisk, SuperSU), test-keys build, writable system partitions
- 🐉 **Frida Detection** — port scanning (27042), `/proc/*/cmdline` process inspection, `/proc/self/maps` memory analysis for Frida artifacts (`frida-server`, `frida-agent`, `frida-gadget`, etc.)
- 🖥️ **Emulator Detection** — Build fingerprint analysis, QEMU pipe/socket detection, hardware property checks
- 🐛 **Debugger Detection** — `android.os.Debug.isDebuggerConnected()`, ptrace status via `/proc/self/status`
- 🔧 **Hooking Framework Detection** — Xposed, Substrate, and LSPOSED module scanning
- 🔏 **Repackaging / Tamper Detection** — APK signature verification, package certificate hash comparison
- 📱 **Screen Capture Prevention** — `FLAG_SECURE` on all activities to prevent screenshots and screen recording

### Response Strategy
When a threat is detected, NutBank can:
- Display a **blocking dialog** that forces app closure
- Run checks **continuously** in the background via coroutines, not just at startup
- Use **obfuscated check logic** to hinder static analysis
- Employ **timing-based anomalies** to detect hooking interference

> 💡 These RASP controls are designed to be **robust but bypassable** — the goal is to provide a realistic training target. Advanced attackers using nutcracker.sh can practice bypassing each protection type.

## 🏗️ Architecture

```
app/src/main/java/sh/nutcracker/nutbank/
├── MainActivity.kt            # Login screen + RASP checks
├── DashboardActivity.kt       # Displays all "leaked" secrets
├── AdminActivity.kt           # Exported admin panel (no auth)
├── Secrets.kt                 # Hardcoded credentials & API keys
├── CryptoHelper.kt            # Weak crypto (ECB, MD5, SHA-1)
├── DataStoreManager.kt        # Insecure storage patterns
├── NetworkClient.kt           # No SSL pinning / hostname verification
├── ContentProviderHandler.kt  # Exported content provider
├── BroadcastReceiverHandler.kt# Exported broadcast receiver
├── DeepLinkActivity.kt        # Insecure deep link handling
├── WebActivity.kt             # Insecure WebView
├── BiometricAuthActivity.kt   # Weak biometric implementation
└── DataStoreManager.kt        # File/database preference storage
```

## 🚀 Getting Started

### Prerequisites
- Android Studio (latest stable)
- Android Emulator or physical device (API 28+)
- RootBeer library (included via Gradle)

### Build & Run

```bash
# Clone the repository
git clone https://github.com/nutcracker-sh/nutbank.git
cd nutbank

# Build and install
./gradlew installDebug

# Launch on connected device/emulator
adb shell am start -n sh.nutcracker.nutbank/.MainActivity
```

### Default Credentials
- **Username**: `admin`
- **Password**: `P@ssw0rd123!`

## 🔧 Use with Nutcracker

This app is designed as a companion target for [nutcracker.sh](https://nutcracker.sh):

1. Install NutBank on your test device/emulator
2. Run nutcracker security analysis against the app
3. Identify all intentional vulnerabilities
4. Practice writing remediation reports

## 📋 OWASP MASVS Coverage

| MASVS Category | Vulnerability | Status |
|---|---|---|
| MASVS-CRYPTO-1 | Weak crypto algorithms | ✅ |
| MASVS-PLATFORM-1 | Exported components | ✅ |
| MASVS-PLATFORM-2 | Insecure data storage | ✅ |
| MASVS-PLATFORM-5 | Insecure WebView | ✅ |
| MASVS-PLATFORM-6 | Insecure deep links | ✅ |
| MASVS-NETWORK-1 | No certificate pinning | ✅ |
| MASVS-NETWORK-2 | Weak TLS configuration | ✅ |
| MASVS-CODE-4 | Insecure logging | ✅ |
| MASVS-CODE-9 | Hardcoded secrets | ✅ |
| MASVS-AUTH-8 | Weak biometric auth | ✅ |

## ⚖️ Disclaimer

This application is provided for **educational and authorized security testing purposes only**. The authors assume no liability and are not responsible for any misuse or damage caused by this project.

## 👤 Author

**Carlos Ganoza** ([@drneox](https://twitter.com/drneox)) — carlos.ganoza@owasp.org

## 📄 License

This project is licensed for educational and security research purposes.
