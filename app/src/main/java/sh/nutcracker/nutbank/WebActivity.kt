package sh.nutcracker.nutbank

import android.annotation.SuppressLint
import android.app.Activity
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast

/**
 * VULNERABILITY: MASVS-CODE-4 — Insecure WebView (Code Injection).
 *
 * 1. setJavaScriptEnabled(true) — JS always on
 * 2. addJavascriptInterface — exposes Java object to JS (RCE on API < 17)
 * 3. setAllowFileAccess(true) — can read local files via file://
 * 4. setAllowContentAccess(true) — can access content provider
 * 5. Loads URL directly from intent data (deep link injection / XSS)
 * 6. No input validation or URL whitelisting
 *
 * nutcracker will flag insecure WebView configuration.
 */
class WebActivity : Activity() {

    companion object {
        private const val TAG = "NutBankWeb"
    }

    // VULNERABILITY: This object is exposed to JavaScript
    inner class SensitiveBridge {
        @JavascriptInterface
        fun getToken(): String {
            // VULNERABILITY: JS can steal the session token
            val prefs = getSharedPreferences("nutbank_session", MODE_PRIVATE)
            return prefs.getString("session_token", "") ?: ""
        }

        @JavascriptInterface
        fun getApiKey(): String = Secrets.API_KEY

        @JavascriptInterface
        fun getDbCredentials(): String = "${Secrets.DB_USER}:${Secrets.DB_PASS}"

        @JavascriptInterface
        fun executeCommand(cmd: String): String {
            // VULNERABILITY: Command injection from JavaScript
            Log.d(TAG, "Executing command from JS: $cmd")
            return try {
                val process = Runtime.getRuntime().exec(cmd)
                process.inputStream.bufferedReader().readText()
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this)

        // VULNERABILITY: JavaScript enabled with no restrictions
        webView.settings.javaScriptEnabled = true

        // VULNERABILITY: Allow access to local files
        webView.settings.allowFileAccess = true
        webView.settings.allowContentAccess = true

        // VULNERABILITY: DOM storage enabled without sanitization
        webView.settings.domStorageEnabled = true

        // VULNERABILITY: Allow file access from file:// URLs
        webView.settings.allowFileAccessFromFileURLs = true
        webView.settings.allowUniversalAccessFromFileURLs = true

        // VULNERABILITY: Expose Java object to JavaScript
        // On API < 17, reflection allows access to all methods (including getClass)
        webView.addJavascriptInterface(SensitiveBridge(), "NutBankBridge")

        webView.webViewClient = WebViewClient()
        webView.webChromeClient = WebChromeClient()

        // VULNERABILITY: Load URL from intent data without validation
        // An attacker can craft a malicious deep link with XSS payload
        val url = intent.data?.toString()
            ?: intent.getStringExtra("url")
            ?: "https://nutbank-demo.web.app"

        Log.d(TAG, "Loading URL in insecure WebView: $url")
        Log.v(TAG, "Session accessible via JS bridge")

        webView.loadUrl(url)
        setContentView(webView)

        Toast.makeText(this, "WebView: $url", Toast.LENGTH_SHORT).show()
    }
}