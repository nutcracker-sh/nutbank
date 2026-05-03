package sh.nutcracker.nutbank

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import android.widget.Toast

/**
 * VULNERABILITY: MASVS-PLATFORM-3 — Insecure Communication / Intent Hijacking.
 *
 * 1. Deep link receives tokens via URL parameters (no validation)
 * 2. Sends sensitive data via implicit Intents (interceptable by other apps)
 * 3. Sticky Broadcast with credentials (readable by any app)
 * 4. Intent data used without verification or sanitization
 * 5. No signature checking on received intents
 *
 * nutcracker will flag insecure IPC communication.
 */
class DeepLinkActivity : Activity() {

    companion object {
        private const val TAG = "NutBankDeepLink"
        const val ACTION_CREDENTIALS = "sh.nutcracker.nutbank.CREDENTIALS"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val tv = TextView(this)
        tv.text = "DeepLink Handler\nProcessing incoming data..."
        setContentView(tv)

        handleDeepLink()
        sendInsecureBroadcast()
        sendInsecureIntent()
    }

    /**
     * VULNERABILITY: Processes deep link data without any validation.
     * An attacker can craft a malicious link to inject tokens or steal data.
     *
     * Example attack: nutbank://auth?token=STOLEN_TOKEN&redirect=evil.com
     */
    private fun handleDeepLink() {
        val uri = intent.data ?: return
        Log.d(TAG, "Deep link received: $uri")

        // VULNERABILITY: Trust all URL parameters without validation
        val token = uri.getQueryParameter("token")
        val username = uri.getQueryParameter("user")
        val redirectUrl = uri.getQueryParameter("redirect")
        val action = uri.getQueryParameter("action")

        Log.v(TAG, "Token from URL: $token")
        Log.v(TAG, "User from URL: $username")
        Log.v(TAG, "Redirect URL: $redirectUrl")
        Log.v(TAG, "Action: $action")

        // VULNERABILITY: Store token from URL directly into SharedPreferences
        if (token != null) {
            val prefs = getSharedPreferences("nutbank_session", MODE_PRIVATE)
            prefs.edit()
                .putString("session_token", token)
                .putString("username", username ?: "unknown")
                .apply()

            Log.d(TAG, "Token from deep link stored in SharedPreferences: $token")
            Toast.makeText(this, "Token accepted from deep link!", Toast.LENGTH_SHORT).show()
        }

        // VULNERABILITY: Execute action from URL without validation
        when (action) {
            "transfer" -> {
                val amount = uri.getQueryParameter("amount") ?: "0"
                val toAccount = uri.getQueryParameter("to") ?: ""
                Log.w(TAG, "Transfer action: $$amount to account $toAccount (NO VERIFICATION)")
            }
            "export" -> {
                // VULNERABILITY: Export all secrets via deep link
                Log.w(TAG, "Exporting secrets via deep link!")
                val result = buildString {
                    append("API_KEY=${Secrets.API_KEY}\n")
                    append("JWT_SECRET=${Secrets.JWT_SECRET}\n")
                    append("STRIPE_KEY=${Secrets.STRIPE_SECRET_KEY}\n")
                    append("DB=${Secrets.DB_USER}:${Secrets.DB_PASS}@${Secrets.DB_HOST}\n")
                }
                Log.i(TAG, "Exported secrets: $result")
            }
        }

        // VULNERABILITY: Open redirect — no URL validation
        if (redirectUrl != null) {
            Log.d(TAG, "Redirecting to: $redirectUrl (OPEN REDIRECT!)")
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(redirectUrl))
            startActivity(intent)
        }
    }

    /**
     * VULNERABILITY: Sends credentials via sticky broadcast.
     * Any app with BROADCAST_STICKY permission can read this.
     */
    private fun sendInsecureBroadcast() {
        // VULNERABILITY: Sticky broadcast with sensitive data
        val intent = Intent(ACTION_CREDENTIALS)
        intent.putExtra("api_key", Secrets.API_KEY)
        intent.putExtra("jwt_secret", Secrets.JWT_SECRET)
        intent.putExtra("db_host", Secrets.DB_HOST)
        intent.putExtra("db_user", Secrets.DB_USER)
        intent.putExtra("db_pass", Secrets.DB_PASS)
        intent.putExtra("session_token", getSharedPreferences("nutbank_session", MODE_PRIVATE)
            .getString("session_token", ""))

        // VULNERABILITY: sendStickyBroadcast — data persists and any app can read
        sendStickyBroadcast(intent)
        Log.d(TAG, "Credentials sent via sticky broadcast (readable by any app)")
    }

    /**
     * VULNERABILITY: Sends sensitive data via implicit intent.
     * Any app with matching intent-filter can intercept this.
     */
    private fun sendInsecureIntent() {
        // VULNERABILITY: Implicit intent with credentials
        val intent = Intent("sh.nutcracker.nutbank.SYNC_DATA")
        intent.putExtra("stripe_key", Secrets.STRIPE_SECRET_KEY)
        intent.putExtra("aws_key", Secrets.AWS_ACCESS_KEY)
        intent.putExtra("aws_secret", Secrets.AWS_SECRET_KEY)
        intent.putExtra("firebase_key", Secrets.FIREBASE_API_KEY)

        // VULNERABILITY: No package specified — any app can intercept
        sendBroadcast(intent)
        Log.d(TAG, "Sensitive data sent via implicit broadcast (interceptable)")
    }
}