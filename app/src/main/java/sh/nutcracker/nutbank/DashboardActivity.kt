package sh.nutcracker.nutbank

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.text.Html
import android.text.method.LinkMovementMethod
import android.util.Log
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/**
 * Dashboard looks like a normal banking app.
 * VULNERABILITIES are hidden — secrets are in the code, logged to Logcat,
 * stored in SharedPreferences, external storage, cache, and SQLite DB.
 * nutcracker.sh will find them through reverse engineering and storage analysis.
 */
class DashboardActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "NutBankDashboard"
        private const val PREFS_NAME = "nutbank_session"
        private const val KEY_TOKEN = "session_token"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_dashboard)

        val username = intent.getStringExtra("username") ?: "user"

        // ── Normal Banking UI ────────────────────────────────────
        findViewById<TextView>(R.id.tvWelcome).text = "Welcome, $username"
        findViewById<TextView>(R.id.tvRole).text = "Personal Account"
        findViewById<TextView>(R.id.tvCardHolder).text = username.uppercase()
        findViewById<TextView>(R.id.tvCardNumber).text =
            "•••• •••• •••• ${Secrets.ACCOUNT_NUMBER.takeLast(4)}"

        // Navigate to CreditCardActivity when card is tapped — requires PIN
        // VULNERABILITY: PIN is hardcoded in Secrets.CARD_PIN and compared in plaintext
        findViewById<TextView>(R.id.tvCardNumber).setOnClickListener {
            showPinDialog()
        }

        // Navigate to WebActivity (About Us) — loads nutcracker.sh in insecure WebView
        findViewById<android.view.View>(R.id.btnAboutUs).setOnClickListener {
            startActivity(Intent(this, WebActivity::class.java))
        }

        // ── VULNERABILITY: Generate and store session token (contains secrets) ─
        val sessionToken = Secrets.generateSessionToken(username)

        // VULNERABILITY: Store in SharedPreferences in plaintext
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        prefs.edit().putString(KEY_TOKEN, sessionToken).apply()

        // VULNERABILITY: Log sensitive data to Logcat
        Log.d(TAG, "Dashboard loaded for user: $username")
        Log.v(TAG, "Session token: $sessionToken")
        Log.d(TAG, "API Key: ${Secrets.API_KEY}")
        Log.i(TAG, "DB Connection: ${Secrets.DB_HOST} db=${Secrets.DB_NAME}")
        Log.w(TAG, "Stripe key in use: ${Secrets.STRIPE_SECRET_KEY}")

        // Also call the centralized leak function
        Secrets.logCredentials()

        // ── VULNERABILITY: MASVS-CRYPTO-1 — Use weak crypto ───────────
        val encryptedToken = CryptoHelper.encryptEcb(sessionToken)
        val passwordHash = CryptoHelper.hashMd5(Secrets.ADMIN_PASSWORD)
        val integrityHash = CryptoHelper.hashSha1(sessionToken)
        Log.d(TAG, "ECB encrypted token: $encryptedToken")
        Log.d(TAG, "MD5 password hash: $passwordHash")
        Log.d(TAG, "SHA-1 integrity: $integrityHash")

        // ── VULNERABILITY: MASVS-PLATFORM-2 — Insecure storage ─────────
        DataStoreManager.writeToExternalStorage(this)
        DataStoreManager.createInsecureDatabase(this)
        DataStoreManager.writeToCache(this)
        DataStoreManager.storeInSharedPreferences(this)

        // ── VULNERABILITY: SSL Pinning disabled — insecure network ─────
        NetworkClient.disableCertificatePinning()

        // Footer link to nutcracker.sh
        val tvFooter = findViewById<TextView>(R.id.tvFooter)
        tvFooter.text = Html.fromHtml("🔒 Powered by <a href=\"https://nutcracker.sh\">nutcracker.sh</a>")
        tvFooter.movementMethod = LinkMovementMethod.getInstance()
    }

    /**
     * VULNERABILITY: PIN is hardcoded in Secrets.CARD_PIN ("1234").
     * The comparison is done in plaintext and the PIN can be extracted via reverse engineering.
     */
    private fun showPinDialog() {
        val pinInput = EditText(this).apply {
            hint = "Enter 4-digit PIN"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                    android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            setPadding(50, 20, 50, 20)
        }

        AlertDialog.Builder(this)
            .setTitle("🔐 Card PIN Required")
            .setMessage("Enter your card PIN to view details.")
            .setView(pinInput)
            .setPositiveButton("Confirm") { _, _ ->
                val enteredPin = pinInput.text.toString()
                if (enteredPin == Secrets.CARD_PIN) {
                    startActivity(Intent(this, CreditCardActivity::class.java))
                } else {
                    Toast.makeText(this, "Incorrect PIN", Toast.LENGTH_SHORT).show()
                    Log.w(TAG, "Failed PIN attempt: $enteredPin")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
