package sh.nutcracker.nutbank

import android.os.Bundle
import android.text.Html
import android.text.method.LinkMovementMethod
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * VULNERABILITY: Dashboard displays secrets directly from the hardcoded Secrets object.
 * Also leaks credentials to Logcat (another common vulnerability).
 * SharedPreferences session token is read and displayed in plaintext.
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

        // ── Header ──────────────────────────────────────────────
        findViewById<TextView>(R.id.tvWelcome).text = "Welcome, $username"
        findViewById<TextView>(R.id.tvRole).text = "Personal Account · ${Secrets.AWS_REGION}"

        // ── Account Details ─────────────────────────────────────
        findViewById<TextView>(R.id.tvAccountNumber).text = "**** **** ${Secrets.ACCOUNT_NUMBER.takeLast(4)}"
        findViewById<TextView>(R.id.tvRoutingNumber).text = Secrets.ROUTING_NUMBER
        findViewById<TextView>(R.id.tvAccountToken).text = Secrets.ACCOUNT_TOKEN
        findViewById<TextView>(R.id.tvAesKey).text = Secrets.AES_KEY
        findViewById<TextView>(R.id.tvAesIv).text = Secrets.AES_IV

        // ── Cloud Services ──────────────────────────────────────
        findViewById<TextView>(R.id.tvAwsAccessKey).text = Secrets.AWS_ACCESS_KEY
        findViewById<TextView>(R.id.tvAwsSecretKey).text = Secrets.AWS_SECRET_KEY
        findViewById<TextView>(R.id.tvS3Bucket).text = "s3://${Secrets.AWS_S3_BUCKET}"
        findViewById<TextView>(R.id.tvFirebaseKey).text = Secrets.FIREBASE_API_KEY
        findViewById<TextView>(R.id.tvFirebaseDbUrl).text = Secrets.FIREBASE_DB_URL
        findViewById<TextView>(R.id.tvFirebaseProject).text = Secrets.FIREBASE_PROJECT

        // ── Payment Gateway ─────────────────────────────────────
        findViewById<TextView>(R.id.tvStripeKey).text = Secrets.STRIPE_SECRET_KEY
        findViewById<TextView>(R.id.tvStripeWebhook).text = Secrets.STRIPE_WEBHOOK_SECRET

        // ── Communications ──────────────────────────────────────
        findViewById<TextView>(R.id.tvSendGridKey).text = Secrets.SENDGRID_API_KEY
        findViewById<TextView>(R.id.tvTwilioSid).text = Secrets.TWILIO_ACCOUNT_SID
        findViewById<TextView>(R.id.tvTwilioToken).text = Secrets.TWILIO_AUTH_TOKEN
        findViewById<TextView>(R.id.tvTwilioPhone).text = Secrets.TWILIO_PHONE_FROM

        // ── Session & API ───────────────────────────────────────
        findViewById<TextView>(R.id.tvApiUrl).text = Secrets.API_BASE_URL
        findViewById<TextView>(R.id.tvApiKey).text = Secrets.API_KEY
        findViewById<TextView>(R.id.tvJwtSecret).text = Secrets.JWT_SECRET

        // Read session token from SharedPreferences (stored in plaintext!)
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val sessionToken = prefs.getString(KEY_TOKEN, "No session found")
        findViewById<TextView>(R.id.tvSessionToken).text = sessionToken
        findViewById<TextView>(R.id.tvAdminUsername).text = Secrets.ADMIN_USERNAME
        findViewById<TextView>(R.id.tvAdminPassword).text = Secrets.ADMIN_PASSWORD

        // ── Database ────────────────────────────────────────────
        findViewById<TextView>(R.id.tvDbHost).text = Secrets.DB_HOST
        findViewById<TextView>(R.id.tvDbCredentials).text = "${Secrets.DB_USER} / ${Secrets.DB_PASS}"
        findViewById<TextView>(R.id.tvDbName).text = Secrets.DB_NAME

        // ── Integrations ────────────────────────────────────────
        findViewById<TextView>(R.id.tvGoogleOAuth).text = Secrets.GOOGLE_OAUTH_CLIENT_ID
        findViewById<TextView>(R.id.tvMapboxToken).text = Secrets.MAPBOX_TOKEN
        findViewById<TextView>(R.id.tvSentryDsn).text = Secrets.SENTRY_DSN

        // ── VULNERABILITY: Log sensitive data to Logcat ──────────
        Log.d(TAG, "Dashboard loaded for user: $username")
        Log.v(TAG, "Session token: $sessionToken")
        Log.d(TAG, "API Key: ${Secrets.API_KEY}")
        Log.i(TAG, "DB Connection: ${Secrets.DB_HOST} db=${Secrets.DB_NAME}")
        Log.w(TAG, "Stripe key in use: ${Secrets.STRIPE_SECRET_KEY}")

        // Also call the centralized leak function
        Secrets.logCredentials()

        // ── VULNERABILITY: MASVS-CRYPTO-1 — Use weak crypto ───────────
        val encryptedToken = CryptoHelper.encryptEcb(sessionToken ?: "no_token")
        val passwordHash = CryptoHelper.hashMd5(Secrets.ADMIN_PASSWORD)
        val integrityHash = CryptoHelper.hashSha1(sessionToken ?: "")
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
}
