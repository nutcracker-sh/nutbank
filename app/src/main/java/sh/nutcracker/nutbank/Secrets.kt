package sh.nutcracker.nutbank

import android.util.Base64

/**
 * VULNERABILITY: Centralized secrets object — all hardcoded in plaintext.
 * In a real app these would be in secure storage, NDK, or fetched from a vault.
 * nutcracker will scan and extract all of these.
 */
object Secrets {

    // ── Cloud Services ──────────────────────────────────────────
    const val AWS_ACCESS_KEY    = "AKIAIOSFODNN7EXAMPLE"
    const val AWS_SECRET_KEY    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    const val AWS_REGION        = "us-east-1"
    const val AWS_S3_BUCKET     = "nutbank-customer-docs-insecure"

    // ── Firebase ────────────────────────────────────────────────
    const val FIREBASE_API_KEY  = "AIzaSyD-FAKE-KEY-nutcracker-demo-1234567"
    const val FIREBASE_PROJECT  = "nutbank-demo-prod"
    const val FIREBASE_DB_URL   = "https://nutbank-demo-prod.firebaseio.com"

    // ── Payment Gateway ─────────────────────────────────────────
    const val STRIPE_SECRET_KEY = "sk_live_FAKE_nutcracker_demo_key_123456789"
    const val STRIPE_WEBHOOK_SECRET = "whsec_fake_stripe_webhook_nutcracker"

    // ── Email / Notifications ───────────────────────────────────
    const val SENDGRID_API_KEY  = "SG.FAKE_nutcracker_demo.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    const val TWILIO_ACCOUNT_SID = "ACfake_nutcracker_twilio_sid_12345"
    const val TWILIO_AUTH_TOKEN = "fake_nutcracker_demo_twilio_token_abc123"
    const val TWILIO_PHONE_FROM = "+15551234567"

    // ── API Configuration ───────────────────────────────────────
    const val API_BASE_URL      = "http://api.nutbank-demo.internal/v1"
    const val API_KEY           = "nb_live_api_key_abc123xyz789_demo_nutcracker"
    const val ADMIN_USERNAME    = "admin"
    const val ADMIN_PASSWORD    = "P@ssw0rd123!"
    const val JWT_SECRET        = "super_secret_jwt_signing_key_nutcracker_demo"

    // ── Banking / Account ───────────────────────────────────────
    const val CARD_PIN          = "1234"
    const val ACCOUNT_NUMBER    = "4821983201"
    const val ROUTING_NUMBER    = "021000021"
    const val ACCOUNT_TOKEN     = "sk_live_FAKE_demo_123"

    // ── Database ────────────────────────────────────────────────
    const val DB_HOST           = "db.internal:3306"
    const val DB_USER           = "root"
    const val DB_PASS           = "nutcracker_demo_pass"
    const val DB_NAME           = "nutbank_prod"

    // ── Encryption (insecure) ───────────────────────────────────
    const val AES_KEY           = "ThisIsA16ByteKey"  // exactly 16 chars — weak!
    const val AES_IV            = "1234567890123456"

    // ── Third-party integrations ────────────────────────────────
    const val GOOGLE_OAUTH_CLIENT_ID = "123456789-fake.apps.googleusercontent.com"
    const val MAPBOX_TOKEN      = "pk.eyJ1IjoibnV0YmFuayIsImEiOiJmYWtlX21hcGJveCJ9.fake"
    const val SENTRY_DSN        = "https://fake_sentry_key@sentry.io/12345"

    /**
     * Generates a fake JWT-like token using the hardcoded secret.
     * VULNERABILITY: JWT signing key is embedded in the app.
     */
    fun generateSessionToken(username: String): String {
        val header = Base64.encodeToString(
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".toByteArray(),
            Base64.NO_WRAP
        )
        val payload = Base64.encodeToString(
            "{\"sub\":\"$username\",\"role\":\"admin\",\"iat\":${System.currentTimeMillis() / 1000}}".toByteArray(),
            Base64.NO_WRAP
        )
        // In a real attack, the attacker can forge tokens since JWT_SECRET is known
        val signature = Base64.encodeToString(
            JWT_SECRET.toByteArray(),
            Base64.NO_WRAP
        )
        return "$header.$payload.$signature"
    }

    /**
     * VULNERABILITY: Logs sensitive credentials to Logcat.
     * Developers sometimes leave this kind of debug logging in production.
     */
    fun logCredentials() {
        android.util.Log.v("NutBankAPI", "API Key: $API_KEY")
        android.util.Log.d("NutBankAPI", "Connecting to: $API_BASE_URL")
        android.util.Log.d("NutBankDB", "DB: $DB_HOST user=$DB_USER pass=$DB_PASS")
        android.util.Log.i("NutBankAuth", "JWT Secret: $JWT_SECRET")
        android.util.Log.w("NutBankStripe", "Stripe Key: $STRIPE_SECRET_KEY")
    }
}