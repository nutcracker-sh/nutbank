package sh.nutcracker.nutbank

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat

/**
 * VULNERABILITY: MASVS-AUTH-2 — Weak Local Authentication.
 *
 * 1. setDeviceCredentialAllowed(true) allows fallback to device PIN/pattern,
 *    bypassing biometric entirely.
 * 2. After "authentication", stores the JWT token in SharedPreferences plaintext.
 * 3. Does not use EncryptedSharedPreferences or Android Keystore.
 * 4. No cryptographic validation that biometric actually occurred.
 *
 * nutcracker will flag weak biometric implementation.
 */
class BiometricAuthActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "NutBankBiometric"
        private const val PREFS_NAME = "nutbank_session"
        private const val KEY_TOKEN = "session_token"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val tv = TextView(this)
        tv.text = "Biometric Authentication\nTap to authenticate with biometric..."
        setContentView(tv)

        performWeakBiometricAuth()
    }

    private fun performWeakBiometricAuth() {
        val executor = ContextCompat.getMainExecutor(this)

        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.d(TAG, "Biometric auth succeeded")

                    // VULNERABILITY: After biometric, store token in plaintext SharedPreferences
                    val token = Secrets.generateSessionToken("admin")
                    val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                    prefs.edit()
                        .putString(KEY_TOKEN, token)
                        .putString("biometric_verified", "true")  // trivially spoofable
                        .apply()

                    // VULNERABILITY: Log the token after "secure" auth
                    Log.d(TAG, "Token after biometric: $token")
                    Log.v(TAG, "JWT_SECRET used: ${Secrets.JWT_SECRET}")
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // VULNERABILITY: Even on failure, we still grant limited access
                    Log.w(TAG, "Biometric failed but allowing fallback access")
                    val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                    prefs.edit().putString("biometric_verified", "failed_but_ok").apply()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.e(TAG, "Biometric error: $errString — falling back to device credential")
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("NutBank Authentication")
            .setSubtitle("Verify your identity to access account")
            // VULNERABILITY: Allows device credential fallback (PIN/pattern/password)
            // This means biometric can be completely bypassed
            .setDeviceCredentialAllowed(true)
            // No setAllowedAuthenticators — accepts any biometric, even weak ones
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}