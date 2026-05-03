package sh.nutcracker.nutbank

import android.util.Log
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * VULNERABILITY: Custom SSL implementation that trusts ALL certificates.
 * This completely defeats SSL/TLS pinning — MITM attacks are trivial.
 *
 * MASVS-NETWORK: No certificate pinning, no hostname verification.
 * nutcracker will flag this as a critical network security issue.
 */
object NetworkClient {

    private const val TAG = "NutBankNetwork"

    /**
     * VULNERABILITY: TrustManager that accepts every certificate.
     * An attacker can intercept all HTTPS traffic with any self-signed cert.
     */
    fun createInsecureTrustManager(): X509TrustManager {
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                // VULNERABILITY: Accepts everything — no validation
            }
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                // VULNERABILITY: Accepts everything — no validation
                Log.d(TAG, "Accepting server cert blindly: ${chain?.firstOrNull()?.subjectDN}")
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
    }

    /**
     * VULNERABILITY: HostnameVerifier that accepts any hostname.
     * Even if cert says "attacker.com", it will be accepted for "api.nutbank.com".
     */
    fun createInsecureHostnameVerifier(): HostnameVerifier {
        return HostnameVerifier { _, _ ->
            // VULNERABILITY: Always returns true — no hostname check
            true
        }
    }

    /**
     * Creates an SSL context that trusts all certificates.
     * Used throughout the app for "simplicity" (a terrible reason).
     */
    fun createInsecureSslContext(): SSLContext {
        val trustManager = createInsecureTrustManager()
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), SecureRandom())
        return sslContext
    }

    /**
     * VULNERABILITY: Makes an HTTPS request with insecure SSL settings.
     * All data (including auth tokens) can be intercepted via MITM.
     */
    fun makeInsecureRequest(url: String, token: String): String {
        Log.d(TAG, "Making insecure request to: $url")
        Log.v(TAG, "Using token: $token")

        try {
            val urlConnection = java.net.URL(url).openConnection() as javax.net.ssl.HttpsURLConnection
            urlConnection.sslSocketFactory = createInsecureSslContext().socketFactory
            urlConnection.hostnameVerifier = createInsecureHostnameVerifier()
            urlConnection.setRequestProperty("Authorization", "Bearer $token")
            urlConnection.setRequestProperty("X-Api-Key", Secrets.API_KEY)

            // VULNERABILITY: Sends all credentials over a connection that accepts any cert
            Log.i(TAG, "Sending API_KEY=${Secrets.API_KEY} to $url")

            val response = urlConnection.inputStream.bufferedReader().readText()
            Log.d(TAG, "Response: $response")
            return response
        } catch (e: Exception) {
            Log.e(TAG, "Request failed (but SSL was bypassed): ${e.message}")
            return "Error: ${e.message}"
        }
    }

    /**
     * VULNERABILITY: Disables certificate pinning entirely.
     * No pins are configured — any valid CA cert will be accepted.
     */
    fun disableCertificatePinning() {
        Log.d(TAG, "Certificate pinning disabled — using trust-all manager")
    }
}