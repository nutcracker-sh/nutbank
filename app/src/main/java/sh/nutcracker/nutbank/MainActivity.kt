/**
 * NutBank — Intentionally vulnerable Android application for security testing.
 *
 * @author Carlos Ganoza (@drneox) — carlos.ganoza@owasp.org
 * @see nutcracker.sh
 * @version 1.0
 */
package sh.nutcracker.nutbank

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import android.text.Html
import android.text.method.LinkMovementMethod
import com.scottyab.rootbeer.RootBeer
import java.io.File
import java.net.Socket

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "NutBankLogin"
        private const val PREFS_NAME = "nutbank_session"
        private const val KEY_TOKEN = "session_token"
        private const val KEY_USERNAME = "username"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val etUser   = findViewById<EditText>(R.id.etUsername)
        val etPass   = findViewById<EditText>(R.id.etPassword)

        // Footer link to nutcracker.sh
        val tvFooter = findViewById<TextView>(R.id.tvFooter)
        tvFooter.text = Html.fromHtml("🔒 Powered by <a href=\"https://nutcracker.sh\">nutcracker.sh</a>")
        tvFooter.movementMethod = LinkMovementMethod.getInstance()

        // RASP check — show dialog but keep UI functional (bypass demo)
        val violations = runRaspChecks()
        if (violations.isNotEmpty()) {
            showBlockingDialog(violations)
        }

        btnLogin.setOnClickListener {
            val user = etUser.text.toString()
            val pass = etPass.text.toString()
            if (user.isEmpty() || pass.isEmpty()) {
                Toast.makeText(this, "Please enter your credentials", Toast.LENGTH_SHORT).show()
            } else if (user == Secrets.ADMIN_USERNAME && pass == Secrets.ADMIN_PASSWORD) {

                // ── VULNERABILITY: Store session in SharedPreferences (plaintext!) ──
                val token = Secrets.generateSessionToken(user)
                val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                prefs.edit()
                    .putString(KEY_TOKEN, token)
                    .putString(KEY_USERNAME, user)
                    .apply()

                // ── VULNERABILITY: Log credentials to Logcat ──
                Log.d(TAG, "Login success for user: $user")
                Log.v(TAG, "Generated token: $token")
                Log.d(TAG, "Auth against: ${Secrets.API_BASE_URL}/auth")

                val intent = Intent(this, DashboardActivity::class.java)
                intent.putExtra("username", user)
                startActivity(intent)
            } else {
                Toast.makeText(this, "Invalid credentials", Toast.LENGTH_SHORT).show()
                // VULNERABILITY: Log failed attempts with the attempted password
                Log.w(TAG, "Failed login: user=$user pass=$pass")
            }
        }
    }

    private fun showBlockingDialog(violations: List<String>) {
        val message = buildString {
            appendLine("This app cannot run in an unsecured environment.\n")
            appendLine("Threats detected:\n")
            violations.forEach { appendLine("  • $it") }
            appendLine("\nPlease use an unmodified device.")
        }

        AlertDialog.Builder(this)
            .setTitle("⛔ Security Check Failed")
            .setMessage(message)
            .setCancelable(false)
            .setNegativeButton("Close App") { _, _ -> finishAffinity() }
            .show()
    }

    private fun runRaspChecks(): List<String> {
        val violations = mutableListOf<String>()

        val rootBeer = RootBeer(this)
        if (rootBeer.isRooted) {
            violations.add("Root access detected (RootBeer)")
            if (rootBeer.checkForSuBinary())          violations.add("  → su binary present")
            if (rootBeer.detectRootManagementApps())  violations.add("  → Root management app installed")
            if (rootBeer.detectTestKeys())             violations.add("  → Test-keys build signature")
            if (rootBeer.checkForRWPaths())            violations.add("  → System partitions are writable")
        }

        if (detectFrida())    violations.add("Dynamic instrumentation detected (Frida)")
        if (detectEmulator()) violations.add("Emulator environment detected")

        return violations
    }

    private fun detectFrida(): Boolean {
        try { Socket("127.0.0.1", 27042).close(); return true } catch (_: Exception) {}
        try {
            File("/proc").listFiles()?.forEach { pid ->
                val cmd = File(pid, "cmdline")
                if (cmd.exists()) {
                    val text = cmd.readText().replace('\u0000', ' ').lowercase()
                    if (listOf("frida-server","frida-agent","frida-gadget").any { text.contains(it) }) return true
                }
            }
        } catch (_: Exception) {}
        try {
            val maps = File("/proc/self/maps")
            if (maps.exists() && maps.readText().lowercase().let {
                it.contains("frida") || it.contains("gum-js-loop")
            }) return true
        } catch (_: Exception) {}
        return false
    }

    private fun detectEmulator(): Boolean {
        val fields = listOf(
            android.os.Build.FINGERPRINT, android.os.Build.MODEL,
            android.os.Build.MANUFACTURER, android.os.Build.PRODUCT,
            android.os.Build.HARDWARE, android.os.Build.BRAND
        ).map { it.lowercase() }
        val sigs = listOf("generic","unknown","google_sdk","emulator","genymotion","sdk_gphone")
        if (sigs.any { s -> fields.any { f -> f.contains(s) } }) return true
        return listOf("/dev/socket/qemud","/dev/qemu_pipe","/sys/qemu_trace").any { File(it).exists() }
    }
}