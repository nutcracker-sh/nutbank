package sh.nutcracker.nutbank

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log
import java.io.File
import java.io.FileWriter

/**
 * VULNERABILITY: MASVS-PLATFORM-2 — Insecure Data Storage.
 *
 * 1. Writes credentials to External Storage (world-readable)
 * 2. SQLite database with passwords stored in plaintext
 * 3. SharedPreferences with MODE_WORLD_READABLE (deprecated but illustrative)
 * 4. Session files in cache directory (accessible on rooted devices)
 * 5. No EncryptedSharedPreferences or SQLCipher
 *
 * nutcracker will detect insecure data storage patterns.
 */
object DataStoreManager {

    private const val TAG = "NutBankStorage"

    /**
     * VULNERABILITY: Writes sensitive data to external storage.
     * Files on external storage are readable by ANY app with READ_EXTERNAL_STORAGE.
     */
    fun writeToExternalStorage(context: Context) {
        try {
            // VULNERABILITY: External storage — world-readable
            val dir = File(context.getExternalFilesDir(null), "nutbank_data")
            dir.mkdirs()

            // Write credentials file
            val credsFile = File(dir, "credentials.txt")
            FileWriter(credsFile).use { writer ->
                writer.write("=== NutBank Credentials ===\n")
                writer.write("DB Host: ${Secrets.DB_HOST}\n")
                writer.write("DB User: ${Secrets.DB_USER}\n")
                writer.write("DB Pass: ${Secrets.DB_PASS}\n")
                writer.write("API Key: ${Secrets.API_KEY}\n")
                writer.write("JWT Secret: ${Secrets.JWT_SECRET}\n")
                writer.write("Stripe Key: ${Secrets.STRIPE_SECRET_KEY}\n")
                writer.write("AWS Key: ${Secrets.AWS_ACCESS_KEY}\n")
                writer.write("AWS Secret: ${Secrets.AWS_SECRET_KEY}\n")
                writer.write("Admin: ${Secrets.ADMIN_USERNAME}:${Secrets.ADMIN_PASSWORD}\n")
            }
            Log.d(TAG, "Credentials written to: ${credsFile.absolutePath}")

            // Write session token
            val sessionFile = File(dir, "session.txt")
            val prefs = context.getSharedPreferences("nutbank_session", Context.MODE_PRIVATE)
            val token = prefs.getString("session_token", "no_token")
            FileWriter(sessionFile).use { writer ->
                writer.write("Session Token: $token\n")
                writer.write("AES Key: ${Secrets.AES_KEY}\n")
                writer.write("AES IV: ${Secrets.AES_IV}\n")
            }
            Log.d(TAG, "Session written to: ${sessionFile.absolutePath}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to write external storage: ${e.message}")
        }
    }

    /**
     * VULNERABILITY: SQLite database with plaintext passwords.
     * No encryption (should use SQLCipher).
     */
    fun createInsecureDatabase(context: Context) {
        val dbHelper = object : SQLiteOpenHelper(context, "nutbank_users.db", null, 1) {
            override fun onCreate(db: SQLiteDatabase) {
                // VULNERABILITY: Passwords stored in plaintext
                db.execSQL("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username TEXT,
                        password TEXT,
                        api_key TEXT,
                        session_token TEXT,
                        credit_card TEXT
                    )
                """)

                // VULNERABILITY: Insert admin credentials in plaintext
                db.execSQL("INSERT INTO users VALUES (1, '${Secrets.ADMIN_USERNAME}', '${Secrets.ADMIN_PASSWORD}', '${Secrets.API_KEY}', '', '')")
                db.execSQL("INSERT INTO users VALUES (2, 'john_doe', 'Password1!', '', '', '4111111111111111')")
                db.execSQL("INSERT INTO users VALUES (3, 'jane_smith', 'Qwerty123', '', '', '5500000000000004')")

                Log.d(TAG, "Insecure database created with plaintext passwords")
            }

            override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {}
        }

        val db = dbHelper.writableDatabase

        // VULNERABILITY: Store current session token in database
        val prefs = context.getSharedPreferences("nutbank_session", Context.MODE_PRIVATE)
        val token = prefs.getString("session_token", "")
        db.execSQL("UPDATE users SET session_token = '$token' WHERE username = '${Secrets.ADMIN_USERNAME}'")

        Log.d(TAG, "Database path: ${db.path}")
        Log.v(TAG, "Token stored in SQLite: $token")

        db.close()
    }

    /**
     * VULNERABILITY: Writes to app cache (accessible via backup or root).
     */
    fun writeToCache(context: Context) {
        val cacheDir = context.cacheDir
        val file = File(cacheDir, "api_response_cache.json")
        file.writeText("""
            {
                "api_key": "${Secrets.API_KEY}",
                "jwt_secret": "${Secrets.JWT_SECRET}",
                "stripe_key": "${Secrets.STRIPE_SECRET_KEY}",
                "db_connection": "${Secrets.DB_USER}:${Secrets.DB_PASS}@${Secrets.DB_HOST}"
            }
        """.trimIndent())

        Log.d(TAG, "Cached credentials at: ${file.absolutePath}")
    }

    /**
     * VULNERABILITY: Stores data in SharedPreferences without encryption.
     * Should use EncryptedSharedPreferences from AndroidX Security.
     */
    fun storeInSharedPreferences(context: Context) {
        val prefs = context.getSharedPreferences("nutbank_sensitive", Context.MODE_PRIVATE)
        prefs.edit()
            .putString("credit_card_number", "4111111111111111")
            .putString("cvv", "123")
            .putString("expiry", "12/28")
            .putString("ssn", "123-45-6789")
            .putString("aws_secret", Secrets.AWS_SECRET_KEY)
            .putString("stripe_key", Secrets.STRIPE_SECRET_KEY)
            .putString("encryption_key", Secrets.AES_KEY)
            .putString("jwt_secret", Secrets.JWT_SECRET)
            .apply()

        Log.d(TAG, "Sensitive data stored in plaintext SharedPreferences")
    }
}