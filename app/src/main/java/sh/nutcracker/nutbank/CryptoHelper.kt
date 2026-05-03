package sh.nutcracker.nutbank

import android.util.Base64
import android.util.Log
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * VULNERABILITY: MASVS-CRYPTO-1 — Weak Cryptography.
 *
 * 1. AES/ECB mode — no IV, identical plaintext = identical ciphertext
 * 2. Hardcoded key and IV in Secrets.kt
 * 3. MD5 for password hashing (collision-prone, broken)
 * 4. SHA-1 for integrity (deprecated, collision attacks known)
 * 5. No key derivation function (PBKDF2 missing) — raw key from string
 * 6. Key is only 16 bytes (128-bit) when 256-bit should be used
 *
 * nutcracker will detect weak crypto algorithms and hardcoded keys.
 */
object CryptoHelper {

    private const val TAG = "NutBankCrypto"

    /**
     * VULNERABILITY: AES/ECB — Electronic Codebook mode.
     * ECB encrypts each block independently, revealing patterns.
     * No IV is needed (and shouldn't be), making it deterministic.
     */
    fun encryptEcb(plaintext: String): String {
        Log.d(TAG, "Encrypting with AES/ECB (INSECURE!)")
        Log.v(TAG, "Key: ${Secrets.AES_KEY}")

        val keySpec = SecretKeySpec(Secrets.AES_KEY.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")  // VULNERABILITY: ECB mode
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)

        val encrypted = cipher.doFinal(plaintext.toByteArray())
        val result = Base64.encodeToString(encrypted, Base64.NO_WRAP)

        Log.d(TAG, "ECB encrypted: $result")
        return result
    }

    /**
     * VULNERABILITY: AES/CBC with hardcoded IV.
     * The IV should be random per encryption, but it's static.
     * Same plaintext + same key + same IV = same ciphertext every time.
     */
    fun encryptCbc(plaintext: String): String {
        Log.d(TAG, "Encrypting with AES/CBC (hardcoded IV!)")
        Log.v(TAG, "Key: ${Secrets.AES_KEY} IV: ${Secrets.AES_IV}")

        val keySpec = SecretKeySpec(Secrets.AES_KEY.toByteArray(), "AES")
        val ivSpec = IvParameterSpec(Secrets.AES_IV.toByteArray())  // VULNERABILITY: Hardcoded IV

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

        val encrypted = cipher.doFinal(plaintext.toByteArray())
        val result = Base64.encodeToString(encrypted, Base64.NO_WRAP)

        Log.d(TAG, "CBC encrypted: $result")
        return result
    }

    /**
     * Decrypt with AES/CBC using the hardcoded IV.
     */
    fun decryptCbc(ciphertext: String): String {
        val keySpec = SecretKeySpec(Secrets.AES_KEY.toByteArray(), "AES")
        val ivSpec = IvParameterSpec(Secrets.AES_IV.toByteArray())

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

        val decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP))
        return String(decrypted)
    }

    /**
     * VULNERABILITY: MD5 hashing — cryptographically broken.
     * Should use bcrypt, scrypt, or Argon2 for passwords.
     */
    fun hashMd5(input: String): String {
        Log.d(TAG, "Hashing with MD5 (BROKEN!)")

        val md = MessageDigest.getInstance("MD5")  // VULNERABILITY: MD5 is broken
        val digest = md.digest(input.toByteArray())
        val result = digest.joinToString("") { "%02x".format(it) }

        Log.v(TAG, "MD5 hash: $result")
        return result
    }

    /**
     * VULNERABILITY: SHA-1 hashing — deprecated and collision-prone.
     * Should use SHA-256 or SHA-3 minimum.
     */
    fun hashSha1(input: String): String {
        Log.d(TAG, "Hashing with SHA-1 (DEPRECATED!)")

        val md = MessageDigest.getInstance("SHA-1")  // VULNERABILITY: SHA-1 deprecated
        val digest = md.digest(input.toByteArray())
        val result = digest.joinToString("") { "%02x".format(it) }

        Log.v(TAG, "SHA-1 hash: $result")
        return result
    }

    /**
     * VULNERABILITY: "Encrypts" a password by just encoding it in Base64.
     * This is encoding, not encryption — trivially reversible.
     */
    fun obfuscatePassword(password: String): String {
        Log.d(TAG, "Obfuscating password (just Base64 — NOT encryption!)")
        val result = Base64.encodeToString(password.toByteArray(), Base64.NO_WRAP)
        Log.v(TAG, "Obfuscated: $result")
        return result
    }

    /**
     * VULNERABILITY: Generates a "random" token using timestamp.
     * Predictable — should use SecureRandom with sufficient entropy.
     */
    fun generateWeakToken(): String {
        val token = "nb_${System.currentTimeMillis()}_${Secrets.API_KEY.take(8)}"
        Log.d(TAG, "Generated weak token: $token")
        return token
    }
}