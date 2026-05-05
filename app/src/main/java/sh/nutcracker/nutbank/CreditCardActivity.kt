package sh.nutcracker.nutbank

import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * VULNERABILITY: This activity is exported without any permission check.
 * Any app on the device can launch it directly to view credit card details.
 * nutcracker will flag this as an insecure exported component exposing PII.
 */
class CreditCardActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 60, 40, 60)
            setBackgroundColor(0xFF0A0F1E.toInt())
        }

        // Title
        val title = TextView(this).apply {
            text = "💳 Card Details"
            setTextColor(0xFFFFFFFF.toInt())
            textSize = 24f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }
        root.addView(title)

        // Subtitle
        val subtitle = TextView(this).apply {
            text = "\nAll card data is exposed without authentication.\nAny app can launch this activity.\n"
            setTextColor(0xFF667788.toInt())
            textSize = 12f
        }
        root.addView(subtitle)

        // Card visual
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 28, 32, 28)
            setBackgroundColor(0xFF1A1A3E.toInt())
        }

        card.addView(TextView(this).apply {
            text = "NutBank"
            setTextColor(0xFFFFFFFF.toInt())
            textSize = 18f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        card.addView(TextView(this).apply {
            text = "\n${formatCardNumber(Secrets.ACCOUNT_NUMBER)}"
            setTextColor(0xFFFFFFFF.toInt())
            textSize = 22f
            letterSpacing = 0.1f
        })

        val detailsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 20, 0, 0)
        }

        val holderCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        holderCol.addView(TextView(this).apply {
            text = "CARDHOLDER"
            setTextColor(0xFF556688.toInt())
            textSize = 9f
        })
        holderCol.addView(TextView(this).apply {
            text = "ADMIN USER"
            setTextColor(0xFFFFFFFF.toInt())
            textSize = 13f
        })
        detailsRow.addView(holderCol)

        val expiryCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        expiryCol.addView(TextView(this).apply {
            text = "EXPIRES"
            setTextColor(0xFF556688.toInt())
            textSize = 9f
        })
        expiryCol.addView(TextView(this).apply {
            text = "12/28"
            setTextColor(0xFFFFFFFF.toInt())
            textSize = 13f
        })
        detailsRow.addView(expiryCol)

        card.addView(detailsRow)
        root.addView(card)

        // Spacer
        root.addView(TextView(this).apply { text = "\n" })

        // Sensitive data section
        val sectionTitle = TextView(this).apply {
            text = "🔒 Sensitive Account Data"
            setTextColor(0xFF8899BB.toInt())
            textSize = 13f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }
        root.addView(sectionTitle)

        val data = listOf(
            "Account Number" to Secrets.ACCOUNT_NUMBER,
            "Routing Number" to Secrets.ROUTING_NUMBER,
            "Account Token" to Secrets.ACCOUNT_TOKEN,
            "Stripe Key" to Secrets.STRIPE_SECRET_KEY,
            "CVV" to "837",
            "Card Type" to "Visa Platinum"
        )

        for ((label, value) in data) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 16, 0, 16)
            }

            row.addView(TextView(this).apply {
                text = label
                setTextColor(0xFF556688.toInt())
                textSize = 12f
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })

            row.addView(TextView(this).apply {
                text = value
                setTextColor(0xFFFF6B6B.toInt())
                textSize = 12f
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            })

            root.addView(row)

            // Divider
            root.addView(TextView(this).apply {
                text = "─".repeat(50)
                setTextColor(0xFF1A2235.toInt())
                textSize = 8f
            })
        }

        setContentView(root)
    }

    private fun formatCardNumber(number: String): String {
        return number.chunked(4).joinToString("  ")
    }
}