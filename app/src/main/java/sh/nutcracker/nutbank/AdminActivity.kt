package sh.nutcracker.nutbank

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * VULNERABILITY: This activity is exported without any permission check.
 * Any app on the device can launch it directly, bypassing authentication.
 * nutcracker will flag this as an insecure exported component.
 */
class AdminActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val tv = TextView(this)
        tv.text = """
            [ADMIN PANEL - No auth required!]
            
            DB Host: ${Secrets.DB_HOST}
            DB User: ${Secrets.DB_USER}
            DB Pass: ${Secrets.DB_PASS}
            DB Name: ${Secrets.DB_NAME}
            
            AWS Key: ${Secrets.AWS_ACCESS_KEY}
            JWT Secret: ${Secrets.JWT_SECRET}
            
            This activity is accessible by any app
            because android:exported="true" with no permission.
        """.trimIndent()

        setContentView(tv)
    }
}