package sh.nutcracker.nutbank

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri

/**
 * VULNERABILITY: ContentProvider exported with no permission.
 * Any app can query sensitive data from this provider.
 * nutcracker will flag this as an insecure exported component.
 */
class ContentProviderHandler : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri, projection: Array<String>?, selection: String?,
        selectionArgs: Array<String>?, sortOrder: String?
    ): Cursor {
        // Returns fake sensitive data to any app that queries
        val cursor = MatrixCursor(arrayOf("key", "value"))
        cursor.addRow(arrayOf("internal_token", "demo_secret_token_nutcracker_12345"))
        cursor.addRow(arrayOf("user_session", "session_abc123_demo_nutcracker"))
        cursor.addRow(arrayOf("api_key", "demo_api_key_nutcracker_xyz789"))
        return cursor
    }

    override fun getType(uri: Uri): String = "vnd.android.cursor.dir/vnd.sh.nutcracker.demo"
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?) = 0
}
