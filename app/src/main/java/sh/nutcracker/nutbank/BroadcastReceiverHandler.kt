package sh.nutcracker.nutbank

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * VULNERABILITY: Exported BroadcastReceiver with no permission.
 * Any app can send intents to trigger this receiver.
 * nutcracker will flag this as an insecure exported component.
 */
class BroadcastReceiverHandler : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // Sensitive action triggered by any external app
        Log.d("BroadcastReceiverHandler", "Received action: ${intent.action}")
        Log.d("BroadcastReceiverHandler", "Data: ${intent.dataString}")
    }
}