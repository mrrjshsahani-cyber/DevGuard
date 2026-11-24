package com.devguard.app.vpn

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.devguard.app.policy.DevSafePolicy
import java.io.FileInputStream

class SelectiveBlackholeVpnService : VpnService() {

    companion object {
        const val ACTION_START_OR_RELOAD = "com.devguard.app.VPN_RELOAD"
        const val ACTION_STOP = "com.devguard.app.VPN_STOP"
        @Volatile
        var isVpnRunning: Boolean = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var drainThread: Thread? = null
    @Volatile
    private var keepDraining = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            teardownTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        rebuildTunnel()
        return START_STICKY
    }

    private fun rebuildTunnel() {
        teardownTunnel()

        val policy = DevSafePolicy(this)
        val blocked = policy.getBlockedPackages().filterNot { policy.isNonBlockable(it) }

        val builder = Builder()
            .setSession("DevGuard Selective Firewall")
            .addAddress("10.8.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:1:fd00::2", 128)
            .addRoute("::", 0)

        if (blocked.isEmpty()) {
            // कोई ऐप ब्लॉक न होने पर केवल अपना ऑफलाइन ऐप टनल में रखकर बाकी पूरा फोन खुला रखें
            try {
                builder.addAllowedApplication(packageName)
            } catch (_: PackageManager.NameNotFoundException) {
            }
        } else {
            for (pkg in blocked) {
                try {
                    builder.addAllowedApplication(pkg)
                } catch (_: PackageManager.NameNotFoundException) {
                }
            }
        }

        vpnInterface = builder.establish() ?: return
        isVpnRunning = true
        keepDraining = true

        drainThread = Thread {
            val fd = vpnInterface?.fileDescriptor ?: return@Thread
            val input = FileInputStream(fd)
            val buffer = ByteArray(32767)
            try {
                while (keepDraining && !Thread.currentThread().isInterrupted) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    // केवल ब्लॉक किए गए ऐप्स का सारा ट्रैफिक यहीं ड्रॉप हो जाता है
                }
            } catch (_: Exception) {
            }
        }.apply { start() }
    }

    private fun teardownTunnel() {
        isVpnRunning = false
        keepDraining = false
        drainThread?.interrupt()
        drainThread = null
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    override fun onDestroy() {
        teardownTunnel()
        super.onDestroy()
    }
}
