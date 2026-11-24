package com.devguard.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.devguard.app.MainActivity
import com.devguard.app.model.AlertSeverity
import com.devguard.app.model.MonitoredAppInfo
import com.devguard.app.model.UploadAlertEvent
import com.devguard.app.monitor.UploadWatchdogEngine
import com.devguard.app.policy.DevSafePolicy
import com.devguard.app.vpn.SelectiveBlackholeVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class SecurityGuardService : Service() {

    companion object {
        const val ACTION_START = "com.devguard.app.START_GUARD"
        const val ACTION_STOP = "com.devguard.app.STOP_GUARD"
        const val ACTION_REFRESH = "com.devguard.app.REFRESH_GUARD"
        const val ACTION_UNBLOCK_APP = "com.devguard.app.UNBLOCK_APP"
        const val EXTRA_PACKAGE = "extra_package"
        const val EXTRA_NOTIF_ID = "extra_notif_id"

        private const val CH_STATUS = "devguard_status"
        private const val CH_ALERTS = "devguard_alerts"
        private const val FG_NOTIF_ID = 1001

        private val _isRunning = MutableStateFlow(false)
        val isRunning = _isRunning.asStateFlow()

        private val _appsState = MutableStateFlow<List<MonitoredAppInfo>>(emptyList())
        val appsState = _appsState.asStateFlow()

        private val _alertsState = MutableStateFlow<List<UploadAlertEvent>>(emptyList())
        val alertsState = _alertsState.asStateFlow()
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var monitorJob: Job? = null
    private lateinit var policy: DevSafePolicy
    private lateinit var watchdog: UploadWatchdogEngine

    // नया ऐप डाउनलोड/इंस्टॉल होते ही तुरंत निगरानी में जोड़ने के लिए रिसीवर
    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val action = intent?.action ?: return
            if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REMOVED) {
                val pkg = intent.data?.schemeSpecificPart
                val isUpdate = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                serviceScope.launch {
                    runSingleScan()
                    if (action == Intent.ACTION_PACKAGE_ADDED && !isUpdate && !pkg.isNullOrBlank()) {
                        val addedApp = _appsState.value.firstOrNull { it.packageName == pkg }
                        if (addedApp != null) {
                            pushNewAppNotification(addedApp)
                        }
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        policy = DevSafePolicy(this)
        watchdog = UploadWatchdogEngine(this, policy)
        createChannels()

        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(
            this,
            packageReceiver,
            filter,
            ContextCompat.RECEIVER_EXPORTED
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopGuard()
                return START_NOT_STICKY
            }
            ACTION_REFRESH -> {
                serviceScope.launch { runSingleScan() }
                return START_STICKY
            }
            ACTION_UNBLOCK_APP -> {
                ensureForeground()
                val pkg = intent.getStringExtra(EXTRA_PACKAGE)
                val notifId = intent.getIntExtra(EXTRA_NOTIF_ID, -1)
                if (!pkg.isNullOrBlank()) {
                    policy.setAppBlocked(pkg, false)
                    reloadVpn()
                    serviceScope.launch { runSingleScan() }
                }
                if (notifId != -1) {
                    (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).cancel(notifId)
                }
                return START_STICKY
            }
            else -> startGuard()
        }
        return START_STICKY
    }

    private fun ensureForeground() {
        val notification = buildStatusNotification("NS Secure व सभी यूजर/नए ऐप्स की निगरानी चालू")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(FG_NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(FG_NOTIF_ID, notification)
        }
    }

    private fun startGuard() {
        ensureForeground()
        _isRunning.value = true
        if (monitorJob?.isActive == true) return

        monitorJob = serviceScope.launch {
            while (isActive) {
                runSingleScan()
                delay(4_000L)
            }
        }
    }

    private fun runSingleScan() {
        val scan = watchdog.scanTraffic()
        _appsState.value = scan.updatedApps
        if (scan.newAlerts.isNotEmpty()) {
            _alertsState.value = (scan.newAlerts + _alertsState.value).take(60)
            scan.newAlerts.forEach { pushAlertNotification(it) }
        }
        if (scan.blockedSetChanged) reloadVpn()
    }

    private fun reloadVpn() {
        if (SelectiveBlackholeVpnService.isVpnRunning) {
            try {
                startService(Intent(this, SelectiveBlackholeVpnService::class.java).apply {
                    action = SelectiveBlackholeVpnService.ACTION_START_OR_RELOAD
                })
            } catch (_: Exception) {
            }
        }
    }

    private fun stopGuard() {
        _isRunning.value = false
        monitorJob?.cancel()
        try {
            stopService(Intent(this, SelectiveBlackholeVpnService::class.java).apply {
                action = SelectiveBlackholeVpnService.ACTION_STOP
            })
        } catch (_: Exception) {
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun pushNewAppNotification(app: MonitoredAppInfo) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val notifId = (app.packageName.hashCode() and 0x7FFF) + 5000
        val notif = NotificationCompat.Builder(this, CH_ALERTS)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("नया ऐप निगरानी में जोड़ा गया")
            .setContentText("${app.appName} अब DevGuard की निगरानी में है।")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        nm.notify(notifId, notif)
    }

    private fun pushAlertNotification(alert: UploadAlertEvent) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val kb = (alert.uploadedBytes / 1024L).coerceAtLeast(1L)
        val notifId = ((alert.id % 100_000).toInt()) + 2000

        val openAppIntent = PendingIntent.getActivity(
            this,
            notifId,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = when {
            alert.actionTaken.contains("Auto-Blocked") -> "ब्लॉक किया गया: ${alert.appName}"
            alert.severity == AlertSeverity.MEDIA_UPLOAD_HIGH -> "बड़ा अपलोड अलर्ट: ${alert.appName}"
            else -> "${alert.appName} गतिविधि सूचना"
        }
        val body = "$kb KB डेटा बाहर गया • ${alert.actionTaken}"

        val builder = NotificationCompat.Builder(this, CH_ALERTS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(openAppIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)

        if (alert.actionTaken.contains("Auto-Blocked")) {
            val unblockIntent = Intent(this, SecurityGuardService::class.java).apply {
                action = ACTION_UNBLOCK_APP
                putExtra(EXTRA_PACKAGE, alert.packageName)
                putExtra(EXTRA_NOTIF_ID, notifId)
            }
            val pendingIntent = PendingIntent.getForegroundService(
                this,
                notifId,
                unblockIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(android.R.drawable.ic_menu_revert, "यह मैं हूँ (Unblock करें)", pendingIntent)
        }

        nm.notify(notifId, builder.build())
    }

    private fun buildStatusNotification(text: String): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CH_STATUS)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("DevGuard सक्रिय है")
            .setContentText(text)
            .setContentIntent(openAppIntent)
            .setOngoing(true)
            .build()
    }

    private fun createChannels() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CH_STATUS, "Security Guard Status", NotificationManager.IMPORTANCE_LOW)
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_ALERTS, "Security Activity Alerts", NotificationManager.IMPORTANCE_HIGH)
        )
    }

    override fun onDestroy() {
        _isRunning.value = false
        try {
            unregisterReceiver(packageReceiver)
        } catch (_: Exception) {
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
