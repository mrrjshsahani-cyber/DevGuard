package com.devguard.app.monitor

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.ConnectivityManager
import com.devguard.app.model.AlertSeverity
import com.devguard.app.model.MonitoredAppInfo
import com.devguard.app.model.TrustCategory
import com.devguard.app.model.UploadAlertEvent
import com.devguard.app.policy.DevSafePolicy

class UploadWatchdogEngine(
    private val context: Context,
    private val policy: DevSafePolicy
) {
    private val statsManager =
        context.getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager
    private val foregroundTracker = ForegroundTracker(context)

    private val baselineTxByUid = mutableMapOf<Int, Long>()
    private val windowTxByUid = mutableMapOf<Int, Long>()
    private val lastNsSecureAlertMs = mutableMapOf<Int, Long>()
    private val baselineStartMs = System.currentTimeMillis() - 10_000L

    data class ScanResult(
        val updatedApps: List<MonitoredAppInfo>,
        val newAlerts: List<UploadAlertEvent>,
        val blockedSetChanged: Boolean
    )

    fun scanTraffic(): ScanResult {
        val now = System.currentTimeMillis()
        val uidTotals = queryUidTrafficTotals(baselineStartMs, now)
        val userState = foregroundTracker.getCurrentState()
        val apps = policy.loadMonitoredApps()
        val config = policy.getConfig()
        val newAlerts = mutableListOf<UploadAlertEvent>()
        var blockedChanged = false

        val updatedApps = apps.map { app ->
            val totals = uidTotals[app.uid] ?: (0L to 0L)
            val currentTx = totals.first
            val currentRx = totals.second

            val previousTx = baselineTxByUid[app.uid]
            val deltaTx = if (previousTx == null) 0L else (currentTx - previousTx).coerceAtLeast(0L)
            baselineTxByUid[app.uid] = currentTx

            val accumulatedBurst = (windowTxByUid[app.uid] ?: 0L) + deltaTx
            windowTxByUid[app.uid] = accumulatedBurst

            val isUserUsingApp = app.packageName == userState.activeForegroundPackage ||
                app.packageName in userState.recentlyActivePackages

            if (app.category == TrustCategory.EMI_ADMIN_MONITOR_ONLY) {
                // NS Secure: कभी ब्लॉक नहीं होगा, लेकिन बैकग्राउंड गतिविधि पर तुरंत सूचना देगा
                val lastNotified = lastNsSecureAlertMs[app.uid] ?: 0L
                if (accumulatedBurst >= config.nsSecureBgAlertBytes && (now - lastNotified) >= 15_000L) {
                    val severity = when {
                        accumulatedBurst >= config.mediaAlertThresholdBytes -> AlertSeverity.MEDIA_UPLOAD_HIGH
                        accumulatedBurst >= 50L * 1024L -> AlertSeverity.TEXT_OR_METADATA_SPIKE
                        else -> AlertSeverity.INFO
                    }
                    val screenTag = if (!userState.isScreenUnlockedAndOn) "स्क्रीन बंद होने पर" else "बैकग्राउंड में"
                    val detail = when (severity) {
                        AlertSeverity.MEDIA_UPLOAD_HIGH -> "बड़ा डेटा/मीडिया संभावित (ब्लॉक नहीं किया गया)"
                        AlertSeverity.TEXT_OR_METADATA_SPIKE -> "टेक्स्ट/सिंक डेटा भेजा (ब्लॉक नहीं किया गया)"
                        AlertSeverity.INFO -> "बैकग्राउंड सर्वर गतिविधि (फोन लॉक से बचाने हेतु खुला रखा गया)"
                    }
                    newAlerts.add(
                        UploadAlertEvent(
                            packageName = app.packageName,
                            appName = app.appName,
                            uploadedBytes = accumulatedBurst,
                            severity = severity,
                            actionTaken = "$screenTag • $detail"
                        )
                    )
                    lastNsSecureAlertMs[app.uid] = now
                    windowTxByUid[app.uid] = 0L
                }
            } else if (app.category == TrustCategory.WATCHED_DEFAULT && accumulatedBurst > 0L) {
                // बाकी सामान्य ऐप्स: स्क्रीन पर खुले हैं तो छूट, बैकग्राउंड में डेटा भेजा तो तुरंत ब्लॉक
                if (!isUserUsingApp &&
                    config.autoBlockBackgroundApps &&
                    accumulatedBurst >= config.bgAutoBlockThresholdBytes
                ) {
                    if (policy.setAppBlocked(app.packageName, true)) {
                        blockedChanged = true
                        val screenTag = if (!userState.isScreenUnlockedAndOn) "स्क्रीन बंद होने पर" else "बैकग्राउंड में"
                        val severity = if (accumulatedBurst >= config.mediaAlertThresholdBytes) {
                            AlertSeverity.MEDIA_UPLOAD_HIGH
                        } else {
                            AlertSeverity.TEXT_OR_METADATA_SPIKE
                        }
                        newAlerts.add(
                            UploadAlertEvent(
                                packageName = app.packageName,
                                appName = app.appName,
                                uploadedBytes = accumulatedBurst,
                                severity = severity,
                                actionTaken = "$screenTag • Auto-Blocked (बैकग्राउंड डेटा रोका गया)"
                            )
                        )
                        windowTxByUid[app.uid] = 0L
                    }
                } else if (isUserUsingApp) {
                    windowTxByUid[app.uid] = 0L
                }
            } else if (app.category == TrustCategory.DEV_SAFE_BYPASS) {
                windowTxByUid[app.uid] = 0L
            }

            app.copy(
                sessionUploadBytes = currentTx,
                sessionDownloadBytes = currentRx,
                lastBurstUploadBytes = accumulatedBurst
            )
        }

        return ScanResult(updatedApps, newAlerts, blockedChanged)
    }

    @Suppress("DEPRECATION")
    private fun queryUidTrafficTotals(startMs: Long, endMs: Long): Map<Int, Pair<Long, Long>> {
        val result = mutableMapOf<Int, Pair<Long, Long>>()
        val types = listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)

        for (type in types) {
            var stats: NetworkStats? = null
            try {
                stats = statsManager.querySummary(type, null, startMs, endMs)
                val bucket = NetworkStats.Bucket()
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(bucket)
                    val prev = result[bucket.uid] ?: (0L to 0L)
                    result[bucket.uid] = (prev.first + bucket.txBytes) to (prev.second + bucket.rxBytes)
                }
            } catch (_: SecurityException) {
            } catch (_: Exception) {
            } finally {
                stats?.close()
            }
        }
        return result
    }
}
