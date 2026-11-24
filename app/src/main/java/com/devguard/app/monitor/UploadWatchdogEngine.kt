package com.devguard.app.monitor

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import com.devguard.app.model.AlertSeverity
import com.devguard.app.model.DataActivityType
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
    private val baselineRxByUid = mutableMapOf<Int, Long>()
    private val windowTxByUid = mutableMapOf<Int, Long>()
    private val windowRxByUid = mutableMapOf<Int, Long>()
    private val lastActivityByUid = mutableMapOf<Int, DataActivityType>()
    private val lastMonitorAlertMs = mutableMapOf<Int, Long>()
    private val baselineStartMs = System.currentTimeMillis() - 10_000L
    private var isBaselineInitialized = false

    data class ScanResult(
        val updatedApps: List<MonitoredAppInfo>,
        val newAlerts: List<UploadAlertEvent>,
        val blockedSetChanged: Boolean
    )

    fun scanTraffic(): ScanResult {
        val apps = policy.loadMonitoredApps()
        if (!hasUsageStatsPermission()) {
            return ScanResult(apps, emptyList(), false)
        }

        val now = System.currentTimeMillis()
        val uidTotals = queryUidTrafficTotals(baselineStartMs, now) ?: return ScanResult(apps, emptyList(), false)
        val userState = foregroundTracker.getCurrentState()
        val config = policy.getConfig()
        val newAlerts = mutableListOf<UploadAlertEvent>()
        var blockedChanged = false

        // पहली रीडिंग केवल शुरुआती बेसलाइन के लिए लें, ताकि पुराने डेटा से कोई ऐप ब्लॉक न हो
        if (!isBaselineInitialized) {
            val initializedApps = apps.map { app ->
                val totals = uidTotals[app.uid] ?: (0L to 0L)
                baselineTxByUid[app.uid] = totals.first
                baselineRxByUid[app.uid] = totals.second
                windowTxByUid[app.uid] = 0L
                windowRxByUid[app.uid] = 0L
                val initialType = TrafficClassifier.classify(totals.first, totals.second)
                lastActivityByUid[app.uid] = initialType
                app.copy(
                    sessionUploadBytes = totals.first,
                    sessionDownloadBytes = totals.second,
                    lastBurstUploadBytes = 0L,
                    lastActivityType = initialType
                )
            }
            isBaselineInitialized = true
            return ScanResult(initializedApps, emptyList(), false)
        }

        val updatedApps = apps.map { app ->
            val totals = uidTotals[app.uid] ?: (0L to 0L)
            val currentTx = totals.first
            val currentRx = totals.second

            val prevTx = baselineTxByUid[app.uid]
            val prevRx = baselineRxByUid[app.uid]
            val deltaTx = if (prevTx == null) 0L else (currentTx - prevTx).coerceAtLeast(0L)
            val deltaRx = if (prevRx == null) 0L else (currentRx - prevRx).coerceAtLeast(0L)
            baselineTxByUid[app.uid] = currentTx
            baselineRxByUid[app.uid] = currentRx

            val burstTx = (windowTxByUid[app.uid] ?: 0L) + deltaTx
            val burstRx = (windowRxByUid[app.uid] ?: 0L) + deltaRx
            windowTxByUid[app.uid] = burstTx
            windowRxByUid[app.uid] = burstRx

            val detectedType = if (burstTx > 0L || burstRx > 0L) {
                TrafficClassifier.classify(burstTx, burstRx).also {
                    lastActivityByUid[app.uid] = it
                }
            } else {
                lastActivityByUid[app.uid] ?: DataActivityType.IDLE
            }

            val isUserUsingApp = app.packageName == userState.activeForegroundPackage ||
                app.packageName in userState.recentlyActivePackages

            val severity = when (detectedType) {
                DataActivityType.LARGE_VIDEO_OR_BACKUP,
                DataActivityType.LARGE_AUDIO_OR_HEAVY_MEDIA,
                DataActivityType.PHOTO_OR_SMALL_AUDIO -> AlertSeverity.MEDIA_UPLOAD_HIGH
                DataActivityType.TEXT_OR_API_SYNC -> AlertSeverity.TEXT_OR_METADATA_SPIKE
                else -> AlertSeverity.INFO
            }

            when (app.category) {
                TrustCategory.EMI_ADMIN_MONITOR_ONLY -> {
                    val lastNotified = lastMonitorAlertMs[app.uid] ?: 0L
                    if (burstTx >= config.nsSecureBgAlertBytes && (now - lastNotified) >= 15_000L) {
                        val screenTag = if (!userState.isScreenUnlockedAndOn) "स्क्रीन बंद होने पर" else "बैकग्राउंड में"
                        newAlerts.add(
                            UploadAlertEvent(
                                packageName = app.packageName,
                                appName = app.appName,
                                uploadedBytes = burstTx,
                                downloadedBytes = burstRx,
                                activityType = detectedType,
                                severity = severity,
                                actionTaken = "$screenTag • Monitor-Only (फोन लॉक से बचाने हेतु खुला रखा गया)"
                            )
                        )
                        lastMonitorAlertMs[app.uid] = now
                        resetWindow(app.uid)
                    }
                }

                TrustCategory.WATCHED_DEFAULT -> {
                    if (detectedType == DataActivityType.NORMAL_DOWNLOAD) {
                        if (burstRx >= 300L * 1024L) resetWindow(app.uid)
                    } else if (!isUserUsingApp &&
                        config.autoBlockBackgroundApps &&
                        burstTx >= config.bgAutoBlockThresholdBytes
                    ) {
                        if (policy.setAppBlocked(app.packageName, true, fromAutoBlock = true)) {
                            blockedChanged = true
                            val screenTag = if (!userState.isScreenUnlockedAndOn) "स्क्रीन बंद होने पर" else "बैकग्राउंड में"
                            newAlerts.add(
                                UploadAlertEvent(
                                    packageName = app.packageName,
                                    appName = app.appName,
                                    uploadedBytes = burstTx,
                                    downloadedBytes = burstRx,
                                    activityType = detectedType,
                                    severity = severity,
                                    actionTaken = "$screenTag • Auto-Blocked (बैकग्राउंड अपलोड रोका गया)"
                                )
                            )
                            resetWindow(app.uid)
                        }
                    } else if (isUserUsingApp && burstTx >= config.bgAutoBlockThresholdBytes) {
                        resetWindow(app.uid)
                    }
                }

                TrustCategory.DEV_TEST_MONITOR -> {
                    if (!isUserUsingApp && burstTx >= config.bgAutoBlockThresholdBytes &&
                        detectedType != DataActivityType.NORMAL_DOWNLOAD
                    ) {
                        if (!config.devSafeModeEnabled && config.autoBlockBackgroundApps) {
                            if (policy.setAppBlocked(app.packageName, true, fromAutoBlock = true)) {
                                blockedChanged = true
                                newAlerts.add(
                                    UploadAlertEvent(
                                        packageName = app.packageName,
                                        appName = app.appName,
                                        uploadedBytes = burstTx,
                                        downloadedBytes = burstRx,
                                        activityType = detectedType,
                                        severity = severity,
                                        actionTaken = "बैकग्राउंड में • Auto-Blocked (Dev-Safe बंद है)"
                                    )
                                )
                                resetWindow(app.uid)
                            }
                        } else {
                            val lastNotified = lastMonitorAlertMs[app.uid] ?: 0L
                            if ((now - lastNotified) >= 20_000L) {
                                newAlerts.add(
                                    UploadAlertEvent(
                                        packageName = app.packageName,
                                        appName = app.appName,
                                        uploadedBytes = burstTx,
                                        downloadedBytes = burstRx,
                                        activityType = detectedType,
                                        severity = severity,
                                        actionTaken = "Test/Debug ऐप डेटा बाहर गया (Dev-Safe के कारण ब्लॉक नहीं)"
                                    )
                                )
                                lastMonitorAlertMs[app.uid] = now
                                resetWindow(app.uid)
                            }
                        }
                    } else if (isUserUsingApp) {
                        resetWindow(app.uid)
                    }
                }

                TrustCategory.TRUSTED_ALLOW,
                TrustCategory.BROWSER_SAFE_ALLOW -> {
                    resetWindow(app.uid)
                }

                else -> Unit
            }

            app.copy(
                sessionUploadBytes = currentTx,
                sessionDownloadBytes = currentRx,
                lastBurstUploadBytes = burstTx,
                lastActivityType = detectedType
            )
        }

        return ScanResult(updatedApps, newAlerts, blockedChanged)
    }

    private fun resetWindow(uid: Int) {
        windowTxByUid[uid] = 0L
        windowRxByUid[uid] = 0L
    }

    private fun hasUsageStatsPermission(): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    @Suppress("DEPRECATION")
    private fun queryUidTrafficTotals(startMs: Long, endMs: Long): Map<Int, Pair<Long, Long>>? {
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
                return null
            } catch (_: Exception) {
            } finally {
                stats?.close()
            }
        }
        return result
    }
}
