package com.devguard.app.monitor

import android.app.KeyguardManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build
import android.os.PowerManager

data class UserActivityState(
    val isScreenUnlockedAndOn: Boolean,
    val activeForegroundPackage: String?,
    val recentlyActivePackages: Set<String>
)

class ForegroundTracker(private val context: Context) {

    private val usageStatsManager =
        context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
    private val powerManager =
        context.getSystemService(Context.POWER_SERVICE) as PowerManager
    private val keyguardManager =
        context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    private var lastCheckTimeMs: Long = System.currentTimeMillis() - 60_000L
    private var currentForegroundPkg: String? = null
    private val lastSeenForegroundMs = mutableMapOf<String, Long>()
    private val graceWindowMs = 30_000L

    fun getCurrentState(): UserActivityState {
        val now = System.currentTimeMillis()
        val isInteractive = powerManager.isInteractive && !keyguardManager.isKeyguardLocked

        val resumeEventType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            UsageEvents.Event.ACTIVITY_RESUMED
        } else {
            @Suppress("DEPRECATION")
            UsageEvents.Event.MOVE_TO_FOREGROUND
        }

        try {
            val events = usageStatsManager.queryEvents(lastCheckTimeMs, now)
            val event = UsageEvents.Event()
            while (events.hasNextEvent()) {
                events.getNextEvent(event)
                if (event.eventType == resumeEventType) {
                    currentForegroundPkg = event.packageName
                    lastSeenForegroundMs[event.packageName] = event.timeStamp
                }
            }
            lastCheckTimeMs = now
        } catch (_: SecurityException) {
        }

        if (isInteractive && currentForegroundPkg != null) {
            lastSeenForegroundMs[currentForegroundPkg!!] = now
        }

        val recentSet = lastSeenForegroundMs
            .filterValues { (now - it) <= graceWindowMs }
            .keys
            .toSet()

        return UserActivityState(
            isScreenUnlockedAndOn = isInteractive,
            activeForegroundPackage = if (isInteractive) currentForegroundPkg else null,
            recentlyActivePackages = if (isInteractive) recentSet else emptySet()
        )
    }
}
