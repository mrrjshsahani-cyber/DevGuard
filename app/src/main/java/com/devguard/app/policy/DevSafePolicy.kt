package com.devguard.app.policy

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.devguard.app.model.GuardConfig
import com.devguard.app.model.MonitoredAppInfo
import com.devguard.app.model.TrustCategory

class DevSafePolicy(private val context: Context) {

    private val prefs = context.getSharedPreferences("devguard_policy", Context.MODE_PRIVATE)

    // ब्राउज़र, APK डाउनलोडर/इंस्टॉलर, और डेवलपर टूल्स जिन्हें कभी ब्लॉक नहीं किया जाएगा
    private val builtInDevAndBrowserPackages = setOf(
        context.packageName,
        "com.android.chrome",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.android.providers.downloads",
        "com.android.providers.downloads.ui",
        "com.termux",
        "com.github.android",
        "com.android.vending",
        "com.google.android.gms",
        "com.google.android.gsf"
    )

    // डिफ़ॉल्ट भरोसेमंद कम्युनिकेशन व पेमेंट ऐप्स (चाहें तो UI से हटा सकते हैं)
    private val defaultTrustedPackages = setOf(
        "com.whatsapp",
        "com.phonepe.app",
        "com.google.android.apps.nbu.paisa.user",
        "net.one97.paytm"
    )

    private val customDevPrefixes = listOf(
        "com.zenoedit",
        "com.dedit",
        "com.scanorder",
        "com.survivalpath",
        "com.devguard"
    )

    private val sideloadInstallers = setOf(
        "com.android.chrome",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.android.shell"
    )

    fun getBlockedPackages(): Set<String> {
        return prefs.getStringSet("blocked_pkgs", emptySet())?.toSet() ?: emptySet()
    }

    fun getTrustedPackages(): Set<String> {
        return prefs.getStringSet("trusted_pkgs", defaultTrustedPackages)?.toSet()
            ?: defaultTrustedPackages
    }

    fun getConfig(): GuardConfig {
        return GuardConfig(
            nsSecureBgAlertBytes = prefs.getLong("ns_alert_b", 1024L),
            bgAutoBlockThresholdBytes = prefs.getLong("bg_block_b", 4096L),
            mediaAlertThresholdBytes = prefs.getLong("media_kb", 300L) * 1024L,
            autoBlockBackgroundApps = prefs.getBoolean("auto_block", true),
            devSafeModeEnabled = prefs.getBoolean("dev_safe", true)
        )
    }

    fun updateConfig(autoBlock: Boolean, devSafe: Boolean) {
        prefs.edit()
            .putBoolean("auto_block", autoBlock)
            .putBoolean("dev_safe", devSafe)
            .apply()
    }

    fun setAppBlocked(packageName: String, block: Boolean): Boolean {
        if (isNonBlockable(packageName)) return false
        val current = getBlockedPackages().toMutableSet()
        if (block) current.add(packageName) else current.remove(packageName)
        prefs.edit().putStringSet("blocked_pkgs", current).apply()
        return true
    }

    fun setAppTrusted(packageName: String, trust: Boolean) {
        val trusted = getTrustedPackages().toMutableSet()
        if (trust) {
            trusted.add(packageName)
            setAppBlocked(packageName, false)
        } else {
            trusted.remove(packageName)
        }
        prefs.edit().putStringSet("trusted_pkgs", trusted).apply()
    }

    fun isNonBlockable(packageName: String): Boolean {
        val pm = context.packageManager
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val activeAdmins = dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()

        if (packageName in activeAdmins || packageName.contains("nssecure", ignoreCase = true)) {
            return true
        }
        return try {
            val info = pm.getApplicationInfo(packageName, 0)
            val label = pm.getApplicationLabel(info).toString()
            if (label.contains("NS Secure", ignoreCase = true)) return true

            val isDebuggable = (info.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val devSafeOn = getConfig().devSafeModeEnabled
            packageName in builtInDevAndBrowserPackages ||
                customDevPrefixes.any { packageName.startsWith(it, ignoreCase = true) } ||
                (devSafeOn && (isDebuggable || isSideloadedTestApp(pm, packageName)))
        } catch (_: PackageManager.NameNotFoundException) {
            true
        }
    }

    fun loadMonitoredApps(): List<MonitoredAppInfo> {
        val pm = context.packageManager
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val activeAdmins = dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()
        val blocked = getBlockedPackages()
        val trusted = getTrustedPackages()
        val devSafeOn = getConfig().devSafeModeEnabled

        val installed = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        return installed.mapNotNull { info ->
            val pkg = info.packageName
            val label = pm.getApplicationLabel(info).toString()
            val isDebuggable = (info.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

            // पहले Device Admin / NS Secure की पहचान (ताकि यह कभी Dev-Safe में न जाए)
            val isAdmin = pkg in activeAdmins ||
                label.contains("NS Secure", ignoreCase = true) ||
                pkg.contains("nssecure", ignoreCase = true)

            val isSideloaded = if (!isAdmin && devSafeOn) isSideloadedTestApp(pm, pkg) else false
            val isDevOrBrowser = !isAdmin && (
                pkg in builtInDevAndBrowserPackages ||
                    customDevPrefixes.any { pkg.startsWith(it, ignoreCase = true) } ||
                    (devSafeOn && (isDebuggable || isSideloaded))
                )

            val isPureSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                !isAdmin && pkg !in blocked

            if (isPureSystem && !isDevOrBrowser) return@mapNotNull null

            val category = when {
                isAdmin -> TrustCategory.EMI_ADMIN_MONITOR_ONLY
                isDevOrBrowser -> TrustCategory.DEV_SAFE_BYPASS
                pkg in blocked -> TrustCategory.BLOCKED_BLACKHOLE
                pkg in trusted -> TrustCategory.TRUSTED_ALLOW
                else -> TrustCategory.WATCHED_DEFAULT
            }

            MonitoredAppInfo(
                uid = info.uid,
                packageName = pkg,
                appName = label,
                isDebuggable = isDebuggable,
                isDeviceAdmin = isAdmin,
                category = category
            )
        }.sortedWith(
            compareBy<MonitoredAppInfo> { it.category.ordinal }
                .thenBy { it.appName.lowercase() }
        )
    }

    private fun isSideloadedTestApp(pm: PackageManager, packageName: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val installer = pm.getInstallSourceInfo(packageName).installingPackageName
                installer != null && installer in sideloadInstallers
            } else {
                @Suppress("DEPRECATION")
                val installer = pm.getInstallerPackageName(packageName)
                installer != null && installer in sideloadInstallers
            }
        } catch (_: Exception) {
            false
        }
    }
}
