package com.devguard.app.policy

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process
import com.devguard.app.model.GuardConfig
import com.devguard.app.model.MonitoredAppInfo
import com.devguard.app.model.TrustCategory

class DevSafePolicy(private val context: Context) {

    private val prefs = context.getSharedPreferences("devguard_policy", Context.MODE_PRIVATE)

    // Google Chrome को ब्राउज़र काम के लिए सुरक्षित रखें
    private val browserSafePackages = setOf(
        "com.android.chrome"
    )

    // Vivo और हार्डवेयर OEM सिस्टम पैकेज (इन्हें निगरानी से बाहर रखा जाएगा)
    private val vivoAndOemPrefixes = listOf(
        "com.vivo.",
        "com.bbk.",
        "com.iqoo.",
        "com.mediatek.",
        "com.qualcomm.",
        "com.qti."
    )

    // डिफ़ॉल्ट भरोसेमंद कम्युनिकेशन व पेमेंट ऐप्स (चाहें तो UI से Trust हटा सकते हैं)
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
        "com.survivalpath"
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
        if (packageName == context.packageName || packageName in browserSafePackages) {
            return true
        }
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
            isVivoOrAndroidSystem(pm, info)
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

        val installed = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        return installed.mapNotNull { info ->
            val pkg = info.packageName
            if (pkg == context.packageName) return@mapNotNull null

            val label = pm.getApplicationLabel(info).toString()
            val isDebuggable = (info.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

            // 1. पहले NS Secure / Device Admin की पहचान (ताकि यह कभी बाहर न हो)
            val isAdmin = pkg in activeAdmins ||
                label.contains("NS Secure", ignoreCase = true) ||
                pkg.contains("nssecure", ignoreCase = true)

            if (!isAdmin) {
                // 2. Vivo और Android सिस्टम ऐप्स को निगरानी लिस्ट से बाहर करें
                if (isVivoOrAndroidSystem(pm, info)) return@mapNotNull null

                // 3. बिना इंटरनेट और बिना आइकन वाले खाली पैकेज छोड़ें
                val hasInternet = pm.checkPermission(Manifest.permission.INTERNET, pkg) ==
                    PackageManager.PERMISSION_GRANTED
                val hasLauncher = pm.getLaunchIntentForPackage(pkg) != null
                if (!hasInternet && !hasLauncher && pkg !in blocked) return@mapNotNull null
            }

            val isDevTestApp = !isAdmin && (
                isDebuggable || customDevPrefixes.any { pkg.startsWith(it, ignoreCase = true) }
                )

            val category = when {
                isAdmin -> TrustCategory.EMI_ADMIN_MONITOR_ONLY
                pkg in browserSafePackages -> TrustCategory.BROWSER_SAFE_ALLOW
                pkg in blocked -> TrustCategory.BLOCKED_BLACKHOLE
                pkg in trusted -> TrustCategory.TRUSTED_ALLOW
                isDevTestApp -> TrustCategory.DEV_TEST_MONITOR
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

    private fun isVivoOrAndroidSystem(pm: PackageManager, info: ApplicationInfo): Boolean {
        val pkg = info.packageName
        if (pkg in browserSafePackages) return false
        if (info.uid < Process.FIRST_APPLICATION_UID) return true
        if (pkg == "android") return true
        if (vivoAndOemPrefixes.any { pkg.startsWith(it, ignoreCase = true) }) return true

        val hasSystemFlag = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        if (hasSystemFlag) {
            if (pkg.startsWith("com.android.") || pkg.startsWith("com.google.android.")) {
                return true
            }
            if (pm.getLaunchIntentForPackage(pkg) == null) {
                return true
            }
        }
        return false
    }
}
