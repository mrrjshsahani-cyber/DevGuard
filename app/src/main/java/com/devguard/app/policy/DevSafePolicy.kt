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

    private val browserSafePackages = setOf(
        "com.android.chrome"
    )

    private val vivoAndOemPrefixes = listOf(
        "com.vivo.",
        "com.bbk.",
        "com.iqoo.",
        "com.mediatek.",
        "com.qualcomm.",
        "com.qti."
    )

    // प्रमुख बैंक, UPI, सरकारी सेवाएं, सोशल मीडिया और रोज़मर्रा के बड़े ऐप्स (कभी ऑटो-ब्लॉक नहीं होंगे)
    private val defaultTrustedPackages = setOf(
        // बैंक, UPI और सरकारी ऐप्स
        "com.kotak811mobilebankingapp.instantsavingsupiscanandpayrecharge",
        "com.msf.kbank.mobile",
        "com.phonepe.app",
        "com.google.android.apps.nbu.paisa.user",
        "net.one97.paytm",
        "in.org.npci.upiapp",
        "com.sbi.lotusintouch",
        "com.sbi.SBIFreedomPlus",
        "com.snapwork.hdfc",
        "com.csam.icici.bank.imobile",
        "com.axis.mobile",
        "com.dreamplug.androidapp",
        "in.gov.uidai.pehchaan",
        "com.digilocker.android",

        // प्रमुख सोशल मीडिया, मैसेजिंग और AI ऐप्स
        "com.whatsapp",
        "com.whatsapp.w4b",
        "com.facebook.katana",
        "com.facebook.lite",
        "com.facebook.orca",
        "com.facebook.stella",
        "com.instagram.android",
        "com.instagram.barcelona",
        "org.telegram.messenger",
        "com.linkedin.android",
        "com.pinterest",
        "com.twitter.android",
        "com.snapchat.android",
        "com.openai.chatgpt",
        "com.google.android.apps.bard",
        "com.google.android.youtube",

        // शॉपिंग, टेलीकॉम और ट्रैवल
        "in.amazon.mShop.android.shopping",
        "com.flipkart.android",
        "com.jio.myjio",
        "com.myairtelapp",
        "com.ixigo.train.ixitrain",
        "cris.org.in.prs.ima",
        "com.application.zomato",
        "in.swiggy.android",
        "com.ubercab",
        "com.olacabs.customer"
    )

    private val customDevPrefixes = listOf(
        "com.zenoedit",
        "com.dedit",
        "com.scanorder",
        "com.survivalpath"
    )

    fun getTrustedPackages(): Set<String> {
        val userTrusted = prefs.getStringSet("user_trusted_pkgs", emptySet()) ?: emptySet()
        val untrustedOverrides = prefs.getStringSet("untrusted_overrides", emptySet()) ?: emptySet()
        return (defaultTrustedPackages + userTrusted) - untrustedOverrides
    }

    fun getBlockedPackages(): Set<String> {
        val rawBlocked = prefs.getStringSet("blocked_pkgs", emptySet())?.toSet() ?: emptySet()
        val trusted = getTrustedPackages()
        // पिछले वर्जन से गलती से ब्लॉक हुए बड़े ऐप्स को अपने आप अनब्लॉक करें
        val cleanedBlocked = rawBlocked.filterNot { it in trusted || isNonBlockable(it) }.toSet()
        if (cleanedBlocked.size != rawBlocked.size) {
            prefs.edit().putStringSet("blocked_pkgs", cleanedBlocked).apply()
        }
        return cleanedBlocked
    }

    fun getConfig(): GuardConfig {
        return GuardConfig(
            nsSecureBgAlertBytes = prefs.getLong("ns_alert_b", 1024L),
            bgAutoBlockThresholdBytes = prefs.getLong("bg_block_kb", 300L) * 1024L,
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

    fun setAppBlocked(packageName: String, block: Boolean, fromAutoBlock: Boolean = false): Boolean {
        if (isNonBlockable(packageName)) return false
        if (fromAutoBlock && packageName in getTrustedPackages()) return false

        val current = getBlockedPackages().toMutableSet()
        if (block) {
            if (!fromAutoBlock && packageName in getTrustedPackages()) {
                setAppTrusted(packageName, false)
            }
            current.add(packageName)
        } else {
            current.remove(packageName)
        }
        prefs.edit().putStringSet("blocked_pkgs", current).apply()
        return true
    }

    fun setAppTrusted(packageName: String, trust: Boolean) {
        val userTrusted = (prefs.getStringSet("user_trusted_pkgs", emptySet()) ?: emptySet()).toMutableSet()
        val untrustedOverrides = (prefs.getStringSet("untrusted_overrides", emptySet()) ?: emptySet()).toMutableSet()

        if (trust) {
            userTrusted.add(packageName)
            untrustedOverrides.remove(packageName)
            val blocked = getBlockedPackages().toMutableSet()
            if (blocked.remove(packageName)) {
                prefs.edit().putStringSet("blocked_pkgs", blocked).apply()
            }
        } else {
            userTrusted.remove(packageName)
            if (packageName in defaultTrustedPackages) {
                untrustedOverrides.add(packageName)
            }
        }

        prefs.edit()
            .putStringSet("user_trusted_pkgs", userTrusted)
            .putStringSet("untrusted_overrides", untrustedOverrides)
            .apply()
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

            val isAdmin = pkg in activeAdmins ||
                label.contains("NS Secure", ignoreCase = true) ||
                pkg.contains("nssecure", ignoreCase = true)

            if (!isAdmin) {
                if (isVivoOrAndroidSystem(pm, info)) return@mapNotNull null

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
