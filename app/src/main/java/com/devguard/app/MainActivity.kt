package com.devguard.app

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import com.devguard.app.model.GuardConfig
import com.devguard.app.policy.DevSafePolicy
import com.devguard.app.service.SecurityGuardService
import com.devguard.app.ui.SecurityDashboardScreen
import com.devguard.app.vpn.SelectiveBlackholeVpnService

class MainActivity : ComponentActivity() {

    private lateinit var policy: DevSafePolicy
    private var hasUsagePermission by mutableStateOf(false)
    private var configState by mutableStateOf(GuardConfig())

    private val notifLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == RESULT_OK) {
            startGuardAndVpn()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        policy = DevSafePolicy(this)
        requestNotificationPermissionIfNeeded()

        setContent {
            val isRunning by SecurityGuardService.isRunning.collectAsState()
            val apps by SecurityGuardService.appsState.collectAsState()
            val alerts by SecurityGuardService.alertsState.collectAsState()

            SecurityDashboardScreen(
                hasUsagePermission = hasUsagePermission,
                isGuardRunning = isRunning,
                isVpnActive = SelectiveBlackholeVpnService.isVpnRunning,
                config = configState,
                apps = apps,
                alerts = alerts,
                onGrantUsageAccess = {
                    startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                },
                onToggleGuard = { start ->
                    if (start) prepareAndStartGuard() else stopGuardAndVpn()
                },
                onToggleAutoBlock = { enabled ->
                    policy.updateConfig(enabled, configState.devSafeModeEnabled)
                    configState = policy.getConfig()
                },
                onToggleDevSafe = { enabled ->
                    policy.updateConfig(configState.autoBlockBackgroundApps, enabled)
                    configState = policy.getConfig()
                    refreshGuard()
                },
                onToggleAppBlock = { pkg, block ->
                    if (policy.setAppBlocked(pkg, block)) {
                        reloadVpnIfRunning()
                        refreshGuard()
                    }
                },
                onToggleAppTrust = { pkg, trust ->
                    policy.setAppTrusted(pkg, trust)
                    reloadVpnIfRunning()
                    refreshGuard()
                }
            )
        }
    }

    override fun onResume() {
        super.onResume()
        hasUsagePermission = checkUsageStatsPermission()
        configState = policy.getConfig()
        refreshGuard()
    }

    private fun prepareAndStartGuard() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            vpnLauncher.launch(vpnIntent)
        } else {
            startGuardAndVpn()
        }
    }

    private fun startGuardAndVpn() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, SecurityGuardService::class.java).apply {
                action = SecurityGuardService.ACTION_START
            }
        )
        startService(
            Intent(this, SelectiveBlackholeVpnService::class.java).apply {
                action = SelectiveBlackholeVpnService.ACTION_START_OR_RELOAD
            }
        )
    }

    private fun stopGuardAndVpn() {
        startService(
            Intent(this, SecurityGuardService::class.java).apply {
                action = SecurityGuardService.ACTION_STOP
            }
        )
    }

    private fun reloadVpnIfRunning() {
        if (SelectiveBlackholeVpnService.isVpnRunning) {
            startService(
                Intent(this, SelectiveBlackholeVpnService::class.java).apply {
                    action = SelectiveBlackholeVpnService.ACTION_START_OR_RELOAD
                }
            )
        }
    }

    private fun refreshGuard() {
        if (SecurityGuardService.isRunning.value) {
            startService(
                Intent(this, SecurityGuardService::class.java).apply {
                    action = SecurityGuardService.ACTION_REFRESH
                }
            )
        }
    }

    private fun checkUsageStatsPermission(): Boolean {
        val appOps = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = appOps.unsafeCheckOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS,
            Process.myUid(),
            packageName
        )
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
