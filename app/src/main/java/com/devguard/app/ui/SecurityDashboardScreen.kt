package com.devguard.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.devguard.app.model.GuardConfig
import com.devguard.app.model.MonitoredAppInfo
import com.devguard.app.model.TrustCategory
import com.devguard.app.model.UploadAlertEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun SecurityDashboardScreen(
    hasUsagePermission: Boolean,
    isGuardRunning: Boolean,
    isVpnActive: Boolean,
    config: GuardConfig,
    apps: List<MonitoredAppInfo>,
    alerts: List<UploadAlertEvent>,
    onGrantUsageAccess: () -> Unit,
    onToggleGuard: (Boolean) -> Unit,
    onToggleAutoBlock: (Boolean) -> Unit,
    onToggleDevSafe: (Boolean) -> Unit,
    onToggleAppBlock: (String, Boolean) -> Unit,
    onToggleAppTrust: (String, Boolean) -> Unit
) {
    var selectedTab by remember { mutableStateOf(0) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0E1117))
            .systemBarsPadding()
            .padding(14.dp)
    ) {
        Text(
            text = "DevGuard",
            color = Color.White,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "NS Secure Monitor-Only • अन्य ऐप्स बैकग्राउंड पर Auto-Block",
            color = Color(0xFF9BA3B4),
            fontSize = 12.sp
        )
        Spacer(modifier = Modifier.height(12.dp))

        if (!hasUsagePermission) {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF2D1B1E)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "Usage Access अनुमति आवश्यक है",
                        color = Color(0xFFFF8A8A),
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "NS Secure की हर गतिविधि देखने और बैकग्राउंड डेटा ब्लॉक करने के लिए इसे चालू करें।",
                        color = Color(0xFFE0E0E0),
                        fontSize = 12.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = onGrantUsageAccess) {
                        Text("Usage Access खोलें")
                    }
                }
            }
            Spacer(modifier = Modifier.height(10.dp))
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0xFF171C26)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = if (isGuardRunning) "सुरक्षा शील्ड सक्रिय" else "सुरक्षा शील्ड बंद",
                            color = if (isGuardRunning) Color(0xFF4ADE80) else Color(0xFFFCA5A5),
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = if (isVpnActive) "VPN फ़िल्टर चालू (Chrome/Dev सुरक्षित)" else "VPN फ़िल्टर बंद",
                            color = Color(0xFF9BA3B4),
                            fontSize = 12.sp
                        )
                    }
                    Button(
                        onClick = { onToggleGuard(!isGuardRunning) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isGuardRunning) Color(0xFFDC2626) else Color(0xFF2563EB)
                        )
                    ) {
                        Text(if (isGuardRunning) "बंद करें" else "चालू करें")
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = Color(0xFF2A3140))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Chrome, डाउनलोड व टेस्ट ऐप्स सुरक्षित", color = Color.White, fontSize = 13.sp)
                    Switch(checked = config.devSafeModeEnabled, onCheckedChange = onToggleDevSafe)
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("अन्य ऐप्स बैकग्राउंड डेटा भेजें तो Block", color = Color.White, fontSize = 13.sp)
                    Switch(checked = config.autoBlockBackgroundApps, onCheckedChange = onToggleAutoBlock)
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { selectedTab = 0 },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (selectedTab == 0) Color(0xFF2563EB) else Color(0xFF232A38)
                )
            ) {
                Text("ऐप्स (${apps.size})")
            }
            Button(
                onClick = { selectedTab = 1 },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (selectedTab == 1) Color(0xFF2563EB) else Color(0xFF232A38)
                )
            ) {
                Text("अलर्ट लॉग (${alerts.size})")
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        if (selectedTab == 0) {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(apps, key = { it.packageName }) { app ->
                    AppPolicyRow(app, onToggleAppBlock, onToggleAppTrust)
                }
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(alerts, key = { it.id }) { alert ->
                    AlertLogRow(alert)
                }
            }
        }
    }
}

@Composable
private fun AppPolicyRow(
    app: MonitoredAppInfo,
    onToggleAppBlock: (String, Boolean) -> Unit,
    onToggleAppTrust: (String, Boolean) -> Unit
) {
    val badgeColor = when (app.category) {
        TrustCategory.EMI_ADMIN_MONITOR_ONLY -> Color(0xFFFACC15)
        TrustCategory.BLOCKED_BLACKHOLE -> Color(0xFFF87171)
        TrustCategory.WATCHED_DEFAULT -> Color(0xFFCBD5E1)
        TrustCategory.TRUSTED_ALLOW -> Color(0xFF4ADE80)
        TrustCategory.DEV_SAFE_BYPASS -> Color(0xFF38BDF8)
    }

    val statusText = when (app.category) {
        TrustCategory.EMI_ADMIN_MONITOR_ONLY -> "Monitor-Only (केवल सूचना, ब्लॉक नहीं)"
        TrustCategory.BLOCKED_BLACKHOLE -> "BLOCKED (इंटरनेट बंद)"
        TrustCategory.WATCHED_DEFAULT -> "Watched (बैकग्राउंड डेटा पर ब्लॉक)"
        TrustCategory.TRUSTED_ALLOW -> "Trusted (अनुमति प्राप्त)"
        TrustCategory.DEV_SAFE_BYPASS -> "Dev/Browser Safe (पूर्ण छूट)"
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF171C26)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(app.appName, color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text(app.packageName, color = Color(0xFF8892A6), fontSize = 11.sp)
                    Text(statusText, color = badgeColor, fontSize = 12.sp, fontWeight = FontWeight.Medium)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text("Up: ${app.sessionUploadBytes / 1024} KB", color = Color(0xFFFB923C), fontSize = 12.sp)
                    Text("Down: ${app.sessionDownloadBytes / 1024} KB", color = Color(0xFF94A3B8), fontSize = 11.sp)
                }
            }

            if (app.category != TrustCategory.EMI_ADMIN_MONITOR_ONLY &&
                app.category != TrustCategory.DEV_SAFE_BYPASS
            ) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    val isBlocked = app.category == TrustCategory.BLOCKED_BLACKHOLE
                    Button(
                        onClick = { onToggleAppBlock(app.packageName, !isBlocked) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isBlocked) Color(0xFF16A34A) else Color(0xFFDC2626)
                        )
                    ) {
                        Text(if (isBlocked) "Unblock करें" else "Block करें", fontSize = 12.sp)
                    }

                    val isTrusted = app.category == TrustCategory.TRUSTED_ALLOW
                    OutlinedButton(onClick = { onToggleAppTrust(app.packageName, !isTrusted) }) {
                        Text(if (isTrusted) "Trust हटाएं" else "Trust करें", color = Color.White, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun AlertLogRow(alert: UploadAlertEvent) {
    val timeStr = remember(alert.timestamp) {
        SimpleDateFormat("dd MMM, hh:mm:ss a", Locale.getDefault()).format(Date(alert.timestamp))
    }
    val kb = (alert.uploadedBytes / 1024L).coerceAtLeast(1L)
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF211B24)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("${alert.appName} ($kb KB बाहर गया)", color = Color(0xFFFCA5A5), fontWeight = FontWeight.Bold)
            Text(alert.actionTaken, color = Color(0xFFFDE047), fontSize = 12.sp)
            Text("${alert.packageName} • $timeStr", color = Color(0xFF94A3B8), fontSize = 11.sp)
        }
    }
}
