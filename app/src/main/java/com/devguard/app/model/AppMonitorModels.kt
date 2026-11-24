package com.devguard.app.model

enum class TrustCategory {
    EMI_ADMIN_MONITOR_ONLY, // NS Secure आदि: कभी ब्लॉक नहीं, हर गतिविधि की सूचना
    BLOCKED_BLACKHOLE,      // बैकग्राउंड डेटा भेजने पर ब्लॉक किए गए ऐप्स
    WATCHED_DEFAULT,        // सभी सामान्य व नए डाउनलोड किए गए ऐप्स: बैकग्राउंड डेटा पर ऑटो-ब्लॉक
    DEV_TEST_MONITOR,       // आपके Debug/Test ऐप्स: पूरी निगरानी + अलर्ट (Dev-Safe में ऑटो-ब्लॉक नहीं)
    TRUSTED_ALLOW,          // उपयोगकर्ता द्वारा भरोसेमंद (WhatsApp, UPI आदि)
    BROWSER_SAFE_ALLOW      // Google Chrome: आपके ब्राउज़र काम के लिए सुरक्षित
}

enum class AlertSeverity {
    INFO,
    TEXT_OR_METADATA_SPIKE,
    MEDIA_UPLOAD_HIGH
}

data class MonitoredAppInfo(
    val uid: Int,
    val packageName: String,
    val appName: String,
    val isDebuggable: Boolean,
    val isDeviceAdmin: Boolean,
    val category: TrustCategory,
    val sessionUploadBytes: Long = 0L,
    val sessionDownloadBytes: Long = 0L,
    val lastBurstUploadBytes: Long = 0L
)

data class UploadAlertEvent(
    val id: Long = System.currentTimeMillis(),
    val timestamp: Long = System.currentTimeMillis(),
    val packageName: String,
    val appName: String,
    val uploadedBytes: Long,
    val severity: AlertSeverity,
    val actionTaken: String
)

data class GuardConfig(
    val nsSecureBgAlertBytes: Long = 1024L,         // NS Secure: 1 KB+ पर तुरंत सूचना
    val bgAutoBlockThresholdBytes: Long = 4096L,    // अन्य ऐप्स: बैकग्राउंड में 4 KB+ पर ब्लॉक
    val mediaAlertThresholdBytes: Long = 307200L,   // 300 KB+ पर हाई मीडिया अलर्ट
    val autoBlockBackgroundApps: Boolean = true,
    val devSafeModeEnabled: Boolean = true
)
