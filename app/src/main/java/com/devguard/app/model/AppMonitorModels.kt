package com.devguard.app.model

enum class TrustCategory {
    EMI_ADMIN_MONITOR_ONLY, // NS Secure: कभी ब्लॉक नहीं, हर गतिविधि की सूचना
    BLOCKED_BLACKHOLE,      // ब्लॉक किए गए ऐप्स
    WATCHED_DEFAULT,        // अनजान ऐप्स: बैकग्राउंड में 300 KB+ अपलोड पर ऑटो-ब्लॉक
    DEV_TEST_MONITOR,       // आपके Debug/Test ऐप्स: निगरानी चालू, ऑटो-ब्लॉक नहीं
    TRUSTED_ALLOW,          // बैंक, UPI, Facebook, Instagram आदि भरोसेमंद ऐप्स
    BROWSER_SAFE_ALLOW      // Google Chrome: आपके ब्राउज़र काम के लिए सुरक्षित
}

enum class AlertSeverity {
    INFO,
    TEXT_OR_METADATA_SPIKE,
    MEDIA_UPLOAD_HIGH
}

enum class DataActivityType(val labelHindi: String) {
    IDLE("कोई गतिविधि नहीं"),
    NORMAL_DOWNLOAD("डाउनलोड / रिसीव (सुरक्षित)"),
    NOTIFICATION_OR_PING("नोटिफिकेशन / पिंग रिक्वेस्ट"),
    TEXT_OR_API_SYNC("टेक्स्ट / API सिंक डेटा"),
    PHOTO_OR_SMALL_AUDIO("फोटो / छोटी ऑडियो फाइल"),
    LARGE_AUDIO_OR_HEAVY_MEDIA("बड़ी ऑडियो / भारी मीडिया"),
    LARGE_VIDEO_OR_BACKUP("बड़ी वीडियो फाइल / बैकअप")
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
    val lastBurstUploadBytes: Long = 0L,
    val lastActivityType: DataActivityType = DataActivityType.IDLE
)

data class UploadAlertEvent(
    val id: Long = System.currentTimeMillis(),
    val timestamp: Long = System.currentTimeMillis(),
    val packageName: String,
    val appName: String,
    val uploadedBytes: Long,
    val downloadedBytes: Long = 0L,
    val activityType: DataActivityType = DataActivityType.TEXT_OR_API_SYNC,
    val severity: AlertSeverity,
    val actionTaken: String
)

data class GuardConfig(
    val nsSecureBgAlertBytes: Long = 1024L,         // NS Secure: 1 KB+ पर तुरंत सूचना
    val bgAutoBlockThresholdBytes: Long = 307200L,  // अनजान ऐप्स: बैकग्राउंड में 300 KB+ पर ब्लॉक
    val mediaAlertThresholdBytes: Long = 307200L,   // 300 KB+ पर हाई मीडिया अलर्ट
    val autoBlockBackgroundApps: Boolean = true,
    val devSafeModeEnabled: Boolean = true
)
