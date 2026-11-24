package com.devguard.app.monitor

import com.devguard.app.model.DataActivityType
import java.util.Locale

object TrafficClassifier {

    fun classify(txBytes: Long, rxBytes: Long): DataActivityType {
        if (txBytes <= 0L && rxBytes <= 0L) {
            return DataActivityType.IDLE
        }

        // डाउनलोड डेटा अपलोड से 3 गुना या अधिक हो तो यह सामान्य डाउनलोड ट्रैफिक है
        if (rxBytes >= 100L * 1024L && rxBytes >= txBytes * 3L) {
            return DataActivityType.NORMAL_DOWNLOAD
        }

        return when {
            txBytes >= 5L * 1024L * 1024L -> DataActivityType.LARGE_VIDEO_OR_BACKUP
            txBytes >= 1536L * 1024L -> DataActivityType.LARGE_AUDIO_OR_HEAVY_MEDIA
            txBytes >= 150L * 1024L -> DataActivityType.PHOTO_OR_SMALL_AUDIO
            txBytes >= 15L * 1024L -> DataActivityType.TEXT_OR_API_SYNC
            else -> DataActivityType.NOTIFICATION_OR_PING
        }
    }

    fun formatSize(bytes: Long): String {
        return when {
            bytes >= 1024L * 1024L -> String.format(Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0))
            bytes >= 1024L -> "${bytes / 1024L} KB"
            else -> "$bytes B"
        }
    }
}
