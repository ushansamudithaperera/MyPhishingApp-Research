package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// NotificationHelper.java — PhishGuard v2.0
//
// Central notification factory used by:
//   • SmsReceiver           (SMS URL detection)
//   • PhishingAccessibilityService  (WhatsApp/Telegram/Gmail)
//
// Features:
//   • Android 13+ POST_NOTIFICATIONS runtime permission safe
//   • High-priority heads-up notification
//   • PendingIntent → MainActivity with URL + source extras
//   • Two action buttons: "Scan Now" + "Dismiss"
// ══════════════════════════════════════════════════════════════════════

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

public class NotificationHelper {

    // ── Channel IDs ───────────────────────────────────────────────
    public static final String CHANNEL_THREAT  = "phishguard_threat";
    public static final String CHANNEL_SERVICE = "phishguard_service";

    // ── Notification IDs ──────────────────────────────────────────
    private static final int NOTIF_BASE_ID   = 1000;
    private static       int notifCounter    = 0;

    // ── Source tags (passed to MainActivity) ──────────────────────
    public static final String SOURCE_SMS       = "SMS";
    public static final String SOURCE_WHATSAPP  = "WhatsApp";
    public static final String SOURCE_TELEGRAM  = "Telegram";
    public static final String SOURCE_GMAIL     = "Gmail";

    // ── Intent extras ─────────────────────────────────────────────
    public static final String EXTRA_URL    = "DETECTED_URL";
    public static final String EXTRA_SOURCE = "DETECTED_SOURCE";

    // ══════════════════════════════════════════════════════════════
    // Create notification channels (call once in Application.onCreate
    // or in MainActivity.onCreate)
    // ══════════════════════════════════════════════════════════════
    public static void createChannels(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;

        NotificationManager nm = context.getSystemService(NotificationManager.class);
        if (nm == null) return;

        // ── Threat alert channel (high priority) ─────────────────
        NotificationChannel threat = new NotificationChannel(
                CHANNEL_THREAT,
                "Phishing Link Alerts",
                NotificationManager.IMPORTANCE_HIGH
        );
        threat.setDescription("Alerts when a suspicious link is detected in messages.");
        threat.enableLights(true);
        threat.setLightColor(Color.RED);
        threat.enableVibration(true);
        threat.setVibrationPattern(new long[]{0, 250, 150, 250});
        threat.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        nm.createNotificationChannel(threat);

        // ── Foreground service channel (low priority) ─────────────
        NotificationChannel service = new NotificationChannel(
                CHANNEL_SERVICE,
                "PhishGuard Background Service",
                NotificationManager.IMPORTANCE_MIN
        );
        service.setDescription("Keeps PhishGuard monitoring active in background.");
        service.setShowBadge(false);
        nm.createNotificationChannel(service);
    }

    // ══════════════════════════════════════════════════════════════
    // Show "Link Detected" notification
    //
    // @param context       app context
    // @param url           extracted URL
    // @param title         notification title (Sinhala)
    // @param message       body text
    // @param subText       sub-text below message
    // @param source        SOURCE_SMS / SOURCE_WHATSAPP / etc.
    // ══════════════════════════════════════════════════════════════
    public static void showLinkDetectedNotification(
            Context context,
            String  url,
            String  title,
            String  message,
            String  subText,
            String  source) {

        // ── Tap action → MainActivity with URL ───────────────────
        Intent openIntent = new Intent(context, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                | Intent.FLAG_ACTIVITY_SINGLE_TOP
                | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        openIntent.putExtra(EXTRA_URL,    url);
        openIntent.putExtra(EXTRA_SOURCE, source);

        int uniqueId = NOTIF_BASE_ID + (notifCounter++);
        PendingIntent tapPendingIntent = PendingIntent.getActivity(
                context,
                uniqueId,
                openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        // ── "Scan Now" action button ──────────────────────────────
        Intent scanIntent = new Intent(context, MainActivity.class);
        scanIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        scanIntent.putExtra(EXTRA_URL,    url);
        scanIntent.putExtra(EXTRA_SOURCE, source);
        scanIntent.putExtra("AUTO_SCAN",  true);       // triggers auto-scan in MainActivity

        PendingIntent scanPendingIntent = PendingIntent.getActivity(
                context,
                uniqueId + 500,
                scanIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        // ── "Dismiss" action button ───────────────────────────────
        Intent dismissIntent = new Intent(context, NotificationDismissReceiver.class);
        dismissIntent.putExtra("NOTIF_ID", uniqueId);
        PendingIntent dismissPendingIntent = PendingIntent.getBroadcast(
                context,
                uniqueId + 600,
                dismissIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        // ── Build notification ────────────────────────────────────
        NotificationCompat.Builder builder = new NotificationCompat.Builder(
                context, CHANNEL_THREAT)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(message)
                .setSubText(source)
                .setStyle(new NotificationCompat.BigTextStyle()
                        .bigText(message + "\n\n" + subText)
                        .setSummaryText(source))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                .setAutoCancel(true)
                .setContentIntent(tapPendingIntent)
                .addAction(android.R.drawable.ic_menu_search,
                        "Scan Now", scanPendingIntent)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel,
                        "Dismiss", dismissPendingIntent)
                .setColor(Color.parseColor("#E8394A"))
                .setColorized(true);

        // ── POST_NOTIFICATIONS check + SecurityException guard ──────
        NotificationManagerCompat nm = NotificationManagerCompat.from(context);

        // Check permission explicitly before calling notify()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // Android 13+ requires POST_NOTIFICATIONS runtime permission
            if (androidx.core.content.ContextCompat.checkSelfPermission(
                    context, android.Manifest.permission.POST_NOTIFICATIONS)
                    != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                return;  // Permission not granted — silently skip
            }
        }

        // Also check if notifications are enabled at system level
        if (!nm.areNotificationsEnabled()) return;

        try {
            nm.notify(uniqueId, builder.build());
        } catch (SecurityException e) {
            // POST_NOTIFICATIONS permission was revoked after check — safe to ignore
            android.util.Log.w("PhishGuard_Notif",
                    "Notification blocked — POST_NOTIFICATIONS permission denied.", e);
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Foreground service notification (for Accessibility Service)
    // ══════════════════════════════════════════════════════════════
    public static Notification buildServiceNotification(Context context) {
        Intent openIntent = new Intent(context, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
                context, 0, openIntent,
                PendingIntent.FLAG_IMMUTABLE
        );

        return new NotificationCompat.Builder(context, CHANNEL_SERVICE)
                .setSmallIcon(android.R.drawable.ic_lock_silent_mode_off)
                .setContentTitle("PhishGuard Active 🛡")
                .setContentText("WhatsApp / Telegram / Gmail monitoring on")
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setOngoing(true)
                .setContentIntent(pi)
                .build();
    }
}