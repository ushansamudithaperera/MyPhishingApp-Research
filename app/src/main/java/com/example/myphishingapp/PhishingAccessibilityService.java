package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// PhishingAccessibilityService.java — PhishGuard v2.0
//
// An AccessibilityService that monitors incoming notifications from:
//   • WhatsApp  (com.whatsapp)
//   • Telegram  (org.telegram.messenger)
//   • Gmail     (com.google.android.gm)
//
// How it works:
//   1. Listens for TYPE_NOTIFICATION_STATE_CHANGED events
//   2. Reads notification text from the AccessibilityEvent
//   3. Extracts URLs using regex
//   4. Fires a PhishGuard notification if a URL is found
//
// ⚠️  IMPORTANT: User must manually enable this service in
//   Settings → Accessibility → Downloaded Apps → PhishGuard
//
// ⚠️  This service uses only notification text — it does NOT
//   read private messages or intercept encrypted content.
// ══════════════════════════════════════════════════════════════════════

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.Notification;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PhishingAccessibilityService extends AccessibilityService {

    private static final String TAG = "PhishGuard_A11y";

    // ── Target apps to monitor ────────────────────────────────────
    private static final Set<String> MONITORED_PACKAGES = new HashSet<>(Arrays.asList(
            "com.whatsapp",                    // WhatsApp
            "com.whatsapp.w4b",                // WhatsApp Business
            "org.telegram.messenger",          // Telegram
            "org.telegram.messenger.web",      // Telegram X
            "com.google.android.gm",           // Gmail
            "com.microsoft.teams",             // Microsoft Teams
            "com.viber.voip",                  // Viber
            "com.facebook.orca"                // Messenger
    ));

    // ── Deduplication: avoid firing multiple times for same URL ───
    private final Set<String> recentlyDetected = new HashSet<>();
    private static final int  MAX_RECENT       = 20;

    // ══════════════════════════════════════════════════════════════
    // Service lifecycle
    // ══════════════════════════════════════════════════════════════
    @Override
    public void onServiceConnected() {
        super.onServiceConnected();

        AccessibilityServiceInfo info = new AccessibilityServiceInfo();
        info.eventTypes = AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED
                | AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED;
        info.feedbackType    = AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags           = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
                | AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
        info.notificationTimeout = 100;
        setServiceInfo(info);

        // Create notification channels (safe to call multiple times)
        NotificationHelper.createChannels(this);

        Log.i(TAG, "PhishGuard Accessibility Service connected.");
    }

    // ══════════════════════════════════════════════════════════════
    // Main event handler
    // ══════════════════════════════════════════════════════════════
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) return;

        String pkg = event.getPackageName() != null
                ? event.getPackageName().toString() : "";

        // Only process monitored apps
        if (!MONITORED_PACKAGES.contains(pkg)) return;

        int eventType = event.getEventType();

        // ── Case 1: Notification heads-up / status bar ────────────
        if (eventType == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED) {
            handleNotificationEvent(event, pkg);
        }
        // ── Case 2: On-screen text change (message bubbles) ───────
        else if (eventType == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            handleTextChangeEvent(event, pkg);
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Handle notification event (heads-up cards)
    // ══════════════════════════════════════════════════════════════
    private void handleNotificationEvent(AccessibilityEvent event, String pkg) {
        Parcelable parcelable = event.getParcelableData();
        if (!(parcelable instanceof Notification)) return;

        Notification notif = (Notification) parcelable;

        // Read notification extras
        Bundle extras = notif.extras;
        if (extras == null) return;

        String title = safeString(extras.getCharSequence(Notification.EXTRA_TITLE));
        String text  = safeString(extras.getCharSequence(Notification.EXTRA_TEXT));
        String big   = safeString(extras.getCharSequence(Notification.EXTRA_BIG_TEXT));

        // Combine all text to maximise URL detection
        String combined = title + " " + text + " " + big;

        processText(combined, pkg);
    }

    // ══════════════════════════════════════════════════════════════
    // Handle on-screen text change (visible message bubbles)
    // ══════════════════════════════════════════════════════════════
    private void handleTextChangeEvent(AccessibilityEvent event, String pkg) {
        // Read from event text list
        List<CharSequence> texts = event.getText();
        if (texts == null || texts.isEmpty()) return;

        StringBuilder sb = new StringBuilder();
        for (CharSequence cs : texts) {
            if (cs != null) sb.append(cs).append(" ");
        }

        // Also try to read content description
        if (event.getContentDescription() != null) {
            sb.append(event.getContentDescription());
        }

        processText(sb.toString(), pkg);
    }

    // ══════════════════════════════════════════════════════════════
    // Core URL processing
    // ══════════════════════════════════════════════════════════════
    private void processText(String text, String pkg) {
        if (text == null || text.trim().isEmpty()) return;

        String url = SmsReceiver.extractUrl(text);
        if (url == null) return;

        // Skip if we recently detected this exact URL (dedup)
        if (recentlyDetected.contains(url)) return;
        if (recentlyDetected.size() >= MAX_RECENT) recentlyDetected.clear();
        recentlyDetected.add(url);

        String source = getSourceName(pkg);
        Log.d(TAG, "URL detected from " + source + ": " + url);

        // ── Fire notification ─────────────────────────────────────
        String title   = "🔗 ලින්ක් එකක් හඳුනාගත්තා!";
        String message = source + " ලේ link එකක් හමු විය:\n"
                + truncate(url, 60);
        String subText = "ආරක්ෂාව පරීක්ෂා කිරීමට tap කරන්න";

        NotificationHelper.showLinkDetectedNotification(
                this, url, title, message, subText, source
        );
    }

    // ══════════════════════════════════════════════════════════════
    // Helpers
    // ══════════════════════════════════════════════════════════════
    private String getSourceName(String pkg) {
        switch (pkg) {
            case "com.whatsapp":
            case "com.whatsapp.w4b":       return NotificationHelper.SOURCE_WHATSAPP;
            case "org.telegram.messenger":
            case "org.telegram.messenger.web": return NotificationHelper.SOURCE_TELEGRAM;
            case "com.google.android.gm":  return NotificationHelper.SOURCE_GMAIL;
            case "com.microsoft.teams":    return "Teams";
            case "com.viber.voip":         return "Viber";
            case "com.facebook.orca":      return "Messenger";
            default:                       return pkg;
        }
    }

    private String safeString(CharSequence cs) {
        return cs != null ? cs.toString() : "";
    }

    private String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max) + "…" : s;
    }

    @Override
    public void onInterrupt() {
        Log.w(TAG, "PhishGuard Accessibility Service interrupted.");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "PhishGuard Accessibility Service destroyed.");
    }
}