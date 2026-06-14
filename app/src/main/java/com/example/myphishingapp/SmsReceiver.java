package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// SmsReceiver.java — PhishGuard v2.0
//
// Listens for incoming SMS messages in the background.
// Extracts URLs using Patterns.WEB_URL regex.
// Fires a high-priority notification if a URL is found.
// Tapping notification → MainActivity auto-scan.
// ══════════════════════════════════════════════════════════════════════

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;
import android.util.Patterns;

import java.util.regex.Matcher;

public class SmsReceiver extends BroadcastReceiver {

    private static final String TAG    = "PhishGuard_SMS";
    private static final String ACTION = "android.provider.Telephony.SMS_RECEIVED";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!ACTION.equals(intent.getAction())) return;

        Bundle bundle = intent.getExtras();
        if (bundle == null) return;

        Object[] pdus = (Object[]) bundle.get("pdus");
        if (pdus == null || pdus.length == 0) return;

        // API 23+ requires "format" parameter
        String format = bundle.getString("format");

        StringBuilder fullMessage = new StringBuilder();
        String sender = "Unknown";

        for (Object pdu : pdus) {
            SmsMessage sms;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                sms = SmsMessage.createFromPdu((byte[]) pdu, format);
            } else {
                //noinspection deprecation
                sms = SmsMessage.createFromPdu((byte[]) pdu);
            }
            if (sms == null) continue;
            fullMessage.append(sms.getMessageBody());
            sender = sms.getOriginatingAddress();
        }

        String body = fullMessage.toString();
        if (body.isEmpty()) return;

        Log.d(TAG, "SMS from: " + sender + " | body length: " + body.length());

        // ── Extract first URL ─────────────────────────────────────
        String extractedUrl = extractUrl(body);
        if (extractedUrl == null) {
            Log.d(TAG, "No URL found in SMS.");
            return;
        }

        Log.d(TAG, "URL extracted: " + extractedUrl);

        // ── Fire notification ─────────────────────────────────────
        String title   = "🔗 ලින්ක් එකක් හඳුනාගත්තා!";
        String message = "SMS: " + (sender != null ? sender : "Unknown")
                + "\n" + truncate(extractedUrl, 60);
        String subText = "ආරක්ෂාව පරීක්ෂා කිරීමට tap කරන්න";

        NotificationHelper.showLinkDetectedNotification(
                context, extractedUrl, title, message, subText,
                NotificationHelper.SOURCE_SMS
        );
    }

    // ── Extract first URL from text ───────────────────────────────
    public static String extractUrl(String text) {
        if (text == null || text.isEmpty()) return null;
        Matcher m = Patterns.WEB_URL.matcher(text);
        if (m.find()) {
            String url = m.group();
            // Ensure protocol prefix
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "https://" + url;
            }
            return url;
        }
        return null;
    }

    private String truncate(String s, int maxLen) {
        return s.length() > maxLen ? s.substring(0, maxLen) + "…" : s;
    }
}