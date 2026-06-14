package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// NotificationDismissReceiver.java
// Handles "Dismiss" action button on PhishGuard notifications.
// ══════════════════════════════════════════════════════════════════════

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.core.app.NotificationManagerCompat;

public class NotificationDismissReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        int notifId = intent.getIntExtra("NOTIF_ID", -1);
        if (notifId != -1) {
            NotificationManagerCompat.from(context).cancel(notifId);
        }
    }
}