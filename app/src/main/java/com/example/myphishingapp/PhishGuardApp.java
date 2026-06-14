package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// PhishGuardApp.java — Application class
//
// Initialises NotificationHelper channels ONCE at app startup.
// Referenced in AndroidManifest.xml via android:name=".PhishGuardApp"
//
// Also handles POST_NOTIFICATIONS permission request on Android 13+.
// ══════════════════════════════════════════════════════════════════════

import android.app.Application;

public class PhishGuardApp extends Application {

    @Override
    public void onCreate() {
        super.onCreate();

        // Create notification channels once at startup
        // (safe to call multiple times — channels already exist = no-op)
        NotificationHelper.createChannels(this);
    }
}