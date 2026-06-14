package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// PhishingModelRouter.java — PhishGuard v3.0
//
// Routes scan requests to either:
//   Method A — Separate Models (URL/SMS/Email specific TFLite files)
//   Method B — Combined Model  (single universal TFLite model)
//
// Measures exact inference latency using System.nanoTime().
// Handles dynamic mode switching without crashes.
// ══════════════════════════════════════════════════════════════════════

import android.content.Context;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

public class PhishingModelRouter {

    private static final String TAG = "PhishingModelRouter";

    // ── Scan modes ────────────────────────────────────────────
    public static final int METHOD_A_SEPARATE = 0;   // 3 distinct models
    public static final int METHOD_B_COMBINED = 1;   // 1 universal model

    // ── Input types ───────────────────────────────────────────
    public static final int INPUT_URL   = 0;
    public static final int INPUT_SMS   = 1;
    public static final int INPUT_EMAIL = 2;

    // ── Current mode ─────────────────────────────────────────
    private int currentMethod = METHOD_A_SEPARATE;
    private final Context context;

    // ── Method A classifiers (lazy-loaded) ───────────────────
    private TFLiteClassifier      urlClassifier;
    private SmsTFLiteClassifier   smsClassifier;
    private EmailTFLiteClassifier emailClassifier;

    // ── Method B classifier (lazy-loaded) ────────────────────
    private CombinedTFLiteClassifier combinedClassifier;

    // ── Loaded flags ──────────────────────────────────────────
    private boolean methodALoaded   = false;
    private boolean methodBLoaded   = false;

    // ════════════════════════════════════════════════════════
    // RouteResult — unified result from either method
    // ════════════════════════════════════════════════════════
    public static class RouteResult {
        // ── Detection result ─────────────────────────────────
        public final String        label;          // "Phishing" | "Legitimate" | "Spam" | etc.
        public final boolean       isThreat;
        public final float         confidence;     // 0–100
        public final List<String>  xaiReasons;

        // ── Method metadata ───────────────────────────────────
        public final int    methodUsed;            // METHOD_A or METHOD_B
        public final int    inputType;             // INPUT_URL / SMS / EMAIL
        public final String modelName;             // e.g. "phishing_model.tflite"
        public final String detectionLayer;        // "ml" | "hard_rules" | "allowlist"

        // ── Performance metrics ───────────────────────────────
        public final long   inferenceNanos;        // raw nanoTime delta
        public final long   inferenceMs;           // rounded milliseconds
        public final long   totalNanos;            // preprocessing + inference
        public final long   totalMs;

        public RouteResult(String label, boolean isThreat, float confidence,
                           List<String> xai, int method, int inputType,
                           String modelName, String layer,
                           long inferenceNanos, long totalNanos) {
            this.label           = label;
            this.isThreat        = isThreat;
            this.confidence      = confidence;
            this.xaiReasons      = xai != null ? xai : new ArrayList<>();
            this.methodUsed      = method;
            this.inputType       = inputType;
            this.modelName       = modelName;
            this.detectionLayer  = layer;
            this.inferenceNanos  = inferenceNanos;
            this.inferenceMs     = inferenceNanos / 1_000_000L;
            this.totalNanos      = totalNanos;
            this.totalMs         = totalNanos / 1_000_000L;
        }

        /** Human-readable latency string for UI display */
        public String latencyLabel() {
            if (inferenceMs < 1) {
                return inferenceNanos / 1_000 + " µs";
            }
            return inferenceMs + " ms";
        }

        /** Full performance string for UI display */
        public String performanceSummary() {
            String method = methodUsed == METHOD_A_SEPARATE ? "Method A" : "Method B";
            return method + " | " + modelName + "\n"
                    + "Inference : " + latencyLabel() + "\n"
                    + "Total     : " + totalMs + " ms";
        }

        /** Short summary for result card */
        public String primaryReason() {
            return xaiReasons.isEmpty() ? "" : xaiReasons.get(0);
        }
    }

    // ════════════════════════════════════════════════════════
    // Constructor
    // ════════════════════════════════════════════════════════
    public PhishingModelRouter(Context context) {
        this.context = context.getApplicationContext();
        // Pre-load Method A on construction (default mode)
        loadMethodA();
    }

    // ════════════════════════════════════════════════════════
    // Mode switching
    // ════════════════════════════════════════════════════════
    public void setMethod(int method) {
        if (method == currentMethod) return;
        currentMethod = method;

        if (method == METHOD_A_SEPARATE && !methodALoaded) {
            loadMethodA();
        } else if (method == METHOD_B_COMBINED && !methodBLoaded) {
            loadMethodB();
        }
        Log.i(TAG, "Switched to " + (method == METHOD_A_SEPARATE ? "Method A" : "Method B"));
    }

    public int getMethod() { return currentMethod; }

    // ── Lazy load Method A ────────────────────────────────────
    private void loadMethodA() {
        if (methodALoaded) return;
        try {
            urlClassifier   = new TFLiteClassifier(context);
            smsClassifier   = new SmsTFLiteClassifier(context);
            emailClassifier = new EmailTFLiteClassifier(context);
            methodALoaded   = true;
            Log.i(TAG, "Method A loaded (3 separate models)");
        } catch (Exception e) {
            Log.e(TAG, "Method A load failed: " + e.getMessage(), e);
        }
    }

    // ── Lazy load Method B ────────────────────────────────────
    private void loadMethodB() {
        if (methodBLoaded) return;
        try {
            combinedClassifier = new CombinedTFLiteClassifier(context);
            methodBLoaded      = true;
            Log.i(TAG, "Method B loaded (combined model)");
        } catch (Exception e) {
            Log.e(TAG, "Method B load failed: " + e.getMessage(), e);
        }
    }

    // ════════════════════════════════════════════════════════
    // ROUTE — URL input
    // ════════════════════════════════════════════════════════
    public RouteResult routeUrl(String url) {
        long t0 = System.nanoTime();   // start total timer

        if (currentMethod == METHOD_A_SEPARATE) {
            if (!methodALoaded) loadMethodA();
            if (urlClassifier == null) return errorResult(INPUT_URL);

            long tInfStart = System.nanoTime();
            TFLiteClassifier.PredictResult r = urlClassifier.predict(url);
            long tInfEnd   = System.nanoTime();
            long tEnd      = System.nanoTime();

            return new RouteResult(
                    r.label,
                    r.isPhishing(),
                    r.phishingProb,
                    r.xaiReasons,
                    METHOD_A_SEPARATE,
                    INPUT_URL,
                    "phishing_model.tflite",
                    r.source,
                    tInfEnd - tInfStart,
                    tEnd    - t0
            );

        } else {
            if (!methodBLoaded) loadMethodB();
            if (combinedClassifier == null) return errorResult(INPUT_URL);

            long tInfStart = System.nanoTime();
            CombinedTFLiteClassifier.CombinedResult r = combinedClassifier.predict(url);
            long tInfEnd   = System.nanoTime();
            long tEnd      = System.nanoTime();

            return new RouteResult(
                    r.label,
                    r.isPhishing,
                    r.phishingProb,
                    r.xaiReasons,
                    METHOD_B_COMBINED,
                    INPUT_URL,
                    "combined_model.tflite",
                    "ml",
                    tInfEnd - tInfStart,
                    tEnd    - t0
            );
        }
    }

    // ════════════════════════════════════════════════════════
    // ROUTE — SMS input
    // ════════════════════════════════════════════════════════
    public RouteResult routeSms(String smsBody) {
        long t0 = System.nanoTime();

        if (currentMethod == METHOD_A_SEPARATE) {
            if (!methodALoaded) loadMethodA();
            if (smsClassifier == null) return errorResult(INPUT_SMS);

            long tInfStart = System.nanoTime();
            SmsTFLiteClassifier.SmsResult r = smsClassifier.predict(smsBody);
            long tInfEnd   = System.nanoTime();
            long tEnd      = System.nanoTime();

            float confidence = r.smishingProb > r.spamProb ? r.smishingProb : r.spamProb;
            return new RouteResult(
                    r.label,
                    r.isThreat,
                    confidence,
                    r.xaiReasons,
                    METHOD_A_SEPARATE,
                    INPUT_SMS,
                    "sms_model.tflite",
                    "ml",
                    tInfEnd - tInfStart,
                    tEnd    - t0
            );

        } else {
            if (!methodBLoaded) loadMethodB();
            if (combinedClassifier == null) return errorResult(INPUT_SMS);

            long tInfStart = System.nanoTime();
            CombinedTFLiteClassifier.CombinedResult r = combinedClassifier.predict(smsBody);
            long tInfEnd   = System.nanoTime();
            long tEnd      = System.nanoTime();

            return new RouteResult(
                    r.label,
                    r.isPhishing,
                    r.phishingProb,
                    r.xaiReasons,
                    METHOD_B_COMBINED,
                    INPUT_SMS,
                    "combined_model.tflite",
                    "ml",
                    tInfEnd - tInfStart,
                    tEnd    - t0
            );
        }
    }

    // ════════════════════════════════════════════════════════
    // ROUTE — Email input
    // ════════════════════════════════════════════════════════
    public RouteResult routeEmail(EmailTFLiteClassifier.EmailInput emailInput,
                                  String emailBodyForCombined) {
        long t0 = System.nanoTime();

        if (currentMethod == METHOD_A_SEPARATE) {
            if (!methodALoaded) loadMethodA();
            if (emailClassifier == null) return errorResult(INPUT_EMAIL);

            long tInfStart = System.nanoTime();
            EmailTFLiteClassifier.EmailResult r = emailClassifier.predict(emailInput);
            long tInfEnd   = System.nanoTime();
            long tEnd      = System.nanoTime();

            return new RouteResult(
                    r.isPhishing ? "Phishing" : "Legitimate",
                    r.isPhishing,
                    r.phishingProb,
                    r.xaiReasons,
                    METHOD_A_SEPARATE,
                    INPUT_EMAIL,
                    "email_phishing_model.tflite",
                    r.detectionLayer,
                    tInfEnd - tInfStart,
                    tEnd    - t0
            );

        } else {
            if (!methodBLoaded) loadMethodB();
            if (combinedClassifier == null) return errorResult(INPUT_EMAIL);

            // Combined model takes raw text — use body text
            String text = emailBodyForCombined != null ? emailBodyForCombined : "";
            if (!emailInput.from.isEmpty()) text = emailInput.from + " " + text;
            if (!emailInput.subject.isEmpty()) text = emailInput.subject + " " + text;

            long tInfStart = System.nanoTime();
            CombinedTFLiteClassifier.CombinedResult r = combinedClassifier.predict(text);
            long tInfEnd   = System.nanoTime();
            long tEnd      = System.nanoTime();

            return new RouteResult(
                    r.label,
                    r.isPhishing,
                    r.phishingProb,
                    r.xaiReasons,
                    METHOD_B_COMBINED,
                    INPUT_EMAIL,
                    "combined_model.tflite",
                    "ml",
                    tInfEnd - tInfStart,
                    tEnd    - t0
            );
        }
    }

    // ════════════════════════════════════════════════════════
    // Benchmark — run same input through BOTH methods
    // Returns [methodA_result, methodB_result]
    // ════════════════════════════════════════════════════════
    public RouteResult[] benchmark(String text, int inputType) {
        // Ensure both models loaded
        if (!methodALoaded) loadMethodA();
        if (!methodBLoaded) loadMethodB();

        RouteResult resultA, resultB;

        // Temporarily force Method A
        int saved = currentMethod;
        currentMethod = METHOD_A_SEPARATE;
        switch (inputType) {
            case INPUT_URL:   resultA = routeUrl(text);   break;
            case INPUT_SMS:   resultA = routeSms(text);   break;
            default:
                EmailTFLiteClassifier.EmailInput ei = new EmailTFLiteClassifier.EmailInput();
                ei.bodyText = text;
                resultA = routeEmail(ei, text);
        }

        // Force Method B
        currentMethod = METHOD_B_COMBINED;
        switch (inputType) {
            case INPUT_URL:   resultB = routeUrl(text);   break;
            case INPUT_SMS:   resultB = routeSms(text);   break;
            default:
                EmailTFLiteClassifier.EmailInput ei = new EmailTFLiteClassifier.EmailInput();
                ei.bodyText = text;
                resultB = routeEmail(ei, text);
        }

        currentMethod = saved;   // restore
        return new RouteResult[]{resultA, resultB};
    }

    // ── Error fallback result ─────────────────────────────────
    private RouteResult errorResult(int inputType) {
        List<String> xai = new ArrayList<>();
        xai.add("Model load error. assets/ folder ලේ .tflite files check කරන්න.");
        return new RouteResult(
                "Error", false, 0f, xai,
                currentMethod, inputType, "error", "error", 0L, 0L
        );
    }

    // ════════════════════════════════════════════════════════
    // Lifecycle
    // ════════════════════════════════════════════════════════
    public void close() {
        if (urlClassifier    != null) { urlClassifier.close();    urlClassifier    = null; }
        if (smsClassifier    != null) { smsClassifier.close();    smsClassifier    = null; }
        if (emailClassifier  != null) { emailClassifier.close();  emailClassifier  = null; }
        if (combinedClassifier!=null) { combinedClassifier.close();combinedClassifier=null;}
        methodALoaded = false;
        methodBLoaded = false;
        Log.i(TAG, "All models closed.");
    }
}