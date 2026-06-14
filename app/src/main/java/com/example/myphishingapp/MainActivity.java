package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// MainActivity.java — PhishGuard v3.0 (A/B Research Mode)
//
// Features:
//   ✅ Method A / Method B toggle
//   ✅ PhishingModelRouter — unified scan entry point
//   ✅ System.nanoTime() inference latency measurement
//   ✅ Performance metrics card (Inference / Total / Model name)
//   ✅ Benchmark mode — runs both methods, shows comparison
//   ✅ URL / SMS / Email / QR tabs
//   ✅ Sinhala XAI + TTS
// ══════════════════════════════════════════════════════════════════════

import android.Manifest;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.speech.tts.TextToSpeech;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Patterns;
import android.view.View;
import android.view.accessibility.AccessibilityManager;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.android.material.tabs.TabLayout;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.json.JSONObject;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity
        implements TextToSpeech.OnInitListener {

    // ── Permission codes ──────────────────────────────────────
    private static final int REQ_SMS    = 100;
    private static final int REQ_CAMERA = 101;
    private static final int REQ_NOTIF  = 102;

    // ── Backend ───────────────────────────────────────────────
    private static final String    BACKEND_URL = "http://10.0.2.2:8000/attack";
    private static final MediaType JSON_MEDIA  = MediaType.parse("application/json; charset=utf-8");

    // ── URL validation regex ──────────────────────────────────
    private static final Pattern URL_PATTERN = Pattern.compile(
            "^(https?://)?" +
                    "((([a-zA-Z0-9\\-]+)\\.)+[a-zA-Z]{2,})" +
                    "(:\\d{1,5})?((/[^\\s]*)?(\\?[^\\s]*)?(#[^\\s]*)?)?$",
            Pattern.CASE_INSENSITIVE);

    // ── Method selector ───────────────────────────────────────
    private TextView btnMethodA, btnMethodB;
    private TextView tvMethodDesc;
    private Button   btnBenchmark;
    private boolean  benchmarkMode = false;

    // ── Tabs ──────────────────────────────────────────────────
    private TabLayout    tabLayout;
    private LinearLayout tabUrl, tabSms, tabEmail, tabQr;

    // ── URL tab ───────────────────────────────────────────────
    private TextInputLayout   tilUrl;
    private TextInputEditText etUrl;
    private Button            btnScanUrl;

    // ── SMS tab ───────────────────────────────────────────────
    private TextInputLayout   tilSms;
    private TextInputEditText etSms;
    private Button            btnScanSms;
    private LinearLayout      layoutSmsUrlPreview;
    private TextView          tvSmsExtractedUrl;

    // ── Email tab ─────────────────────────────────────────────
    private TextInputLayout   tilEmailSender, tilEmailBody;
    private TextInputEditText etEmailSender, etEmailBody;
    private Button            btnScanEmail;

    // ── QR tab ────────────────────────────────────────────────
    private Button       btnQrStart, btnQrScanNow;
    private LinearLayout layoutQrResult;
    private TextView     tvQrScannedUrl, tvQrStatus;
    private String       qrScannedUrl = "";

    // ── Result section ────────────────────────────────────────
    private LinearLayout         layoutResultSection, layoutLoading, layoutActionButtons;
    private CircularProgressView circularProgress;
    private TextView             tvScoreNumber, tvVerdict, tvSourceTag, tvScannedUrl;
    private TextView             tvStatusChip;

    // ── Performance metrics ───────────────────────────────────
    private CardView cardPerformance;
    private TextView tvInferenceTime, tvTotalTime, tvMethodUsed;

    // ── Benchmark card ────────────────────────────────────────
    private CardView     cardBenchmark;
    private TextView     tvBenchmarkALabel, tvBenchmarkATime, tvBenchmarkAVerdict;
    private TextView     tvBenchmarkBLabel, tvBenchmarkBTime, tvBenchmarkBVerdict;
    private LinearLayout layoutBenchmarkWinner;
    private TextView     tvBenchmarkWinner, tvBenchmarkDiff;

    // ── XAI card ──────────────────────────────────────────────
    private CardView     cardXai;
    private LinearLayout layoutXaiHeader, layoutXaiContent;
    private TextView     tvXaiReasons;
    private ImageView    ivXaiChevron;
    private ImageButton  btnTts;
    private boolean      xaiExpanded = true;

    // ── Action buttons ────────────────────────────────────────
    private Button   btnAllow, btnBlock, btnActiveDefense;
    private CardView cardDefenseResult;
    private TextView tvDefenseResult;

    // ── Logic ─────────────────────────────────────────────────
    private PhishingModelRouter router;     // ← unified router
    private TextToSpeech        tts;
    private boolean             ttsReady = false;
    private OkHttpClient        httpClient;

    private String currentMaliciousUrl = "";
    private String currentXaiText      = "";
    private int    currentTabIdx       = 0;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    // ═════════════════════════════════════════════════════════
    // onCreate
    // ═════════════════════════════════════════════════════════
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        requestAllPermissions();
        bindViews();

        router     = new PhishingModelRouter(this);
        httpClient = new OkHttpClient();
        tts        = new TextToSpeech(this, this);

        setupMethodSelector();
        setupTabLayout();
        setupUrlTab();
        setupSmsTab();
        setupEmailTab();
        setupQrTab();
        setupResultSection();

        mainHandler.postDelayed(this::checkAccessibilityService, 1500);
        handleIncomingIntent(getIntent());
    }

    // ═════════════════════════════════════════════════════════
    // Permissions
    // ═════════════════════════════════════════════════════════
    private void requestAllPermissions() {
        String[] perms = {Manifest.permission.RECEIVE_SMS,
                Manifest.permission.READ_SMS,
                Manifest.permission.CAMERA};
        boolean allOk = true;
        for (String p : perms)
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED)
                allOk = false;
        if (!allOk) ActivityCompat.requestPermissions(this, perms, REQ_SMS);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
        }
    }

    // ═════════════════════════════════════════════════════════
    // View binding
    // ═════════════════════════════════════════════════════════
    private void bindViews() {
        btnMethodA    = findViewById(R.id.btnMethodA);
        btnMethodB    = findViewById(R.id.btnMethodB);
        tvMethodDesc  = findViewById(R.id.tvMethodDesc);
        btnBenchmark  = findViewById(R.id.btnBenchmark);

        tabLayout     = findViewById(R.id.tabLayout);
        tabUrl        = findViewById(R.id.tabUrl);
        tabSms        = findViewById(R.id.tabSms);
        tabEmail      = findViewById(R.id.tabEmail);
        tabQr         = findViewById(R.id.tabQr);

        tilUrl        = findViewById(R.id.tilUrl);
        etUrl         = findViewById(R.id.etUrl);
        btnScanUrl    = findViewById(R.id.btnScanUrl);

        tilSms              = findViewById(R.id.tilSms);
        etSms               = findViewById(R.id.etSms);
        btnScanSms          = findViewById(R.id.btnScanSms);
        layoutSmsUrlPreview = findViewById(R.id.layoutSmsUrlPreview);
        tvSmsExtractedUrl   = findViewById(R.id.tvSmsExtractedUrl);

        tilEmailSender = findViewById(R.id.tilEmailSender);
        tilEmailBody   = findViewById(R.id.tilEmailBody);
        etEmailSender  = findViewById(R.id.etEmailSender);
        etEmailBody    = findViewById(R.id.etEmailBody);
        btnScanEmail   = findViewById(R.id.btnScanEmail);

        btnQrStart     = findViewById(R.id.btnQrStart);
        btnQrScanNow   = findViewById(R.id.btnQrScanNow);
        layoutQrResult = findViewById(R.id.layoutQrResult);
        tvQrScannedUrl = findViewById(R.id.tvQrScannedUrl);
        tvQrStatus     = findViewById(R.id.tvQrStatus);

        layoutResultSection = findViewById(R.id.layoutResultSection);
        layoutLoading       = findViewById(R.id.layoutLoading);
        layoutActionButtons = findViewById(R.id.layoutActionButtons);
        circularProgress    = findViewById(R.id.circularProgress);
        tvScoreNumber       = findViewById(R.id.tvScoreNumber);
        tvVerdict           = findViewById(R.id.tvVerdict);
        tvSourceTag         = findViewById(R.id.tvSourceTag);
        tvScannedUrl        = findViewById(R.id.tvScannedUrl);
        tvStatusChip        = findViewById(R.id.tvStatusChip);

        cardPerformance  = findViewById(R.id.cardPerformance);
        tvInferenceTime  = findViewById(R.id.tvInferenceTime);
        tvTotalTime      = findViewById(R.id.tvTotalTime);
        tvMethodUsed     = findViewById(R.id.tvMethodUsed);

        cardBenchmark        = findViewById(R.id.cardBenchmark);
        tvBenchmarkALabel    = findViewById(R.id.tvBenchmarkALabel);
        tvBenchmarkATime     = findViewById(R.id.tvBenchmarkATime);
        tvBenchmarkAVerdict  = findViewById(R.id.tvBenchmarkAVerdict);
        tvBenchmarkBLabel    = findViewById(R.id.tvBenchmarkBLabel);
        tvBenchmarkBTime     = findViewById(R.id.tvBenchmarkBTime);
        tvBenchmarkBVerdict  = findViewById(R.id.tvBenchmarkBVerdict);
        layoutBenchmarkWinner= findViewById(R.id.layoutBenchmarkWinner);
        tvBenchmarkWinner    = findViewById(R.id.tvBenchmarkWinner);
        tvBenchmarkDiff      = findViewById(R.id.tvBenchmarkDiff);

        cardXai          = findViewById(R.id.cardXai);
        layoutXaiHeader  = findViewById(R.id.layoutXaiHeader);
        layoutXaiContent = findViewById(R.id.layoutXaiContent);
        tvXaiReasons     = findViewById(R.id.tvXaiReasons);
        ivXaiChevron     = findViewById(R.id.ivXaiChevron);
        btnTts           = findViewById(R.id.btnTts);

        btnAllow          = findViewById(R.id.btnAllow);
        btnBlock          = findViewById(R.id.btnBlock);
        btnActiveDefense  = findViewById(R.id.btnActiveDefense);
        cardDefenseResult = findViewById(R.id.cardDefenseResult);
        tvDefenseResult   = findViewById(R.id.tvDefenseResult);
    }

    // ═════════════════════════════════════════════════════════
    // Method A / B selector
    // ═════════════════════════════════════════════════════════
    private void setupMethodSelector() {
        refreshMethodUI(PhishingModelRouter.METHOD_A_SEPARATE);

        btnMethodA.setOnClickListener(v -> selectMethod(PhishingModelRouter.METHOD_A_SEPARATE));
        btnMethodB.setOnClickListener(v -> selectMethod(PhishingModelRouter.METHOD_B_COMBINED));

        btnBenchmark.setOnClickListener(v -> {
            benchmarkMode = !benchmarkMode;
            btnBenchmark.setText(benchmarkMode ? "⚡ BENCHMARK ON" : "⚡ BENCHMARK");
            btnBenchmark.setTextColor(benchmarkMode
                    ? getResources().getColor(R.color.accent_orange)
                    : getResources().getColor(R.color.text_muted));
            if (benchmarkMode)
                Toast.makeText(this, "Benchmark ON — next scan runs BOTH methods",
                        Toast.LENGTH_SHORT).show();
            else
                cardBenchmark.setVisibility(View.GONE);
        });
    }

    private void selectMethod(int method) {
        router.setMethod(method);
        refreshMethodUI(method);
        hideResults();
        Toast.makeText(this,
                method == PhishingModelRouter.METHOD_A_SEPARATE
                        ? "Method A: Separate Models"
                        : "Method B: Combined Model",
                Toast.LENGTH_SHORT).show();
    }

    private void refreshMethodUI(int method) {
        boolean isA = method == PhishingModelRouter.METHOD_A_SEPARATE;

        // Active button — white bg with dark text
        btnMethodA.setBackgroundResource(isA
                ? R.drawable.method_active_bg
                : android.R.color.transparent);
        btnMethodA.setTextColor(getResources().getColor(
                isA ? R.color.bg_primary : R.color.text_muted));

        btnMethodB.setBackgroundResource(!isA
                ? R.drawable.method_active_bg
                : android.R.color.transparent);
        btnMethodB.setTextColor(getResources().getColor(
                !isA ? R.color.bg_primary : R.color.text_muted));

        tvMethodDesc.setText(isA
                ? "3 separate TFLite models — URL / SMS / Email specific"
                : "1 universal TFLite model — handles all input types");
    }

    // ═════════════════════════════════════════════════════════
    // Tab layout
    // ═════════════════════════════════════════════════════════
    private void setupTabLayout() {
        tabLayout.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(TabLayout.Tab tab) {
                currentTabIdx = tab.getPosition();
                tabUrl.setVisibility(currentTabIdx == 0 ? View.VISIBLE : View.GONE);
                tabSms.setVisibility(currentTabIdx == 1 ? View.VISIBLE : View.GONE);
                tabEmail.setVisibility(currentTabIdx == 2 ? View.VISIBLE : View.GONE);
                tabQr.setVisibility(currentTabIdx == 3 ? View.VISIBLE : View.GONE);
                hideResults();
            }
            @Override public void onTabUnselected(TabLayout.Tab tab) {}
            @Override public void onTabReselected(TabLayout.Tab tab) {}
        });
    }

    // ═════════════════════════════════════════════════════════
    // URL tab
    // ═════════════════════════════════════════════════════════
    private void setupUrlTab() {
        etUrl.addTextChangedListener(simple(() -> tilUrl.setError(null)));
        btnScanUrl.setOnClickListener(v -> {
            String url = text(etUrl);
            if (!validateUrl(url, tilUrl)) return;
            if (!url.startsWith("http")) url = "https://" + url;
            final String finalUrl = url;

            if (benchmarkMode) {
                runBenchmark(finalUrl, PhishingModelRouter.INPUT_URL, finalUrl);
            } else {
                final String u = finalUrl;
                runScan(() -> router.routeUrl(u), finalUrl);
            }
        });
    }

    // ═════════════════════════════════════════════════════════
    // SMS tab
    // ═════════════════════════════════════════════════════════
    private void setupSmsTab() {
        etSms.addTextChangedListener(simple(() -> {
            tilSms.setError(null);
            String ex = extractFirstUrl(text(etSms));
            tvSmsExtractedUrl.setText(ex != null ? ex : "");
            layoutSmsUrlPreview.setVisibility(ex != null ? View.VISIBLE : View.GONE);
        }));
        btnScanSms.setOnClickListener(v -> {
            String body = text(etSms);
            if (body.isEmpty()) { tilSms.setError("SMS body ලිවීම"); return; }
            String display = body.length() > 55 ? body.substring(0, 55) + "…" : body;

            if (benchmarkMode) {
                runBenchmark(body, PhishingModelRouter.INPUT_SMS, display);
            } else {
                runScan(() -> router.routeSms(body), display);
            }
        });
    }

    // ═════════════════════════════════════════════════════════
    // Email tab
    // ═════════════════════════════════════════════════════════
    private void setupEmailTab() {
        btnScanEmail.setOnClickListener(v -> {
            String sender = text(etEmailSender);
            String body   = text(etEmailBody);

            if (!sender.isEmpty() && !Patterns.EMAIL_ADDRESS.matcher(sender).matches()) {
                tilEmailSender.setError("Valid email ලිවීම"); return;
            }
            if (body.isEmpty()) { tilEmailBody.setError("Email body ලිවීම"); return; }

            EmailTFLiteClassifier.EmailInput emailInput =
                    new EmailTFLiteClassifier.EmailInput();
            emailInput.from     = sender;
            emailInput.bodyText = body;

            String display = sender.isEmpty() ? "(email body)" : sender;
            String combined = sender + " " + body;   // for Method B

            if (benchmarkMode) {
                runBenchmark(combined, PhishingModelRouter.INPUT_EMAIL, display);
            } else {
                runScan(() -> router.routeEmail(emailInput, combined), display);
            }
        });
    }

    // ═════════════════════════════════════════════════════════
    // QR tab — always uses URL routing
    // ═════════════════════════════════════════════════════════
    private void setupQrTab() {
        btnQrStart.setOnClickListener(v -> {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.CAMERA}, REQ_CAMERA);
                return;
            }
            IntentIntegrator i = new IntentIntegrator(this);
            i.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE);
            i.setPrompt("QR code ලේ camera point කරන්න");
            i.setBeepEnabled(true); i.setOrientationLocked(true); i.initiateScan();
        });
        btnQrScanNow.setOnClickListener(v -> {
            if (!qrScannedUrl.isEmpty()) {
                final String url = qrScannedUrl.startsWith("http")
                        ? qrScannedUrl : "https://" + qrScannedUrl;
                runScan(() -> router.routeUrl(url), url);
            }
        });
    }

    // ═════════════════════════════════════════════════════════
    // Universal scan runner (single method)
    // ═════════════════════════════════════════════════════════
    interface ScanTask { PhishingModelRouter.RouteResult run(); }

    private void runScan(ScanTask task, String displayLabel) {
        showScanLoading(displayLabel);
        new Thread(() -> {
            PhishingModelRouter.RouteResult result = task.run();
            mainHandler.post(() -> displaySingleResult(result, displayLabel));
        }).start();
    }

    // ═════════════════════════════════════════════════════════
    // Benchmark runner (both methods)
    // ═════════════════════════════════════════════════════════
    private void runBenchmark(String text, int inputType, String displayLabel) {
        showScanLoading(displayLabel);
        new Thread(() -> {
            PhishingModelRouter.RouteResult[] results =
                    router.benchmark(text, inputType);
            mainHandler.post(() -> displayBenchmarkResults(results, displayLabel));
        }).start();
    }

    // ═════════════════════════════════════════════════════════
    // Show scan loading state
    // ═════════════════════════════════════════════════════════
    private void showScanLoading(String displayLabel) {
        layoutResultSection.setVisibility(View.VISIBLE);
        layoutLoading.setVisibility(View.VISIBLE);
        layoutActionButtons.setVisibility(View.GONE);
        cardXai.setVisibility(View.GONE);
        cardBenchmark.setVisibility(View.GONE);
        btnActiveDefense.setVisibility(View.GONE);
        cardDefenseResult.setVisibility(View.GONE);
        cardPerformance.setVisibility(View.GONE);
        tvScannedUrl.setText(displayLabel);
        setStatusChip("SCANNING…", 0xFFF39C12);
    }

    // ═════════════════════════════════════════════════════════
    // Display single-method result
    // ═════════════════════════════════════════════════════════
    private void displaySingleResult(PhishingModelRouter.RouteResult r, String displayLabel) {
        layoutLoading.setVisibility(View.GONE);
        if (r == null) { setStatusChip("ERROR", 0xFFF39C12); return; }

        int score = (int) Math.min(r.confidence, 100f);
        animateScore(score);
        tvScannedUrl.setText(displayLabel);
        tvSourceTag.setText(
                (r.methodUsed == PhishingModelRouter.METHOD_A_SEPARATE ? "A" : "B")
                        + " | " + r.detectionLayer);

        // ── Performance metrics ────────────────────────────
        cardPerformance.setVisibility(View.VISIBLE);
        tvInferenceTime.setText("Inference: " + r.latencyLabel());
        tvTotalTime.setText("Total: " + r.totalMs + " ms");
        tvMethodUsed.setText(
                (r.methodUsed == PhishingModelRouter.METHOD_A_SEPARATE
                        ? "Method A" : "Method B")
                        + " | " + r.modelName);

        if (r.isThreat) {
            currentMaliciousUrl = displayLabel;
            tvVerdict.setText("⚠ " + r.label.toUpperCase());
            tvVerdict.setTextColor(0xFFE8394A);
            setStatusChip("THREAT", 0xFFE8394A);
            if (!r.xaiReasons.isEmpty()) showXaiCard(r.xaiReasons);
            layoutActionButtons.setVisibility(View.VISIBLE);
            btnActiveDefense.setVisibility(View.VISIBLE);
            if (!r.xaiReasons.isEmpty())
                speakSinhala("අවවාදයි! " +
                        r.xaiReasons.get(0).replaceAll("[^\\p{L}\\p{N}\\p{P}\\p{Z}]","").trim());
        } else {
            currentMaliciousUrl = "";
            tvVerdict.setText("✓ SAFE");
            tvVerdict.setTextColor(0xFF2ECC71);
            setStatusChip("SAFE", 0xFF2ECC71);
            layoutActionButtons.setVisibility(View.VISIBLE);
        }
    }

    // ═════════════════════════════════════════════════════════
    // Display benchmark results (Method A vs B)
    // ═════════════════════════════════════════════════════════
    private void displayBenchmarkResults(PhishingModelRouter.RouteResult[] results,
                                         String displayLabel) {
        layoutLoading.setVisibility(View.GONE);
        if (results == null || results.length < 2) {
            setStatusChip("ERROR", 0xFFF39C12); return;
        }

        PhishingModelRouter.RouteResult rA = results[0];
        PhishingModelRouter.RouteResult rB = results[1];

        // Show the current method's result in main card
        PhishingModelRouter.RouteResult primary =
                router.getMethod() == PhishingModelRouter.METHOD_A_SEPARATE ? rA : rB;
        displaySingleResult(primary, displayLabel);

        // ── Benchmark card ─────────────────────────────────
        cardBenchmark.setVisibility(View.VISIBLE);

        tvBenchmarkATime.setText("Inference: " + rA.latencyLabel()
                + " | Total: " + rA.totalMs + " ms");
        tvBenchmarkAVerdict.setText(rA.isThreat ? "⚠ " + rA.label : "✓ Safe");
        tvBenchmarkAVerdict.setTextColor(rA.isThreat ? 0xFFE8394A : 0xFF2ECC71);

        tvBenchmarkBTime.setText("Inference: " + rB.latencyLabel()
                + " | Total: " + rB.totalMs + " ms");
        tvBenchmarkBVerdict.setText(rB.isThreat ? "⚠ " + rB.label : "✓ Safe");
        tvBenchmarkBVerdict.setTextColor(rB.isThreat ? 0xFFE8394A : 0xFF2ECC71);

        // Winner
        layoutBenchmarkWinner.setVisibility(View.VISIBLE);
        long diff = Math.abs(rA.inferenceMs - rB.inferenceMs);
        if (rA.inferenceMs < rB.inferenceMs) {
            tvBenchmarkWinner.setText("Method A (Separate)");
            tvBenchmarkDiff.setText("by " + diff + " ms");
        } else if (rB.inferenceMs < rA.inferenceMs) {
            tvBenchmarkWinner.setText("Method B (Combined)");
            tvBenchmarkDiff.setText("by " + diff + " ms");
        } else {
            tvBenchmarkWinner.setText("Tie");
            tvBenchmarkDiff.setText("");
        }
    }

    // ═════════════════════════════════════════════════════════
    // Result section wiring
    // ═════════════════════════════════════════════════════════
    private void setupResultSection() {
        layoutXaiHeader.setOnClickListener(v -> {
            xaiExpanded = !xaiExpanded;
            layoutXaiContent.setVisibility(xaiExpanded ? View.VISIBLE : View.GONE);
            ivXaiChevron.animate().rotation(xaiExpanded ? 0 : 180).setDuration(200).start();
        });
        btnTts.setOnClickListener(v -> {
            if (!currentXaiText.isEmpty()) speakSinhala(currentXaiText);
        });
        btnAllow.setOnClickListener(v -> {
            Toast.makeText(this, "✓ Connection allowed", Toast.LENGTH_SHORT).show();
            hideResults();
        });
        btnBlock.setOnClickListener(v -> {
            Toast.makeText(this, "✕ Blocked.", Toast.LENGTH_LONG).show();
            hideResults();
        });
        btnActiveDefense.setOnClickListener(v -> {
            if (!currentMaliciousUrl.isEmpty()) sendDefenseRequest(currentMaliciousUrl);
        });
    }

    // ═════════════════════════════════════════════════════════
    // Score animation
    // ═════════════════════════════════════════════════════════
    private void animateScore(int target) {
        ValueAnimator anim = ValueAnimator.ofInt(0, target);
        anim.setDuration(800);
        anim.setInterpolator(new AccelerateDecelerateInterpolator());
        anim.addUpdateListener(animation -> {
            int val = (int) animation.getAnimatedValue();
            circularProgress.setProgress(val);
            tvScoreNumber.setText(String.valueOf(val));
            tvScoreNumber.setTextColor(val <= 30 ? 0xFF2ECC71
                    : val <= 60 ? 0xFFF39C12 : 0xFFE8394A);
        });
        anim.start();
    }

    private void showXaiCard(List<String> reasons) {
        StringBuilder sb = new StringBuilder();
        for (String r : reasons) sb.append(r).append("\n\n");
        currentXaiText = sb.toString().trim();
        tvXaiReasons.setText(currentXaiText);
        cardXai.setVisibility(View.VISIBLE);
        xaiExpanded = true;
        layoutXaiContent.setVisibility(View.VISIBLE);
        ivXaiChevron.setRotation(0f);
    }

    // ═════════════════════════════════════════════════════════
    // Active Defense
    // ═════════════════════════════════════════════════════════
    private void sendDefenseRequest(String malUrl) {
        btnActiveDefense.setEnabled(false);
        btnActiveDefense.setText("⏳ LAUNCHING...");
        String payload;
        try { JSONObject b = new JSONObject(); b.put("url", malUrl); payload = b.toString(); }
        catch (Exception e) { resetDefBtn(); return; }
        RequestBody rb  = RequestBody.create(payload, JSON_MEDIA);
        Request request = new Request.Builder().url(BACKEND_URL).post(rb).build();
        httpClient.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(Call c, IOException e) {
                mainHandler.post(() -> {
                    Toast.makeText(MainActivity.this, "Backend unreachable.", Toast.LENGTH_LONG).show();
                    resetDefBtn();
                });
            }
            @Override public void onResponse(Call c, Response r) throws IOException {
                String body = r.body() != null ? r.body().string() : "{}";
                mainHandler.post(() -> { showDefResult(body); resetDefBtn(); });
            }
        });
    }

    private void showDefResult(String body) {
        try {
            JSONObject j = new JSONObject(body);
            tvDefenseResult.setText("Defense Active ✓\nFields: "
                    + j.optInt("fields_found") + "\nStatus: " + j.optString("status"));
        } catch (Exception e) { tvDefenseResult.setText("Defense response received."); }
        cardDefenseResult.setVisibility(View.VISIBLE);
    }

    private void resetDefBtn() {
        btnActiveDefense.setEnabled(true);
        btnActiveDefense.setText("⚡ LAUNCH ACTIVE DEFENSE");
    }

    // ═════════════════════════════════════════════════════════
    // Accessibility Service check
    // ═════════════════════════════════════════════════════════
    private void checkAccessibilityService() {
        if (isAccessibilityServiceEnabled()) return;
        new AlertDialog.Builder(this)
                .setTitle("🛡 WhatsApp / Telegram Detection")
                .setMessage("WhatsApp සහ Telegram ලේ phishing links detect කිරීමට\n" +
                        "PhishGuard Accessibility Service enable කරන්නද?\n\n" +
                        "Settings → Accessibility → PhishGuard")
                .setPositiveButton("Enable Now", (d, w) ->
                        startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)))
                .setNegativeButton("Later", null).show();
    }

    private boolean isAccessibilityServiceEnabled() {
        AccessibilityManager am = (AccessibilityManager)
                getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (am == null) return false;
        String target = getPackageName() + "/" + PhishingAccessibilityService.class.getName();
        for (AccessibilityServiceInfo i :
                am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK))
            if (target.equals(i.getId())) return true;
        return false;
    }

    // ═════════════════════════════════════════════════════════
    // TTS
    // ═════════════════════════════════════════════════════════
    @Override
    public void onInit(int status) {
        if (status == TextToSpeech.SUCCESS) {
            Locale si = new Locale("si", "LK");
            if (tts.setLanguage(si) < 0) tts.setLanguage(Locale.ENGLISH);
            tts.setSpeechRate(0.9f);
            ttsReady = true;
        }
    }

    private void speakSinhala(String text) {
        if (ttsReady && !text.isEmpty())
            tts.speak(text, TextToSpeech.QUEUE_FLUSH, null, "pg_tts");
    }

    // ═════════════════════════════════════════════════════════
    // Incoming intent (from notification)
    // ═════════════════════════════════════════════════════════
    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent); setIntent(intent); handleIncomingIntent(intent);
    }

    private void handleIncomingIntent(Intent intent) {
        if (intent == null) return;
        String url    = intent.getStringExtra(NotificationHelper.EXTRA_URL);
        String source = intent.getStringExtra(NotificationHelper.EXTRA_SOURCE);
        boolean auto  = intent.getBooleanExtra("AUTO_SCAN", false);
        if (url != null && !url.isEmpty()) {
            tabLayout.selectTab(tabLayout.getTabAt(0));
            etUrl.setText(url);
            if (source != null)
                Toast.makeText(this, source + " ලේ link detect විය", Toast.LENGTH_SHORT).show();
            if (auto) {
                final String finalUrl = url.startsWith("http") ? url : "https://" + url;
                mainHandler.postDelayed(() -> runScan(() -> router.routeUrl(finalUrl), finalUrl), 400);
            }
        }
        String legacy = intent.getStringExtra("INCOMING_URL");
        if (legacy != null && !legacy.isEmpty()) {
            tabLayout.selectTab(tabLayout.getTabAt(1));
            etSms.setText("Auto-detected: " + legacy);
            final String finalUrl = legacy.startsWith("http") ? legacy : "https://" + legacy;
            mainHandler.postDelayed(() -> runScan(() -> router.routeUrl(finalUrl), finalUrl), 300);
        }
    }

    // ═════════════════════════════════════════════════════════
    // QR result
    // ═════════════════════════════════════════════════════════
    @Override
    protected void onActivityResult(int reqCode, int resCode, Intent data) {
        IntentResult r = IntentIntegrator.parseActivityResult(reqCode, resCode, data);
        if (r != null && r.getContents() != null) {
            qrScannedUrl = r.getContents();
            tvQrScannedUrl.setText(qrScannedUrl);
            layoutQrResult.setVisibility(View.VISIBLE);
            tvQrStatus.setText("✓ Scanned");
            btnQrScanNow.setEnabled(true);
            etUrl.setText(qrScannedUrl);
        } else super.onActivityResult(reqCode, resCode, data);
    }

    // ═════════════════════════════════════════════════════════
    // Helpers
    // ═════════════════════════════════════════════════════════
    private boolean validateUrl(String url, TextInputLayout til) {
        if (url.isEmpty()) { til.setError("URL ලිවීම"); return false; }
        if (!URL_PATTERN.matcher(url.startsWith("http") ? url : "https://"+url).matches()) {
            til.setError("Please enter a valid URL"); return false;
        }
        til.setError(null); return true;
    }

    private String extractFirstUrl(String text) {
        Matcher m = Patterns.WEB_URL.matcher(text != null ? text : "");
        return m.find() ? m.group() : null;
    }

    private String text(TextInputEditText et) {
        Editable e = et.getText(); return e != null ? e.toString().trim() : "";
    }

    private void setStatusChip(String label, int color) {
        tvStatusChip.setText("● " + label); tvStatusChip.setTextColor(color);
    }

    private void hideResults() {
        layoutResultSection.setVisibility(View.GONE);
        currentMaliciousUrl = ""; currentXaiText = "";
    }

    private TextWatcher simple(Runnable r) {
        return new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) { r.run(); }
            @Override public void afterTextChanged(Editable s) {}
        };
    }

    // ═════════════════════════════════════════════════════════
    // Lifecycle
    // ═════════════════════════════════════════════════════════
    @Override
    protected void onDestroy() {
        if (tts    != null) { tts.stop(); tts.shutdown(); }
        if (router != null) router.close();
        super.onDestroy();
    }
}