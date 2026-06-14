package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// CombinedTFLiteClassifier.java — PhishGuard v3.0
//
// Universal phishing classifier — handles URL / SMS / Email with ONE model.
// Model  : combined_model.tflite
// Vocab  : vocab.json
// Meta   : combined_meta.json
//
// Pipeline (mirrors Python predict_combined()):
//   1. Load vocab.json → token_map (word → int)
//   2. Lowercase + whitespace-split input text
//   3. Map tokens → int IDs (1 = [UNK], 0 = padding)
//   4. Pad / truncate to max_sequence_length
//   5. TFLite run: int32[1, SEQ] → float32[1, 1]
//   6. Apply optimal_threshold
//   7. Dynamic Sinhala XAI
// ══════════════════════════════════════════════════════════════════════

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.tensorflow.lite.Interpreter;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class CombinedTFLiteClassifier {

    private static final String TAG        = "CombinedClassifier";
    private static final String MODEL_FILE = "combined_model.tflite";
    private static final String VOCAB_FILE = "vocab.json";
    private static final String META_FILE  = "combined_meta.json";

    // ── Model state ───────────────────────────────────────────
    private Interpreter        tflite;
    private Map<String, Integer> tokenMap;   // word → token ID
    private int                seqLength;    // max_sequence_length
    private float              threshold;    // optimal_threshold

    // ── XAI patterns ─────────────────────────────────────────
    private static final Pattern URL_PAT  =
            Pattern.compile("https?://\\S+|www\\.\\S+");
    private static final Pattern IP_PAT   =
            Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern BRAND_PAT =
            Pattern.compile("paypa[l1]|g[o0]{2}g[l1]e|am[a@]z[o0]n|" +
                            "micros[o0]ft|[a@]pp[l1]e|netfl[i1]x",
                    Pattern.CASE_INSENSITIVE);

    private static final String[] URGENCY_WORDS = {
            "urgent","immediately","suspended","blocked","expire",
            "verify","confirm","kyc","otp","atm","limited","account"
    };
    private static final String[] FINANCIAL_WORDS = {
            "prize","won","winner","cash","reward","congratulations",
            "claim","invoice","payment","wire transfer","bank","credit card"
    };
    private static final String[] SHORTENERS = {
            "bit.ly","tinyurl","t.co","goo.gl","short.link","ow.ly","rb.gy"
    };

    // ═════════════════════════════════════════════════════════
    // CombinedResult
    // ═════════════════════════════════════════════════════════
    public static class CombinedResult {
        public final String       label;         // "Phishing" | "Legitimate"
        public final boolean      isPhishing;
        public final float        phishingProb;  // 0–100
        public final List<String> xaiReasons;

        public CombinedResult(String label, boolean isPhishing,
                              float prob, List<String> xai) {
            this.label        = label;
            this.isPhishing   = isPhishing;
            this.phishingProb = prob;
            this.xaiReasons   = xai != null ? xai : new ArrayList<>();
        }

        public String primaryReason() {
            return xaiReasons.isEmpty() ? "" : xaiReasons.get(0);
        }
    }

    // ═════════════════════════════════════════════════════════
    // Constructor
    // ═════════════════════════════════════════════════════════
    public CombinedTFLiteClassifier(Context context) {
        try {
            loadMeta(context);
            loadVocab(context);
            loadModel(context);
            Log.i(TAG, "CombinedTFLiteClassifier ready — vocab=" + tokenMap.size()
                    + " seqLen=" + seqLength + " threshold=" + threshold);
        } catch (Exception e) {
            Log.e(TAG, "Init failed: " + e.getMessage(), e);
        }
    }

    // ── Load combined_meta.json ───────────────────────────────
    private void loadMeta(Context context) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(context.getAssets().open(META_FILE)));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        reader.close();

        JsonObject meta = new Gson().fromJson(sb.toString(), JsonObject.class);
        seqLength = meta.get("max_sequence_length").getAsInt();
        threshold = meta.get("optimal_threshold").getAsFloat();
    }

    // ── Load vocab.json ───────────────────────────────────────
    // Format: ["", "[UNK]", "the", "your", ...]
    // index = token ID  (0=padding, 1=[UNK])
    private void loadVocab(Context context) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(context.getAssets().open(VOCAB_FILE)));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        reader.close();

        JsonArray vocabArr = new Gson().fromJson(sb.toString(), JsonArray.class);
        tokenMap = new HashMap<>(vocabArr.size());
        for (int i = 0; i < vocabArr.size(); i++) {
            tokenMap.put(vocabArr.get(i).getAsString(), i);
        }
    }

    // ── Load TFLite model ─────────────────────────────────────
    private void loadModel(Context context) throws Exception {
        AssetFileDescriptor afd = context.getAssets().openFd(MODEL_FILE);
        FileInputStream fis = new FileInputStream(afd.getFileDescriptor());
        MappedByteBuffer buffer = fis.getChannel().map(
                FileChannel.MapMode.READ_ONLY,
                afd.getStartOffset(), afd.getDeclaredLength());
        tflite = new Interpreter(buffer);
    }

    // ═════════════════════════════════════════════════════════
    // MAIN PREDICT
    // ═════════════════════════════════════════════════════════
    public CombinedResult predict(String inputText) {
        if (tflite == null || tokenMap == null) {
            List<String> err = new ArrayList<>();
            err.add("Combined model not loaded. assets/ folder ලේ files check කරන්න.");
            return new CombinedResult("Error", false, 0f, err);
        }

        try {
            // Step 1: Tokenise
            int[] tokenIds = tokenise(inputText);

            // Step 2: TFLite inference
            int[][]   input  = new int[1][seqLength];
            float[][] output = new float[1][1];
            input[0] = tokenIds;
            tflite.run(input, output);

            float prob      = output[0][0] * 100f;
            boolean phishing= output[0][0] >= threshold;
            String  label   = phishing ? "Phishing" : "Legitimate";

            // Step 3: Sinhala XAI
            List<String> xai = buildXai(inputText, prob, phishing);

            return new CombinedResult(label, phishing, prob, xai);

        } catch (Exception e) {
            Log.e(TAG, "Predict failed: " + e.getMessage(), e);
            List<String> err = new ArrayList<>();
            err.add("Detection error: " + e.getMessage());
            return new CombinedResult("Error", false, 0f, err);
        }
    }

    // ═════════════════════════════════════════════════════════
    // TOKENISATION
    // Mirrors Python predict_combined() tokenisation exactly:
    //   1. Lowercase
    //   2. Strip punctuation (keep alphanumeric + spaces)
    //   3. Split on whitespace
    //   4. Map to IDs (1=[UNK] for unknown tokens)
    //   5. Pad with 0 / truncate to seqLength
    // ═════════════════════════════════════════════════════════
    private int[] tokenise(String text) {
        // Lowercase + strip punctuation (mirrors Keras standardize)
        String clean = text.toLowerCase()
                .replaceAll("[^\\w\\s]", " ")
                .replaceAll("\\s+", " ")
                .trim();

        String[] words = clean.split(" ");
        int[] ids = new int[seqLength];  // default 0 = padding

        for (int i = 0; i < Math.min(words.length, seqLength); i++) {
            Integer id = tokenMap.get(words[i]);
            ids[i] = (id != null) ? id : 1;  // 1 = [UNK]
        }
        return ids;
    }

    // ═════════════════════════════════════════════════════════
    // SINHALA XAI ENGINE
    // Universal — works for URL / SMS / Email inputs
    // ═════════════════════════════════════════════════════════
    private List<String> buildXai(String text, float prob, boolean isPhishing) {
        List<String> flags = new ArrayList<>();
        if (!isPhishing) {
            flags.add("✅ Input ආරක්ෂිතයි. Phishing ලක්ෂණ හඳුනාගත නොහැකිය.");
            return flags;
        }

        String lower = text.toLowerCase();

        // 1. Brand mimicry
        if (BRAND_PAT.matcher(lower).find()) {
            flags.add("🏦 PayPal, Google, Amazon, Bank වැනි ප්‍රසිද්ධ ආයතනයක " +
                    "නමක් ව්‍යාජ ලෙස copy කර ඇත.");
        }

        // 2. IP in URL
        if (IP_PAT.matcher(lower).find()) {
            flags.add("🔢 IP address URL ලේ ඇත (192.168.x.x ආකාරය). " +
                    "නීත්‍යානුකූල sites domain names use කරයි.");
        }

        // 3. URL shortener
        for (String sh : SHORTENERS) {
            if (lower.contains(sh)) {
                flags.add("🔗 '" + sh + "' shortened URL ඇත. " +
                        "Scammers real destination සඟවීමට use කරයි.");
                break;
            }
        }

        // 4. No HTTPS
        java.util.regex.Matcher urlM = URL_PAT.matcher(lower);
        boolean hasUrl = false, hasHttpOnly = false;
        while (urlM.find()) {
            hasUrl = true;
            if (urlM.group().startsWith("http://")) hasHttpOnly = true;
        }
        if (hasUrl && hasHttpOnly) {
            flags.add("🔓 Insecure link (https:// නෑ). " +
                    "Passwords සහ OTP intercept කිරීම පහසු වේ.");
        }

        // 5. Urgency
        List<String> urgFound = new ArrayList<>();
        for (String w : URGENCY_WORDS) if (lower.contains(w)) urgFound.add(w);
        if (urgFound.size() >= 2) {
            flags.add("⏰ '" + urgFound.get(0) + "', '" + urgFound.get(1) +
                    "' — urgency words ඇත. Panic කරවා ඉක්මනින් act කරවීමේ " +
                    "scam technique.");
        } else if (urgFound.size() == 1) {
            flags.add("⏰ '" + urgFound.get(0) + "' — urgency indicator.");
        }

        // 6. Financial bait
        for (String w : FINANCIAL_WORDS) {
            if (lower.contains(w)) {
                flags.add("💰 '" + w + "' — financial bait ඇත. " +
                        "'ඔබ ජය ගත්තා' / 'ත්‍යාගය claim කරන්න' genuine නොවෙයි.");
                break;
            }
        }

        // 7. Many URLs
        int urlCount = 0;
        java.util.regex.Matcher um = URL_PAT.matcher(lower);
        while (um.find()) urlCount++;
        if (urlCount > 3) {
            flags.add("🔗 " + urlCount + " links ඇත — phishing content indicator.");
        }

        // 8. AI confidence
        if (prob >= 90f) {
            flags.add(String.format("🤖 AI Model: %.1f%% confidence — Phishing.", prob));
        } else if (prob >= 70f) {
            flags.add(String.format("🤖 AI Model: %.1f%% confidence — Likely Phishing.", prob));
        } else {
            flags.add(String.format("🤖 AI Model: %.1f%% P(phishing) " +
                    "— threshold %.0f%%.", prob, threshold * 100f));
        }

        if (flags.isEmpty()) {
            flags.add("🤖 Text pattern analysis ලේ phishing ලක්ෂණ හඳුනාගනු ලැබීය. " +
                    "Unknown sender ලෙ links/offers ලේ respond නොකරන්න.");
        }
        return flags;
    }

    // ═════════════════════════════════════════════════════════
    // Lifecycle
    // ═════════════════════════════════════════════════════════
    public void close() {
        if (tflite != null) {
            tflite.close();
            tflite = null;
        }
    }
}