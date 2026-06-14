package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// SmsTFLiteClassifier.java — PhishGuard v2.0
//
// SMS Phishing Detection (Ham / Spam / Smishing)
// Model: sms_model.tflite + sms_model_meta.json
//
// Pipeline (mirrors Python predict_sms_tflite()):
//   1. preprocess() — URL/Phone/Amount tokenisation
//   2. TF-IDF → sparse vector (vocab + IDF from JSON)
//   3. SVD projection (50K → 512 dense features)
//   4. StandardScaler
//   5. TFLite inference
//   6. Per-class threshold (Smishing / Spam)
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

public class SmsTFLiteClassifier {

    private static final String TAG = "SmsTFLiteClassifier";

    // ── Model files ───────────────────────────────────────────
    private static final String MODEL_FILE = "sms_model.tflite";
    private static final String META_FILE  = "sms_model_meta.json";

    // ── Labels ───────────────────────────────────────────────
    public static final int LABEL_HAM      = 0;
    public static final int LABEL_SPAM     = 1;
    public static final int LABEL_SMISHING = 2;

    // ── Model state ──────────────────────────────────────────
    private Interpreter tflite;
    private Map<String, Integer> vocabulary;
    private float[]   idfValues;
    private float[]   scalerMean;
    private float[]   scalerScale;
    private float     smishingThreshold;
    private float     spamThreshold;
    private int       nInputFeatures;  // TF-IDF vocab size
    private List<String> classNames;

    // ── PredictResult ─────────────────────────────────────────
    public static class SmsResult {
        public final String  label;         // "Ham" | "Spam" | "Smishing"
        public final int     labelIndex;    // 0 | 1 | 2
        public final float   hamProb;
        public final float   spamProb;
        public final float   smishingProb;
        public final List<String> xaiReasons;  // Sinhala explanations
        public final boolean isThreat;      // Spam or Smishing

        public SmsResult(String label, int idx,
                         float ham, float spam, float smishing,
                         List<String> xai) {
            this.label        = label;
            this.labelIndex   = idx;
            this.hamProb      = ham;
            this.spamProb     = spam;
            this.smishingProb = smishing;
            this.xaiReasons   = xai;
            this.isThreat     = idx == LABEL_SPAM || idx == LABEL_SMISHING;
        }

        public String primaryReason() {
            return xaiReasons.isEmpty() ? "" : xaiReasons.get(0);
        }
    }

    // ═════════════════════════════════════════════════════════
    // Constructor
    // ═════════════════════════════════════════════════════════
    public SmsTFLiteClassifier(Context context) {
        try {
            loadMeta(context);
            loadModel(context);
            Log.i(TAG, "SmsTFLiteClassifier ready — vocab=" + vocabulary.size()
                    + " svd=" + nInputFeatures);
        } catch (Exception e) {
            Log.e(TAG, "Init failed: " + e.getMessage(), e);
        }
    }

    // ── Load JSON metadata ────────────────────────────────────
    private void loadMeta(Context context) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(context.getAssets().open(META_FILE)));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        reader.close();

        JsonObject meta = new Gson().fromJson(sb.toString(), JsonObject.class);

        smishingThreshold = meta.get("smishing_threshold").getAsFloat();
        spamThreshold     = meta.get("spam_threshold").getAsFloat();
        nInputFeatures    = meta.get("n_features").getAsInt();

        // Class names
        classNames = new ArrayList<>();
        JsonArray cn = meta.getAsJsonArray("class_names");
        for (int i = 0; i < cn.size(); i++) classNames.add(cn.get(i).getAsString());

        // Vocabulary: array of words, index = position
        JsonArray vocabArr = meta.getAsJsonArray("vocabulary");
        vocabulary = new HashMap<>(vocabArr.size());
        for (int i = 0; i < vocabArr.size(); i++)
            vocabulary.put(vocabArr.get(i).getAsString(), i);

        // IDF values
        JsonArray idfArr = meta.getAsJsonArray("idf_values");
        idfValues = new float[idfArr.size()];
        for (int i = 0; i < idfArr.size(); i++)
            idfValues[i] = idfArr.get(i).getAsFloat();

        // StandardScaler
        JsonArray meanArr  = meta.getAsJsonArray("scaler_mean");
        JsonArray scaleArr = meta.getAsJsonArray("scaler_scale");
        scalerMean  = new float[meanArr.size()];
        scalerScale = new float[scaleArr.size()];
        for (int i = 0; i < meanArr.size(); i++)  scalerMean[i]  = meanArr.get(i).getAsFloat();
        for (int i = 0; i < scaleArr.size(); i++) scalerScale[i] = scaleArr.get(i).getAsFloat();
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
    public SmsResult predict(String smsText) {
        if (tflite == null) {
            List<String> err = new ArrayList<>();
            err.add("Model not loaded");
            return new SmsResult("Ham", 0, 100f, 0f, 0f, err);
        }

        try {
            // Step 1: Preprocess
            String clean = preprocess(smsText);

            // Step 2: TF-IDF vector (5K features directly)
            float[] tfidfVec = buildTfidfVector(clean);

            // Step 3: StandardScaler
            float[] scaled = scaleFeatures(tfidfVec);

            // Step 4: TFLite inference
            float[][] input  = new float[1][nInputFeatures];
            float[][] output = new float[1][3];
            input[0] = scaled;
            tflite.run(input, output);

            float hamP   = output[0][0] * 100f;
            float spamP  = output[0][1] * 100f;
            float smishP = output[0][2] * 100f;

            // Step 6: Per-class threshold
            int    labelIdx;
            String labelStr;
            if (output[0][2] >= smishingThreshold) {
                labelIdx = LABEL_SMISHING; labelStr = "Smishing";
            } else if (output[0][1] >= spamThreshold) {
                labelIdx = LABEL_SPAM;     labelStr = "Spam";
            } else {
                labelIdx = LABEL_HAM;      labelStr = "Ham";
            }

            // Step 7: Sinhala XAI
            List<String> xai = buildXai(smsText, clean, labelIdx, output[0]);

            return new SmsResult(labelStr, labelIdx, hamP, spamP, smishP, xai);

        } catch (Exception e) {
            Log.e(TAG, "Predict failed: " + e.getMessage(), e);
            List<String> err = new ArrayList<>();
            err.add("Detection error: " + e.getMessage());
            return new SmsResult("Ham", 0, 100f, 0f, 0f, err);
        }
    }

    // ═════════════════════════════════════════════════════════
    // TEXT PREPROCESSING
    // Mirrors Python preprocess_text() exactly
    // ═════════════════════════════════════════════════════════
    private String preprocess(String text) {
        if (text == null) return "";
        String t = text.toLowerCase();
        // URL → URL_TOKEN
        t = t.replaceAll("https?://\\S+|www\\.\\S+|bit\\.ly/\\S+", "url_token");
        // Phone numbers (7+ digits) → PHONE_TOKEN
        t = t.replaceAll("\\b\\d{7,}\\b", "phone_token");
        // Amounts/prices → AMOUNT_TOKEN
        t = t.replaceAll("(?:rs|£|\\$|€|usd)\\s*[\\d,]+(?:\\.\\d+)?|[\\d,]+(?:\\.\\d+)?\\s*(?:rs|£|\\$|€)",
                "amount_token");
        // Strip non-alphanumeric (keep spaces and underscores)
        t = t.replaceAll("[^a-z0-9\\s_]", " ");
        // Collapse whitespace
        t = t.replaceAll("\\s+", " ").trim();
        return t;
    }

    // ═════════════════════════════════════════════════════════
    // TF-IDF FEATURE VECTOR
    // Mirrors Python's manual TF-IDF reconstruction
    // ═════════════════════════════════════════════════════════
    private float[] buildTfidfVector(String cleanText) {
        float[] vec = new float[nInputFeatures];
        String[] words = cleanText.split("\\s+");
        if (words.length == 0) return vec;

        // Generate unigrams + bigrams + trigrams
        List<String> tokens = new ArrayList<>();
        for (String w : words) if (!w.isEmpty()) tokens.add(w);
        for (int i = 0; i < words.length - 1; i++)
            if (!words[i].isEmpty() && !words[i+1].isEmpty())
                tokens.add(words[i] + " " + words[i+1]);
        for (int i = 0; i < words.length - 2; i++)
            if (!words[i].isEmpty() && !words[i+1].isEmpty() && !words[i+2].isEmpty())
                tokens.add(words[i] + " " + words[i+1] + " " + words[i+2]);

        // Term frequency counts
        Map<Integer, Integer> tfCounts = new HashMap<>();
        for (String tok : tokens) {
            Integer idx = vocabulary.get(tok);
            if (idx != null) {
                Integer _cur = tfCounts.get(idx);
                tfCounts.put(idx, _cur != null ? _cur + 1 : 1);
            }
        }

        // TF-IDF with sublinear_tf (log scaling)
        int nTokens = Math.max(tokens.size(), 1);
        for (Map.Entry<Integer, Integer> e : tfCounts.entrySet()) {
            int   idx   = e.getKey();
            int   count = e.getValue();
            float tfVal = (float) Math.log(1.0 + (double) count / nTokens);
            vec[idx]    = tfVal * idfValues[idx];
        }
        return vec;
    }

    // ═════════════════════════════════════════════════════════
    // STANDARD SCALER
    // ═════════════════════════════════════════════════════════
    private float[] scaleFeatures(float[] raw) {
        float[] scaled = new float[raw.length];
        for (int i = 0; i < raw.length; i++)
            scaled[i] = (raw[i] - scalerMean[i]) / (scalerScale[i] + 1e-8f);
        return scaled;
    }

    // ═════════════════════════════════════════════════════════
    // SINHALA XAI ENGINE
    // Mirrors Python get_sms_xai_sinhala()
    // ═════════════════════════════════════════════════════════
    private List<String> buildXai(String rawText, String cleanText,
                                  int labelIdx, float[] proba) {
        List<String> flags = new ArrayList<>();
        String lower = rawText.toLowerCase();

        if (labelIdx == LABEL_HAM) {
            flags.add("✅ මෙම SMS message ආරක්ෂිතයි. Phishing හෝ spam ලක්ෂණ හඳුනාගත නොහැකිය.");
            return flags;
        }

        if (labelIdx == LABEL_SMISHING) {
            // 1. URL present
            if (cleanText.contains("url_token") ||
                    Pattern.compile("https?://|www\\.").matcher(lower).find()) {
                flags.add("🔗 SMS ලේ link/URL ඇත. Smishing attacks ලේ ව්‍යාජ links " +
                        "click කරවා personal details steal කරයි. Link tap නොකරන්න.");
            }
            // 2. Urgency
            String[] urgentWords = {"urgent","immediately","now","expire","suspended",
                    "blocked","today","limited"};
            List<String> found = new ArrayList<>();
            for (String w : urgentWords) if (lower.contains(w)) found.add(w);
            if (!found.isEmpty()) {
                flags.add("⏰ '" + found.get(0) + "' වැනි urgency words ඇත. " +
                        "Scammers ලා ඔබව ඉක්මනින් act කරවීමට මෙවැනි words use කරයි.");
            }
            // 3. Financial bait
            String[] finWords = {"prize","won","winner","claim","reward",
                    "congratulations","selected","cash","award"};
            List<String> finFound = new ArrayList<>();
            for (String w : finWords) if (lower.contains(w)) finFound.add(w);
            if (!finFound.isEmpty()) {
                flags.add("💰 '" + finFound.get(0) + "' — financial bait words ඇත. " +
                        "'ඔබ ජය ගත්තා' 'ත්‍යාගය claim කරන්න' — scam ලක්ෂණ.");
            }
            // 4. Personal info request
            String[] personalWords = {"kyc","otp","account","password","verify",
                    "atm","pin","bank","card","login","update"};
            List<String> perFound = new ArrayList<>();
            for (String w : personalWords) if (lower.contains(w)) perFound.add(w);
            if (!perFound.isEmpty()) {
                flags.add("🔐 '" + perFound.get(0) + "' — personal/financial info " +
                        "request ඇත. Bank/KYC/OTP SMS ලෙස pretend කිරීම smishing technique.");
            }
            // 5. Phone token
            if (cleanText.contains("phone_token")) {
                flags.add("📞 Suspicious phone number ඇත. Scammers ලා fake call centers " +
                        "ලේ numbers include කරයි. Call නොකරන්න.");
            }
            // 6. Amount
            if (cleanText.contains("amount_token")) {
                flags.add("💵 Specific amount/price mention ඇත. " +
                        "'Free' / 'Rs.2,00,000' ආකාරයේ offers genuine නොවෙයි.");
            }
            // 7. Score
            float smishPct = proba[2] * 100f;
            if (smishPct >= 90f)
                flags.add(String.format("🤖 AI Model: %.1f%% confidence — Smishing.", smishPct));
            else if (smishPct >= 70f)
                flags.add(String.format("🤖 AI Model: %.1f%% confidence — Likely Smishing.", smishPct));

            if (flags.isEmpty())
                flags.add("🤖 SMS pattern analysis ලේ smishing ලක්ෂණ හඳුනාගනු ලැබීය. " +
                        "Unknown sender ලෙ links/offers ලේ respond නොකරන්න.");

        } else if (labelIdx == LABEL_SPAM) {
            // Spam reasons
            String[] promoWords = {"free","offer","discount","deal","buy",
                    "subscribe","promotion","ringtone","txt","mobile"};
            List<String> promoFound = new ArrayList<>();
            for (String w : promoWords) if (lower.contains(w)) promoFound.add(w);
            if (!promoFound.isEmpty()) {
                flags.add("📢 '" + promoFound.get(0) + "' — promotional spam keywords ඇත. " +
                        "Unsolicited commercial message.");
            }
            if (Pattern.compile("reply|stop|opt out|unsubscribe").matcher(lower).find()) {
                flags.add("📵 'Reply STOP' / 'Opt out' instructions ඇත — " +
                        "bulk SMS marketing pattern.");
            }
            flags.add(String.format("🤖 AI Model: %.1f%% confidence — Spam.", proba[1] * 100f));
        }

        return flags;
    }

    public void close() {
        if (tflite != null) tflite.close();
    }
}