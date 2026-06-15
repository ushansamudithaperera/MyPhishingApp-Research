package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// CombinedTFLiteClassifier.java — PhishGuard v4.0
//
// v4.0 Changes (3 critical fixes):
//
//   FIX 1 — preprocessText() mirrors Python smart_preprocess() EXACTLY:
//     "paypal-security.com/login?verify=1"
//     → remove scheme → replace [./\-?=&_:@#+%~|,;!] with spaces
//     → "paypal security com login verify 1"
//     Without this, URLs are ONE token → [UNK] → model learns nothing
//     → 40-60% probability for obvious threats.
//
//   FIX 2 — ALLOWLIST_DOMAINS checked BEFORE any ML inference:
//     facebook.com, google.com, github.com etc. → immediate SAFE return
//     (0.0 probability, no XAI, no TFLite call)
//
//   FIX 3 — Sinhala XAI fallback:
//     If phishing detected but no rule fired → inject:
//     "AI ආකෘතිය මගින් සැකසහිත රටාවක් හඳුනාගෙන ඇත."
//     XAI list is NEVER empty for a detected threat.
//
// Pipeline:
//   predict(inputText)
//     ├─ 1. Allowlist check → SAFE (bypass model)
//     ├─ 2. preprocessText() → mirrors Python smart_preprocess()
//     │     a) lowercase
//     │     b) IP → IP_TOKEN
//     │     c) URLs: remove scheme, replace URL punctuation with spaces
//     │     d) phone numbers → PHONE_TOKEN
//     │     e) amounts → AMOUNT_TOKEN
//     │     f) prepend SRC_URL / SRC_SMS / SRC_EMAIL prefix
//     │     g) collapse whitespace
//     ├─ 3. tokenise() → int[seqLength] via vocab.json
//     ├─ 4. TFLite run → float P(phishing)
//     └─ 5. buildXai() → Sinhala explanations (never empty for threats)
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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CombinedTFLiteClassifier {

    private static final String TAG        = "CombinedClassifier";
    private static final String MODEL_FILE = "combined_model.tflite";
    private static final String VOCAB_FILE = "vocab.json";
    private static final String META_FILE  = "combined_meta.json";

    // ── Model state ───────────────────────────────────────────
    private Interpreter          tflite;
    private Map<String, Integer> tokenMap;  // word → token ID
    private int                  seqLength; // max_sequence_length
    private float                threshold; // optimal_threshold (0.50)

    // ════════════════════════════════════════════════════════════
    // FIX 2 — ALLOWLIST_DOMAINS
    // Checked FIRST in predict() — bypasses TFLite entirely.
    // Mirrors Python ALLOWLIST_DOMAINS set in Cell 3.
    // ════════════════════════════════════════════════════════════
    private static final Set<String> ALLOWLIST_DOMAINS = new HashSet<>(Arrays.asList(
            // Major tech
            "google.com", "gmail.com", "youtube.com", "googleapis.com",
            "github.com", "githubusercontent.com", "githubassets.com",
            "microsoft.com", "office.com", "live.com", "outlook.com",
            "apple.com", "icloud.com",
            "amazon.com", "aws.amazon.com",
            "facebook.com", "fb.com", "instagram.com", "whatsapp.com",
            "twitter.com", "x.com",
            "linkedin.com",
            "wikipedia.org", "wikimedia.org",
            "stackoverflow.com",
            "openai.com", "chatgpt.com",
            "anthropic.com",
            "cloudflare.com",
            "mozilla.org",
            "python.org",
            "reddit.com",
            "netflix.com",
            "adobe.com",
            "dropbox.com",
            "slack.com",
            "zoom.us",
            "shopify.com",
            "kaggle.com",
            "huggingface.co",
            "arxiv.org",
            "tensorflow.org",
            "pytorch.org",
            // Sri Lanka
            "kln.ac.lk", "cmb.ac.lk", "mora.ac.lk", "pdn.ac.lk",
            "gov.lk", "ac.lk",
            "dialog.lk", "slt.lk", "hutch.lk", "airtel.lk",
            "sampath.lk", "hnb.lk", "boc.lk", "nsb.lk", "peoples.lk",
            // Payment
            "paypal.com", "stripe.com", "visa.com", "mastercard.com"
    ));

    // ════════════════════════════════════════════════════════════
    // FIX 1 — Preprocessing patterns (mirrors Python Cell 3 v17)
    // ════════════════════════════════════════════════════════════

    // IP: 192.168.1.1 → IP_TOKEN
    private static final Pattern IP_PAT = Pattern.compile(
            "(?:\\b)(\\d{1,3}\\.){3}\\d{1,3}\\b"
    );

    // URLs to find and tokenise
    private static final Pattern URL_PAT = Pattern.compile(
            "https?://\\S+|www\\.\\S+",
            Pattern.CASE_INSENSITIVE
    );

    // URL punctuation → spaces  (Python _URL_PUNCT_RE)
    // Covers: . / - ? = & _ : @ # + % ~ | , ; !
    private static final Pattern URL_PUNCT_PAT = Pattern.compile(
            "[./\\-?=&_:@#+%~|,;!]"
    );

    // Phone numbers → PHONE_TOKEN
    private static final Pattern PHONE_PAT = Pattern.compile(
            "\\b\\d{7,}\\b"
    );

    // Money amounts → AMOUNT_TOKEN
    private static final Pattern AMOUNT_PAT = Pattern.compile(
            "(?i)(?:rs|lkr|\u00a3|\\$|\u20ac|usd)\\s*[\\d,]+(?:\\.\\d+)?"
                    + "|[\\d,]+(?:\\.\\d+)?\\s*(?:rs|lkr|\u00a3|\\$|\u20ac)"
    );

    // ── XAI-specific patterns ────────────────────────────────
    private static final Pattern XAI_IP_PAT = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    );
    private static final Pattern BRAND_PAT = Pattern.compile(
            "paypa[l1]|g[o0]{2}g[l1]e|am[a@]z[o0]n|micros[o0]ft|"
                    + "[a@]pp[l1]e|faceb[o0]{2}k|netfl[i1]x|"
                    + "inst[a@]gr[a@]m|twitt[e3]r|wh[a@]ts[a@]pp",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern XAI_URL_PAT = Pattern.compile(
            "https?://\\S+|www\\.\\S+",
            Pattern.CASE_INSENSITIVE
    );

    private static final String[] URGENCY_WORDS = {
            "urgent", "immediately", "suspended", "blocked", "expire",
            "verify", "confirm", "kyc", "otp", "limited",
            "unauthorized", "compromised", "locked", "restricted"
    };
    private static final String[] FINANCIAL_WORDS = {
            "prize", "won", "winner", "cash", "reward", "congratulations",
            "claim", "airdrop", "token", "crypto", "wallet", "stake"
    };
    private static final String[] SHORTENERS = {
            "bit.ly", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
            "rb.gy", "cutt.ly", "short.io", "t.ly", "tiny.cc",
            "shorturl.at", "adf.ly", "bc.vc", "wa.me", "lnkd.in"
    };
    private static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
            "tk", "ml", "ga", "cf", "gq", "pw", "xyz", "top", "click",
            "cfd", "sbs", "cyou", "bond", "bar", "quest", "lol",
            "shop", "store", "loan", "party", "faith", "date", "win",
            "bid", "live", "buzz", "cc", "vip", "monster", "cam", "zip"
    ));

    // ════════════════════════════════════════════════════════════
    // CombinedResult
    // ════════════════════════════════════════════════════════════
    public static class CombinedResult {
        public final String       label;          // "Phishing" | "Legitimate"
        public final boolean      isPhishing;
        public final float        phishingProb;   // 0–100
        public final List<String> xaiReasons;
        public final String       detectionLayer; // "allowlist" | "ml" | "error"

        public CombinedResult(String label, boolean isPhishing,
                              float prob, List<String> xai,
                              String layer) {
            this.label          = label;
            this.isPhishing     = isPhishing;
            this.phishingProb   = prob;
            this.xaiReasons     = (xai != null) ? xai : new ArrayList<>();
            this.detectionLayer = layer;
        }

        /** Backwards-compatible constructor */
        public CombinedResult(String label, boolean isPhishing,
                              float prob, List<String> xai) {
            this(label, isPhishing, prob, xai, "ml");
        }

        public String primaryReason() {
            return xaiReasons.isEmpty() ? "" : xaiReasons.get(0);
        }
    }

    // ════════════════════════════════════════════════════════════
    // Constructor
    // ════════════════════════════════════════════════════════════
    public CombinedTFLiteClassifier(Context context) {
        try {
            loadMeta(context);
            loadVocab(context);
            loadModel(context);
            Log.i(TAG, "CombinedTFLiteClassifier v4.0 ready"
                    + " vocab=" + tokenMap.size()
                    + " seqLen=" + seqLength
                    + " threshold=" + threshold);
        } catch (Exception e) {
            Log.e(TAG, "Init failed: " + e.getMessage(), e);
        }
    }

    // ── Load combined_meta.json ───────────────────────────────
    // MUST use UTF-8 — file contains native Sinhala Unicode
    private void loadMeta(Context context) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        context.getAssets().open(META_FILE),
                        StandardCharsets.UTF_8));   // UTF-8 critical for Sinhala
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
                new InputStreamReader(
                        context.getAssets().open(VOCAB_FILE),
                        StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        reader.close();

        JsonArray arr = new Gson().fromJson(sb.toString(), JsonArray.class);
        tokenMap = new HashMap<>(arr.size());
        for (int i = 0; i < arr.size(); i++) {
            tokenMap.put(arr.get(i).getAsString(), i);
        }
    }

    // ── Load TFLite model ─────────────────────────────────────
    private void loadModel(Context context) throws Exception {
        AssetFileDescriptor afd = context.getAssets().openFd(MODEL_FILE);
        FileInputStream fis = new FileInputStream(afd.getFileDescriptor());
        MappedByteBuffer buf = fis.getChannel().map(
                FileChannel.MapMode.READ_ONLY,
                afd.getStartOffset(),
                afd.getDeclaredLength());
        tflite = new Interpreter(buf);
    }

    // ════════════════════════════════════════════════════════════
    // MAIN PREDICT
    // ════════════════════════════════════════════════════════════
    public CombinedResult predict(String inputText) {
        return predict(inputText, "unknown");
    }

    public CombinedResult predict(String inputText, String source) {
        if (tflite == null || tokenMap == null) {
            List<String> err = new ArrayList<>();
            err.add("Model not loaded — assets/ folder ලේ files check කරන්න.");
            return new CombinedResult("Error", false, 0f, err, "error");
        }
        if (inputText == null || inputText.trim().isEmpty()) {
            List<String> err = new ArrayList<>();
            err.add("Empty input.");
            return new CombinedResult("Error", false, 0f, err, "error");
        }

        // ── FIX 2: Allowlist check — before any ML inference ──
        String domain = extractDomain(inputText);
        if (isAllowlisted(domain)) {
            Log.d(TAG, "Allowlisted domain: " + domain);
            return new CombinedResult(
                    "Legitimate", false, 0f,
                    new ArrayList<>(), "allowlist");
        }

        try {
            // ── FIX 1: Preprocess to match Python exactly ──────
            String processed = preprocessText(inputText, source);

            // Tokenise preprocessed text
            int[] tokenIds = tokenise(processed);

            // TFLite inference
            int[][]   input  = new int[1][seqLength];
            float[][] output = new float[1][1];
            input[0] = tokenIds;
            tflite.run(input, output);

            float rawProb   = output[0][0];       // 0.0–1.0
            float probPct   = rawProb * 100f;     // 0–100
            boolean phishing = rawProb >= threshold;
            String  label   = phishing ? "Phishing" : "Legitimate";

            // ── FIX 3: XAI with guaranteed fallback ───────────
            List<String> xai = buildXai(inputText, probPct, phishing, rawProb);

            return new CombinedResult(label, phishing, probPct, xai, "ml");

        } catch (Exception e) {
            Log.e(TAG, "Predict failed: " + e.getMessage(), e);
            List<String> err = new ArrayList<>();
            err.add("Detection error: " + e.getMessage());
            return new CombinedResult("Error", false, 0f, err, "error");
        }
    }

    // ════════════════════════════════════════════════════════════
    // FIX 1 — preprocessText()
    //
    // EXACTLY mirrors Python smart_preprocess() from Cell 3 v17.
    // This is the root fix for 40-60% probabilities on real threats.
    //
    // Python step          Java equivalent
    // ─────────────────    ─────────────────────────────────────────
    // text.lower()         text.toLowerCase()
    // IP_RE.sub(IP_TOKEN)  IP_PAT.matcher().replaceAll(" IP_TOKEN ")
    // URL_RE.sub(fn)       URL_PAT.matcher() → loop → tokenise each URL
    //   remove scheme        .replaceFirst("^https?://","")
    //   _URL_PUNCT_RE.sub    URL_PUNCT_PAT.replaceAll(" ")
    // PHONE_RE.sub(TOKEN)  PHONE_PAT.matcher().replaceAll(" PHONE_TOKEN ")
    // AMOUNT_RE.sub(TOKEN) AMOUNT_PAT.matcher().replaceAll(" AMOUNT_TOKEN ")
    // prefix + text        "SRC_URL " + text
    // re.sub(\s+,' ')      .replaceAll("\\s+"," ").trim()
    //
    // Example:
    //  IN:  "https://paypal-security.com/login?verify=1&user=abc"
    //  →    IP pass (no IP found)
    //  →    URL found → remove "https://"
    //       "paypal-security.com/login?verify=1&user=abc"
    //       → replace [./\-?=&] with spaces
    //       "paypal security com login verify 1 user abc"
    //  →    prefix: "SRC_URL paypal security com login verify 1 user abc"
    // ════════════════════════════════════════════════════════════
    public String preprocessText(String text, String source) {
        if (text == null) return "";

        // Step 1: lowercase
        text = text.toLowerCase();

        // Step 2: IP addresses → IP_TOKEN
        text = IP_PAT.matcher(text).replaceAll(" IP_TOKEN ");

        // Step 3: URL tokenisation
        // Find every URL, remove scheme, split on punctuation.
        // "paypal-security.com/login" → "paypal security com login"
        Matcher urlM = URL_PAT.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (urlM.find()) {
            String url = urlM.group();
            // a) strip scheme
            url = url.replaceFirst("(?i)^https?://", "");
            // b) URL punctuation → spaces
            url = URL_PUNCT_PAT.matcher(url).replaceAll(" ");
            // c) collapse
            url = url.replaceAll("\\s+", " ").trim();
            urlM.appendReplacement(sb, " " + url + " ");
        }
        urlM.appendTail(sb);
        text = sb.toString();

        // Step 4: Phone numbers → PHONE_TOKEN
        text = PHONE_PAT.matcher(text).replaceAll(" PHONE_TOKEN ");

        // Step 5: Money amounts → AMOUNT_TOKEN
        text = AMOUNT_PAT.matcher(text).replaceAll(" AMOUNT_TOKEN ");

        // Step 6: Source prefix
        String prefix;
        switch (source) {
            case "url":   prefix = "SRC_URL ";   break;
            case "sms":   prefix = "SRC_SMS ";   break;
            case "email": prefix = "SRC_EMAIL "; break;
            default:      prefix = "SRC_UNK ";
        }
        text = prefix + text;

        // Step 7: Collapse whitespace
        return text.replaceAll("\\s+", " ").trim();
    }

    /** Convenience overload (source = "unknown") */
    public String preprocessText(String text) {
        return preprocessText(text, "unknown");
    }

    // ════════════════════════════════════════════════════════════
    // TOKENISATION
    // Splits preprocessed text, builds unigrams + bigrams,
    // maps to vocab IDs (1=[UNK]), pads/truncates to seqLength.
    // Bigrams mirror ngrams=2 in Python TextVectorization.
    // ════════════════════════════════════════════════════════════
    private int[] tokenise(String processedText) {
        String[] words = processedText.trim().split("\\s+");
        List<String> tokens = new ArrayList<>();

        // Unigrams
        for (String w : words) {
            if (!w.isEmpty()) tokens.add(w);
        }
        // Bigrams (mirrors ngrams=2 in Python TextVectorization)
        for (int i = 0; i < words.length - 1; i++) {
            if (!words[i].isEmpty() && !words[i + 1].isEmpty()) {
                tokens.add(words[i] + " " + words[i + 1]);
            }
        }

        int[] ids = new int[seqLength]; // 0 = padding
        for (int i = 0; i < Math.min(tokens.size(), seqLength); i++) {
            Integer id = tokenMap.get(tokens.get(i));
            ids[i] = (id != null) ? id : 1; // 1 = [UNK]
        }
        return ids;
    }

    // ════════════════════════════════════════════════════════════
    // FIX 2 helpers — domain extraction + allowlist check
    // ════════════════════════════════════════════════════════════
    private String extractDomain(String text) {
        if (text == null) return "";
        // From URL with scheme
        Matcher m = Pattern.compile(
                "https?://([^/\\s?#:]+)",
                Pattern.CASE_INSENSITIVE).matcher(text);
        if (m.find()) return m.group(1).toLowerCase();
        // www. without scheme
        m = Pattern.compile(
                "(?:^|\\s)www\\.([^/\\s?#:]+)",
                Pattern.CASE_INSENSITIVE).matcher(text);
        if (m.find()) return m.group(1).toLowerCase();
        return "";
    }

    private boolean isAllowlisted(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        // Check exact + all parent domains
        // "mail.google.com" → checks "mail.google.com", "google.com"
        String[] parts = domain.split("\\.");
        for (int i = 0; i < parts.length - 1; i++) {
            StringBuilder candidate = new StringBuilder();
            for (int j = i; j < parts.length; j++) {
                if (j > i) candidate.append(".");
                candidate.append(parts[j]);
            }
            if (ALLOWLIST_DOMAINS.contains(candidate.toString())) {
                return true;
            }
        }
        return false;
    }

    // ════════════════════════════════════════════════════════════
    // FIX 3 — buildXai()
    //
    // Evaluates ALL rules — returns all that fired.
    // If phishing detected but ZERO rules fired → inject fallback:
    //   "AI ආකෘතිය මගින් සැකසහිත රටාවක් හඳුනාගෙන ඇත."
    // XAI list is NEVER empty for a detected threat.
    // ════════════════════════════════════════════════════════════
    private List<String> buildXai(String text, float probPct,
                                  boolean isPhishing, float rawProb) {
        List<String> flags = new ArrayList<>();

        if (!isPhishing) {
            return flags; // No XAI for safe results
        }

        String lower = text.toLowerCase();

        // Rule 1: IP address in URL
        if (XAI_IP_PAT.matcher(lower).find()) {
            flags.add("🔢 URL තුළ IP ලිපිනයක් (192.168.x.x ආකාරය) අඩංගු වේ. "
                    + "නිත්‍යානුකූල වෙබ් අඩවිවල domain නාම භාවිතා කෙරේ — "
                    + "මෙය ඉතා සැකසහිතයි.");
        }

        // Rule 2: Brand mimicry
        if (BRAND_PAT.matcher(lower).find()) {
            flags.add("🏦 PayPal, Google, Amazon, Bank වැනි ප්‍රසිද්ධ ආයතනයක නමක් "
                    + "ව්‍යාජ ලෙස භාවිතා කර ඇත. "
                    + "ඔබේ රහස්‍ය තොරතුරු සොරා ගැනීමට සකස් කළ link/message.");
        }

        // Rule 3: URL shortener
        for (String sh : SHORTENERS) {
            if (lower.contains(sh)) {
                flags.add("🔗 URL Shortener (" + sh + ") භාවිතා කර "
                        + "නියම ගමනාන්තය සඟවා ඇත. "
                        + "Scammers ලා සැබෑ phishing site ගොනු කිරීමට භාවිතා කරයි.");
                break;
            }
        }

        // Rule 4: Suspicious TLD
        String domain = extractDomain(text);
        if (!domain.isEmpty()) {
            String[] dParts = domain.split("\\.");
            if (dParts.length > 0) {
                String tld = dParts[dParts.length - 1];
                if (SUSPICIOUS_TLDS.contains(tld)) {
                    flags.add("🌐 සැකසහිත domain extension (." + tld + ") "
                            + "භාවිතා කර ඇත. "
                            + "Phishing sites ලා මෙවැනි extensions භාවිතා කරයි.");
                }
            }
            // Rule 5: Excessive subdomains
            if (dParts.length >= 4) {
                flags.add("🌐 Subdomains " + (dParts.length - 1) + "+ ක් ඇත — "
                        + "නිත්‍යානුකූල site ලෙස පෙනී සිටීමට සාදා ගත් URL. "
                        + "උදා: paypal.secure.verify.evil.com");
            }
        }

        // Rule 6: Insecure HTTP
        Matcher urlM = XAI_URL_PAT.matcher(lower);
        boolean hasUrl = false, hasHttpOnly = false;
        while (urlM.find()) {
            hasUrl = true;
            if (urlM.group().startsWith("http://")) hasHttpOnly = true;
        }
        if (hasUrl && hasHttpOnly) {
            flags.add("🔓 ආරක්ෂිත නොවන link (https:// නොමැත). "
                    + "ඔබ ඇතුල් කරන passwords සහ OTP intercept කිරීම පහසු වේ.");
        }

        // Rule 7: Urgency keywords (2+ triggers)
        List<String> urgFound = new ArrayList<>();
        for (String w : URGENCY_WORDS) {
            if (lower.contains(w)) urgFound.add(w);
        }
        if (urgFound.size() >= 2) {
            flags.add("⏰ හදිසි (Urgency) වචන ('"
                    + urgFound.get(0) + "', '" + urgFound.get(1) + "') "
                    + "භාවිතා කර ඇත. "
                    + "Scammers ලා ඔබව කලබලයට පත් කර ඉක්මනින් ක්‍රියා කරවීමට "
                    + "මෙය භාවිතා කරයි.");
        } else if (urgFound.size() == 1) {
            flags.add("⏰ '" + urgFound.get(0) + "' — urgency indicator.");
        }

        // Rule 8: Financial bait
        for (String w : FINANCIAL_WORDS) {
            if (lower.contains(w)) {
                flags.add("💰 මූල්‍ය ලාභ ('" + w + "') ගෙනහැර ඇත. "
                        + "ත්‍යාග ලාභ කරවීමේ නාමයෙන් credentials "
                        + "සොරා ගැනීමේ උත්සාහයකි.");
                break;
            }
        }

        // Rule 9: Multiple URLs
        int urlCount = 0;
        Matcher um = XAI_URL_PAT.matcher(lower);
        while (um.find()) urlCount++;
        if (urlCount >= 3) {
            flags.add("🔗 URLs " + urlCount + "ක් හඳුනාගන්නා ලදී — "
                    + "phishing messages වල bogus redirect links "
                    + "බොහෝ ගණනක් ඇතුළත් කෙරේ.");
        }

        // ── FIX 3: Guaranteed Sinhala fallback ────────────────
        // "AI ආකෘතිය මගින් සැකසහිත රටාවක් හඳුනාගෙන ඇත."
        if (flags.isEmpty()) {
            flags.add("🤖 AI ආකෘතිය මගින් සැකසහිත රටාවක් හඳුනාගෙන ඇත.");
        }

        // Always append AI confidence as last item
        flags.add(String.format(
                "🤖 AI Model: %.1f%% P(phishing) — threshold %.0f%%.",
                probPct, threshold * 100f));

        return flags;
    }

    // ════════════════════════════════════════════════════════════
    // Lifecycle
    // ════════════════════════════════════════════════════════════
    public void close() {
        if (tflite != null) {
            tflite.close();
            tflite = null;
        }
        Log.i(TAG, "CombinedTFLiteClassifier closed.");
    }
}