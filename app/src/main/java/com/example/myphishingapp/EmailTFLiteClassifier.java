package com.example.myphishingapp;

// ══════════════════════════════════════════════════════════════════════
// EmailTFLiteClassifier.java — PhishGuard v2.0
//
// Email Phishing Detection (Legitimate / Phishing)
// Model: email_phishing_model.tflite + email_phishing_mobile_meta.json
//
// Pipeline (mirrors Python EmailPhishingDetector):
//   Layer 1 — Allowlist (trusted domain + SPF/DKIM/DMARC pass)
//   Layer 2 — Hard rules (display name spoof + auth fail, IP in URL)
//   Layer 3 — TFLite ML (42 email features → StandardScaler → NN)
//   Layer 4 — Dynamic Sinhala XAI
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailTFLiteClassifier {

    private static final String TAG        = "EmailTFLiteClassifier";
    private static final String MODEL_FILE = "email_phishing_model.tflite";
    private static final String META_FILE  = "email_phishing_mobile_meta.json";

    // ── Model state ───────────────────────────────────────────
    private Interpreter tflite;
    private float[]      scalerMean;
    private float[]      scalerScale;
    private float        threshold;
    private int          nFeatures;
    private List<String> featureNames;
    private Map<String, String> sinhalaReasons;

    // ── Trusted domains allowlist ─────────────────────────────
    private static final Set<String> TRUSTED_DOMAINS = new HashSet<>(Arrays.asList(
            "google.com","microsoft.com","apple.com","amazon.com","amazonaws.com",
            "dropbox.com","paypal.com","stripe.com","linkedin.com","facebook.com",
            "github.com","twitter.com","salesforce.com","gov.lk","ac.lk",
            "kln.ac.lk","cmb.ac.lk","mora.ac.lk","pdn.ac.lk"
    ));

    // ── Free email providers ──────────────────────────────────
    private static final Set<String> FREE_EMAIL = new HashSet<>(Arrays.asList(
            "gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com",
            "mail.com","protonmail.com","icloud.com","gmx.com","zoho.com",
            "yandex.com","live.com","msn.com","rocketmail.com"
    ));

    // ── Brand display name triggers ───────────────────────────
    private static final String[] BRAND_TRIGGERS = {
            "paypal","google","microsoft","apple","amazon","facebook",
            "netflix","linkedin","dropbox","bank","wells fargo","chase",
            "hsbc","dhl","fedex","ups","docusign","tax","government","irs"
    };

    // ── Dangerous attachment extensions ──────────────────────
    private static final String[] DANGEROUS_EXTS = {
            ".exe",".scr",".com",".bat",".cmd",".vbs",".js",".jar",".msi",
            ".zip",".rar",".7z",".tar",".gz",".docm",".xlsm",".pptm",
            ".pdf.exe",".doc.exe",".iso",".img",".dmg",".lnk",".url"
    };

    // ── Phishing keywords with weights ───────────────────────
    private static final Map<String, Float> PHISHING_KWS = new HashMap<String, Float>() {{
        put("urgent", 1.0f); put("immediately", 1.0f); put("suspended", 1.0f);
        put("verify", 0.9f); put("confirm", 0.9f); put("compromised", 0.9f);
        put("invoice", 0.8f); put("payment", 0.8f); put("wire transfer", 1.0f);
        put("bank account", 0.9f); put("credit card", 0.9f); put("billing", 0.7f);
        put("login", 0.7f); put("click here", 0.9f); put("activate", 0.8f);
        put("security alert", 1.0f); put("account alert", 0.9f);
        put("penalty", 0.9f); put("lawsuit", 0.9f); put("overdue", 0.8f);
    }};

    // ── URL patterns ──────────────────────────────────────────
    private static final Pattern IP_URL_PATTERN =
            Pattern.compile("https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    private static final Pattern URL_PATTERN =
            Pattern.compile("https?://\\S+");
    private static final String[] URL_SHORTENERS = {
            "bit.ly","tinyurl","t.co","goo.gl","ow.ly","short.link","rb.gy","is.gd"
    };

    // ═════════════════════════════════════════════════════════
    // EmailInput — structured email data for feature extraction
    // ═════════════════════════════════════════════════════════
    public static class EmailInput {
        public String subject      = "";
        public String from         = "";
        public String replyTo      = "";
        public String authResults  = "";  // "spf=pass dkim=pass dmarc=fail" etc.
        public String bodyText     = "";
        public String bodyHtml     = "";
        public List<String> attachmentNames = new ArrayList<>();
        public int    numReceived  = 1;   // number of Received: headers
    }

    // ═════════════════════════════════════════════════════════
    // EmailResult
    // ═════════════════════════════════════════════════════════
    public static class EmailResult {
        public final String        label;         // "phishing" | "legitimate"
        public final float         phishingProb;  // 0-100
        public final float         legitimateProb;
        public final List<String>  xaiReasons;
        public final List<String>  triggeredFlags;
        public final String        detectionLayer; // "allowlist"|"hard_rules"|"ml"
        public final boolean       isPhishing;

        public EmailResult(String label, float phProb, float legProb,
                           List<String> xai, List<String> flags, String layer) {
            this.label          = label;
            this.phishingProb   = phProb;
            this.legitimateProb = legProb;
            this.xaiReasons     = xai;
            this.triggeredFlags = flags;
            this.detectionLayer = layer;
            this.isPhishing     = "phishing".equals(label);
        }

        public String primaryReason() {
            return xaiReasons.isEmpty() ? "" : xaiReasons.get(0);
        }
    }

    // ═════════════════════════════════════════════════════════
    // Constructor
    // ═════════════════════════════════════════════════════════
    public EmailTFLiteClassifier(Context context) {
        try {
            loadMeta(context);
            loadModel(context);
            Log.i(TAG, "EmailTFLiteClassifier ready — features=" + nFeatures
                    + " threshold=" + threshold);
        } catch (Exception e) {
            Log.e(TAG, "Init failed: " + e.getMessage(), e);
        }
    }

    private void loadMeta(Context context) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(context.getAssets().open(META_FILE)));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        reader.close();

        JsonObject meta  = new Gson().fromJson(sb.toString(), JsonObject.class);
        nFeatures        = meta.get("n_features").getAsInt();
        threshold        = meta.get("optimal_threshold").getAsFloat();

        JsonArray meanArr  = meta.getAsJsonArray("scaler_mean");
        JsonArray scaleArr = meta.getAsJsonArray("scaler_std");
        scalerMean  = new float[meanArr.size()];
        scalerScale = new float[scaleArr.size()];
        for (int i = 0; i < meanArr.size(); i++)  scalerMean[i]  = meanArr.get(i).getAsFloat();
        for (int i = 0; i < scaleArr.size(); i++) scalerScale[i] = scaleArr.get(i).getAsFloat();

        featureNames = new ArrayList<>();
        JsonArray fArr = meta.getAsJsonArray("feature_names");
        for (int i = 0; i < fArr.size(); i++) featureNames.add(fArr.get(i).getAsString());

        // Sinhala reasons map
        sinhalaReasons = new HashMap<>();
        JsonObject sr = meta.getAsJsonObject("sinhala_reasons");
        if (sr != null) {
            for (String key : sr.keySet())
                sinhalaReasons.put(key, sr.get(key).getAsString());
        }
    }

    private void loadModel(Context context) throws Exception {
        AssetFileDescriptor afd = context.getAssets().openFd(MODEL_FILE);
        FileInputStream fis = new FileInputStream(afd.getFileDescriptor());
        MappedByteBuffer buffer = fis.getChannel().map(
                FileChannel.MapMode.READ_ONLY,
                afd.getStartOffset(), afd.getDeclaredLength());
        tflite = new Interpreter(buffer);
    }

    // ═════════════════════════════════════════════════════════
    // MAIN PREDICT — 4-Layer pipeline
    // ═════════════════════════════════════════════════════════
    public EmailResult predict(EmailInput email) {
        List<String> flags = new ArrayList<>();
        List<String> xai   = new ArrayList<>();

        String fromLower     = email.from.toLowerCase();
        String bodyLower     = (email.bodyText + " " + email.bodyHtml).toLowerCase();
        String subjectLower  = email.subject.toLowerCase();
        String authLower     = email.authResults.toLowerCase();

        // ── Layer 1: Allowlist ────────────────────────────────
        String senderDomain = extractDomain(email.from);
        if (isTrustedDomain(senderDomain, authLower)) {
            xai.add("✅ විශ්වාසදායක sender domain — SPF/DKIM/DMARC සත්‍යාපනය සාර්ථකයි.");
            return new EmailResult("legitimate", 0f, 100f, xai, flags, "allowlist");
        }

        // ── Layer 2: Hard rules ───────────────────────────────
        int hardHits = 0;

        boolean spfFail   = authLower.contains("spf=fail")   || authLower.contains("spf=softfail");
        boolean dkimFail  = authLower.contains("dkim=fail");
        boolean dmarcFail = authLower.contains("dmarc=fail");
        boolean authFail  = spfFail || dkimFail || dmarcFail;

        if (spfFail)   { flags.add("spf_fail");  hardHits++; }
        if (dkimFail)  { flags.add("dkim_fail");  hardHits++; }
        if (dmarcFail) { flags.add("dmarc_fail"); hardHits++; }

        boolean displayNameSpoofed = isDisplayNameSpoofed(email.from);
        if (displayNameSpoofed && authFail) {
            flags.add("display_name_spoof");
            hardHits += 2;
        }

        boolean rawIpInUrl = IP_URL_PATTERN.matcher(bodyLower).find();
        if (rawIpInUrl && authFail) {
            flags.add("raw_ip_in_url");
            hardHits += 2;
        }

        boolean dangerousAttach = hasDangerousAttachment(email.attachmentNames);
        if (dangerousAttach && authFail) {
            flags.add("suspicious_attachment");
            hardHits += 2;
        }

        if (hardHits >= 3) {
            xai = buildXai(email, flags, 100f);
            return new EmailResult("phishing", 100f, 0f, xai, flags, "hard_rules");
        }

        // ── Layer 3: ML Inference ─────────────────────────────
        if (tflite == null) {
            xai.add("⚠️ Email model not loaded.");
            return new EmailResult("legitimate", 0f, 100f, xai, flags, "error");
        }

        float[] featureVec = extractFeatures(email);
        float[] scaled     = scaleFeatures(featureVec);

        float[][] input  = new float[1][nFeatures];
        float[][] output = new float[1][2];
        input[0] = scaled;
        tflite.run(input, output);

        float legProb  = output[0][0] * 100f;
        float phishProb= output[0][1] * 100f;
        String label   = (output[0][1] >= threshold) ? "phishing" : "legitimate";

        // ── Layer 4: Sinhala XAI ──────────────────────────────
        if ("phishing".equals(label)) {
            if (!flags.contains("spf_fail")  && spfFail)   flags.add("spf_fail");
            if (!flags.contains("dkim_fail") && dkimFail)  flags.add("dkim_fail");
            if (!flags.contains("dmarc_fail")&& dmarcFail) flags.add("dmarc_fail");
            if (displayNameSpoofed) flags.add("display_name_spoof");
            if (rawIpInUrl)         flags.add("raw_ip_in_url");
            if (dangerousAttach)    flags.add("suspicious_attachment");
            flags.add("ml_model_phishing");
            xai = buildXai(email, flags, phishProb);
        }

        return new EmailResult(label, phishProb, legProb, xai, flags, "ml");
    }

    // ═════════════════════════════════════════════════════════
    // FEATURE EXTRACTION — 42 email features
    // Mirrors Python extract_email_features()
    // ═════════════════════════════════════════════════════════
    private float[] extractFeatures(EmailInput email) {
        float[] f = new float[nFeatures];
        Map<String, Float> feats = new HashMap<>();

        String bodyText   = email.bodyText  != null ? email.bodyText  : "";
        String bodyHtml   = email.bodyHtml  != null ? email.bodyHtml  : "";
        String fromH      = email.from      != null ? email.from      : "";
        String replyTo    = email.replyTo   != null ? email.replyTo   : "";
        String authResults= email.authResults != null ? email.authResults : "";
        String subject    = email.subject   != null ? email.subject   : "";
        String combined   = (bodyText + " " + bodyHtml).toLowerCase();

        // Extract URLs from body
        List<String> urls = extractUrls(bodyText + " " + bodyHtml);

        // ── Structural features ───────────────────────────────
        feats.put("num_urls",         (float) urls.size());
        long httpsCount = 0, httpCount = 0;
        for (String u : urls) {
            if (u.startsWith("https://")) httpsCount++;
            else if (u.startsWith("http://")) httpCount++;
        }
        feats.put("num_https_urls",   (float) httpsCount);
        feats.put("num_http_urls",    (float) httpCount);
        feats.put("ratio_https_urls", urls.isEmpty() ? 0f : (float) httpsCount / urls.size());
        feats.put("has_raw_ip_url",   IP_URL_PATTERN.matcher(combined).find() ? 1f : 0f);
        feats.put("num_tracking_pixels", 0f); // not detectable without full HTML parsing
        feats.put("body_text_length", (float) bodyText.length());
        feats.put("body_text_entropy", (float) shannonEntropy(bodyText));
        int htmlLen = bodyHtml.length(), textLen = bodyText.length();
        feats.put("html_to_text_ratio", textLen > 0 ? (float) htmlLen / (htmlLen + textLen) : 0f);
        feats.put("is_html_only",     (htmlLen > 0 && textLen == 0) ? 1f : 0f);

        feats.put("subject_length",   (float) subject.length());
        feats.put("subject_entropy",  (float) shannonEntropy(subject));
        feats.put("subject_has_re_fwd",
                subject.toLowerCase().startsWith("re:") ||
                        subject.toLowerCase().startsWith("fwd:") ||
                        subject.toLowerCase().startsWith("fw:")  ? 1f : 0f);
        String[] subjWords = subject.toUpperCase().split("\\s+");
        int capsCount = 0;
        for (String w : subjWords) if (w.equals(w.toUpperCase()) && w.length() > 1) capsCount++;
        feats.put("subject_all_caps_ratio",
                subjWords.length > 0 ? (float) capsCount / subjWords.length : 0f);
        feats.put("num_received_hops", (float) Math.max(email.numReceived, 1));

        // ── Header anomaly features ───────────────────────────
        String authL = authResults.toLowerCase();
        feats.put("has_spf_fail",
                (authL.contains("spf=fail") || authL.contains("spf=softfail")) ? 1f : 0f);
        feats.put("has_dkim_fail",  authL.contains("dkim=fail")  ? 1f : 0f);
        feats.put("has_dmarc_fail", authL.contains("dmarc=fail") ? 1f : 0f);

        // auth_score: 0 = all fail, 1 = all pass
        float authScore = 0f;
        if (authL.contains("spf=pass"))   authScore += 0.33f;
        if (authL.contains("dkim=pass"))  authScore += 0.33f;
        if (authL.contains("dmarc=pass")) authScore += 0.34f;
        feats.put("auth_score", authScore);

        // From/Reply-To mismatch
        String fromDomain  = extractDomain(fromH);
        String replyDomain = extractDomain(replyTo);
        feats.put("from_replyto_mismatch",
                (!replyTo.isEmpty() && !fromDomain.equals(replyDomain)) ? 1f : 0f);
        feats.put("is_display_name_spoofed", isDisplayNameSpoofed(fromH) ? 1f : 0f);
        feats.put("sender_domain_length",    (float) fromDomain.length());
        feats.put("sender_domain_brand_similarity", brandSimilarity(fromDomain));
        feats.put("sender_is_free_email",    FREE_EMAIL.contains(fromDomain) ? 1f : 0f);
        feats.put("replyto_domain_mismatch",
                (!replyTo.isEmpty() && !fromDomain.equals(replyDomain)) ? 1f : 0f);

        // ── Attachment features ───────────────────────────────
        feats.put("num_attachments",          (float) email.attachmentNames.size());
        boolean hasDang = hasDangerousAttachment(email.attachmentNames);
        feats.put("has_dangerous_attachment", hasDang ? 1f : 0f);
        int dangCount = 0;
        for (String a : email.attachmentNames) {
            String al = a.toLowerCase();
            for (String ext : DANGEROUS_EXTS) if (al.endsWith(ext)) { dangCount++; break; }
        }
        feats.put("num_dangerous_attachments", (float) dangCount);
        double nameEntropy = 0;
        for (String a : email.attachmentNames) nameEntropy += shannonEntropy(a);
        feats.put("attachment_name_entropy",
                email.attachmentNames.isEmpty() ? 0f : (float)(nameEntropy / email.attachmentNames.size()));

        // ── NLP/Lexical features ──────────────────────────────
        float urgScore = 0f;
        int   urgCount = 0;
        for (Map.Entry<String, Float> kw : PHISHING_KWS.entrySet()) {
            if (combined.contains(kw.getKey())) {
                urgScore += kw.getValue();
                urgCount++;
            }
        }
        feats.put("urgency_keyword_score", urgScore);
        feats.put("urgency_keyword_count", (float) urgCount);

        String[] finKws = {"invoice","payment","wire transfer","bank account",
                "credit card","billing","refund","payroll","tax"};
        boolean hasFin = false;
        for (String kw : finKws) if (combined.contains(kw)) { hasFin = true; break; }
        feats.put("contains_financial_trigger", hasFin ? 1f : 0f);
        feats.put("num_exclamation_marks", (float) countChar(combined, '!'));

        // ── URL-level features ────────────────────────────────
        Set<String> urlDomains = new HashSet<>();
        for (String u : urls) urlDomains.add(extractDomain(u));
        feats.put("num_unique_url_domains", (float) urlDomains.size());

        float avgLen = 0;
        for (String u : urls) avgLen += u.length();
        feats.put("avg_url_length", urls.isEmpty() ? 0f : avgLen / urls.size());

        int ipUrlCount = 0;
        for (String u : urls) if (IP_URL_PATTERN.matcher(u).find()) ipUrlCount++;
        feats.put("num_ip_urls", (float) ipUrlCount);

        int shortCount = 0;
        for (String d : urlDomains)
            for (String sh : URL_SHORTENERS) if (d.contains(sh)) { shortCount++; break; }
        feats.put("num_shortened_urls", (float) shortCount);

        // ── Advanced NLP features (approximated) ─────────────
        feats.put("tfidf_phishing_score", urgScore * 0.1f);
        feats.put("domain_entropy",       (float) shannonEntropy(fromDomain));
        feats.put("levenshtein_brand_min_dist", minBrandLevenshtein(fromDomain));
        feats.put("body_word_count",
                (float) bodyText.split("\\s+").length);
        // external domains = url domains not matching sender domain
        int extCount = 0;
        for (String d : urlDomains) if (!d.equals(fromDomain) && !d.isEmpty()) extCount++;
        feats.put("num_external_domains", (float) extCount);

        // Build ordered feature vector
        for (int i = 0; i < featureNames.size() && i < nFeatures; i++) {
            String name = featureNames.get(i);
            f[i] = (feats.containsKey(name) ? feats.get(name) : 0f);
        }
        return f;
    }

    // ═════════════════════════════════════════════════════════
    // SINHALA XAI
    // ═════════════════════════════════════════════════════════
    private List<String> buildXai(EmailInput email, List<String> flags, float phishProb) {
        List<String> xai = new ArrayList<>();

        for (String flag : flags) {
            String reason = sinhalaReasons.get(flag);
            if (reason != null && !xai.contains(reason)) xai.add(reason);
        }

        // Additional dynamic reasons
        String bodyLower = (email.bodyText + " " + email.bodyHtml).toLowerCase();

        if (flags.contains("ml_model_phishing") || phishProb >= threshold * 100) {
            if (xai.size() < 2) {
                if (bodyLower.contains("urgent") || bodyLower.contains("immediately"))
                    xai.add("🚨 ඉහළ හදිසි (Urgency) භාෂාව — 'urgent', 'immediately' වැනි words.");
                if (email.attachmentNames.size() > 0 && !flags.contains("suspicious_attachment"))
                    xai.add("📎 ඇමිණීමක් (Attachment) ඇත — open නොකරන්න.");
                List<String> urls = extractUrls(email.bodyText);
                if (urls.size() > 3 && !flags.contains("many_urls"))
                    xai.add("🔗 " + urls.size() + " links ඇත — Phishing email indicator.");
            }
            if (!flags.contains("ml_model_phishing"))
                xai.add(String.format("🤖 ML model: %.1f%% phishing confidence.", phishProb));
        }

        if (xai.isEmpty())
            xai.add("🤖 AI analysis ලේ phishing patterns හඳුනාගනු ලැබීය. " +
                    "Sender verify කර reply නොකරන්න.");

        return xai;
    }

    // ═════════════════════════════════════════════════════════
    // HELPERS
    // ═════════════════════════════════════════════════════════

    private float[] scaleFeatures(float[] raw) {
        float[] sc = new float[raw.length];
        for (int i = 0; i < raw.length; i++)
            sc[i] = (raw[i] - scalerMean[i]) / (scalerScale[i] + 1e-8f);
        return sc;
    }

    private boolean isTrustedDomain(String domain, String authLower) {
        if (!TRUSTED_DOMAINS.contains(domain)) return false;
        // Require at least SPF pass for trusted domain
        return authLower.contains("spf=pass") && authLower.contains("dkim=pass");
    }

    private String extractDomain(String header) {
        if (header == null || header.isEmpty()) return "";
        // Extract email address from "Display Name <email@domain.com>"
        Matcher m = Pattern.compile("<([^>]+)>").matcher(header);
        String email = m.find() ? m.group(1) : header;
        int atIdx = email.indexOf('@');
        return atIdx >= 0 ? email.substring(atIdx + 1).toLowerCase().trim() : "";
    }

    private boolean isDisplayNameSpoofed(String from) {
        if (from == null || from.isEmpty()) return false;
        Matcher m = Pattern.compile("^\"?([^\"<]+)\"?\\s*<([^>]+)>").matcher(from.trim());
        if (!m.find()) return false;
        String displayName = m.group(1).toLowerCase().trim();
        String emailAddr   = m.group(2).toLowerCase().trim();
        String emailDomain = emailAddr.contains("@")
                ? emailAddr.substring(emailAddr.indexOf('@') + 1) : "";
        for (String brand : BRAND_TRIGGERS)
            if (displayName.contains(brand) && !emailDomain.contains(brand)) return true;
        return false;
    }

    private boolean hasDangerousAttachment(List<String> names) {
        for (String name : names) {
            String lower = name.toLowerCase();
            for (String ext : DANGEROUS_EXTS) if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    private List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null) return urls;
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) urls.add(m.group());
        return urls;
    }

    private double shannonEntropy(String text) {
        if (text == null || text.isEmpty()) return 0.0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : text.toCharArray()) freq.put(c, (freq.containsKey(c) ? freq.get(c) : 0) + 1);
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = (double) count / text.length();
            entropy -= p * Math.log(p) / Math.log(2);
        }
        return entropy;
    }

    private float brandSimilarity(String domain) {
        if (domain.isEmpty()) return 0f;
        String domainCore = domain.contains(".") ? domain.split("\\.")[0] : domain;
        float maxSim = 0f;
        for (String brand : BRAND_TRIGGERS) {
            int dist = levenshtein(domainCore, brand);
            float sim = 1f - (float) dist / Math.max(domainCore.length(), brand.length());
            if (sim > maxSim) maxSim = sim;
        }
        return maxSim;
    }

    private float minBrandLevenshtein(String domain) {
        if (domain.isEmpty()) return 10f;
        String domainCore = domain.contains(".") ? domain.split("\\.")[0] : domain;
        float minDist = 10f;
        String[] brands = {"paypal","google","amazon","microsoft","apple","facebook"};
        for (String b : brands) {
            float d = levenshtein(domainCore, b);
            if (d < minDist) minDist = d;
        }
        return minDist;
    }

    private int levenshtein(String a, String b) {
        int la = Math.min(a.length(), 10), lb = Math.min(b.length(), 10);
        a = a.substring(0, la); b = b.substring(0, lb);
        int[][] dp = new int[la+1][lb+1];
        for (int i = 0; i <= la; i++) dp[i][0] = i;
        for (int j = 0; j <= lb; j++) dp[0][j] = j;
        for (int i = 1; i <= la; i++)
            for (int j = 1; j <= lb; j++)
                dp[i][j] = a.charAt(i-1) == b.charAt(j-1)
                        ? dp[i-1][j-1]
                        : 1 + Math.min(dp[i-1][j-1], Math.min(dp[i-1][j], dp[i][j-1]));
        return dp[la][lb];
    }

    private int countChar(String s, char c) {
        int count = 0;
        for (char x : s.toCharArray()) if (x == c) count++;
        return count;
    }

    public void close() {
        if (tflite != null) tflite.close();
    }
}