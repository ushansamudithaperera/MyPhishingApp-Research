package com.example.myphishingapp;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
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
import java.util.List;
import java.util.regex.Pattern;

// ══════════════════════════════════════════════════════════════════════
// TFLiteClassifier.java  — v2025.10
// Changes:
//   ✅ Layer 1: Allowlist check (google.com etc → always LEGITIMATE)
//   ✅ Layer 2: Hard rules (IP, @, brand mimicry → PHISHING if 2+ hits)
//   ✅ Layer 3: TFLite ML inference (unchanged)
//   ✅ Dynamic Sinhala XAI reasons (matches Python get_xai_explanation_sinhala)
//   ✅ PredictResult inner class — carries label + reasons together
// ══════════════════════════════════════════════════════════════════════
public class TFLiteClassifier {

    private Interpreter tflite;
    private float[] scalerMean;
    private float[] scalerScale;
    private float threshold;
    private int nFeatures;

    // ── PredictResult: label + Sinhala XAI reasons ─────────────────
    public static class PredictResult {
        public final String label;           // "phishing" | "legitimate" | "error"
        public final float phishingProb;     // 0.0 – 100.0
        public final List<String> xaiReasons; // Sinhala explanation bullets
        public final String source;          // "allowlist" | "hard_rules" | "ml"

        public PredictResult(String label, float phishingProb,
                             List<String> xaiReasons, String source) {
            this.label        = label;
            this.phishingProb = phishingProb;
            this.xaiReasons   = xaiReasons;
            this.source       = source;
        }

        public boolean isPhishing() { return "phishing".equals(label); }

        // First reason as single string (for TTS / simple display)
        public String primaryReason() {
            return xaiReasons.isEmpty() ? "" : xaiReasons.get(0);
        }

        // All reasons joined with newline
        public String allReasons() {
            StringBuilder sb = new StringBuilder();
            for (String r : xaiReasons) sb.append("• ").append(r).append("\n");
            return sb.toString().trim();
        }
    }

    // ── Allowlist — always LEGITIMATE (mirrors Python ALLOWLIST_DOMAINS) ─
    private static final String[] ALLOWLIST = {
            "google.com","github.com","microsoft.com","apple.com","amazon.com",
            "facebook.com","twitter.com","x.com","linkedin.com","wikipedia.org",
            "stackoverflow.com","youtube.com","openai.com","chatgpt.com",
            "anthropic.com","cloudflare.com","mozilla.org","python.org",
            "reddit.com","netflix.com","adobe.com","dropbox.com","slack.com",
            "zoom.us","shopify.com","notion.so","figma.com","kaggle.com",
            "gnu.org","sourceforge.net","archive.org","wikimedia.org",
            // AWS & Cloud
            "aws.amazon.com","skillbuilder.aws","docs.aws.amazon.com",
            "azure.microsoft.com","portal.azure.com","learn.microsoft.com",
            "cloud.google.com","firebase.google.com","developers.google.com",
            // Dev platforms
            "docker.com","cisco.com","canva.com","atlassian.com","salesforce.com",
            "oracle.com","ibm.com","redhat.com","ubuntu.com","debian.org",
            "postgresql.org","mysql.com","mongodb.com","kubernetes.io",
            "reactjs.org","vuejs.org","angular.io","nodejs.org","npmjs.com",
            "pypi.org","docs.python.org","developer.mozilla.org",
            "developer.apple.com","developer.android.com","docs.github.com",
            // Learning
            "udemy.com","coursera.org","edx.org","khanacademy.org",
            "pluralsight.com","comptia.org","pearsonvue.com","credly.com",
            "huggingface.co","deepseek.com","perplexity.ai","claude.ai",
            "grok.com","midjourney.com","replicate.com","paperswithcode.com",
            // Payment (official only)
            "paypal.com","stripe.com","wise.com","payoneer.com",
            // News & Reference
            "bbc.com","bbc.co.uk","cnn.com","reuters.com","apnews.com",
            "nytimes.com","forbes.com","techcrunch.com","wired.com",
            "arxiv.org","ieee.org","acm.org","researchgate.net",
            // Sri Lanka universities
            "kln.ac.lk","cmb.ac.lk","mora.ac.lk","pdn.ac.lk",
            "sjp.ac.lk","ruh.ac.lk","sliit.lk","nsbm.ac.lk",
            // Gaming & entertainment
            "steampowered.com","epicgames.com","ea.com","roblox.com",
            // E-commerce
            "ebay.com","etsy.com","walmart.com","aliexpress.com","newegg.com",
            // Productivity
            "trello.com","asana.com","monday.com","hubspot.com","zendesk.com",
    };

    // ── Trusted domains for is_trusted_domain feature (Java feature[21]) ─
    private static final String[] TRUSTED_DOMAINS_FEAT = {
            "google.com","facebook.com","amazon.com","microsoft.com",
            "apple.com","youtube.com","twitter.com","instagram.com",
            "linkedin.com","github.com","wikipedia.org"
    };

    // ── Phishing keywords (matches Python Cell 5 _KWS list) ─────────
    private static final String[] PHISH_KEYWORDS = {
            "login","signin","verify","update","secure","account",
            "banking","confirm","password","alert","suspend","unusual",
            "validate","authorize","credential"
    };

    // ── Brand mimicry patterns (for hard rules + feature) ───────────
    private static final Pattern BRAND_MIMICRY_PATTERN = Pattern.compile(
            "(paypa[l1]|g[o0]{2}g[l1]e|arn[a@]z[o0]n|micros[o0]ft|" +
                    "[a@]pp[l1]e|faceb[o0]{2}k|netfl[i1]x|yah[o0]{2}|tw[i1]tter)",
            Pattern.CASE_INSENSITIVE);

    // ── Suspicious TLDs ─────────────────────────────────────────────
    private static final String[] SUSP_TLD_HIGH = {".tk",".ml",".ga",".cf",".gq"};
    private static final String[] SUSP_TLD_MED  = {".xyz",".top",".click",".loan",".win"};
    private static final String[] SUSP_TLD_ALL  = {
            ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".loan",
            ".win",".racing",".download",".pw",".cfd",".sbs",".cyou"
    };

    // ── Levenshtein brands (matches Python _LEV_BRANDS) ─────────────
    private static final String[] LEV_BRANDS = {
            "paypal","google","amazon","microsoft","apple","facebook"
    };

    // ════════════════════════════════════════════════════════════════
    // Constructor
    // ════════════════════════════════════════════════════════════════
    public TFLiteClassifier(Context context) {
        try {
            loadMetaJson(context);
            loadModel(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void loadMetaJson(Context context) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(context.getAssets().open("phishing_mobile_meta.json"))
        );
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        reader.close();

        JsonObject meta = new Gson().fromJson(sb.toString(), JsonObject.class);
        nFeatures = meta.get("n_features").getAsInt();
        threshold = meta.get("optimal_threshold").getAsFloat();

        JsonArray meanArr = meta.getAsJsonArray("scaler_mean");
        scalerMean = new float[meanArr.size()];
        for (int i = 0; i < meanArr.size(); i++)
            scalerMean[i] = meanArr.get(i).getAsFloat();

        JsonArray scaleArr = meta.getAsJsonArray("scaler_scale");
        scalerScale = new float[scaleArr.size()];
        for (int i = 0; i < scaleArr.size(); i++)
            scalerScale[i] = scaleArr.get(i).getAsFloat();
    }

    private void loadModel(Context context) throws Exception {
        AssetFileDescriptor afd = context.getAssets().openFd("phishing_model.tflite");
        FileInputStream fis = new FileInputStream(afd.getFileDescriptor());
        FileChannel fc = fis.getChannel();
        MappedByteBuffer buffer = fc.map(
                FileChannel.MapMode.READ_ONLY,
                afd.getStartOffset(),
                afd.getDeclaredLength()
        );
        tflite = new Interpreter(buffer);
    }

    // ════════════════════════════════════════════════════════════════
    // MAIN PREDICT — 3-layer pipeline (mirrors Python predict_with_tflite)
    // ════════════════════════════════════════════════════════════════
    public PredictResult predict(String url) {
        if (tflite == null) {
            return new PredictResult("error", 0f, new ArrayList<>(), "error");
        }

        String host = extractHost(url);

        // ── Layer 1: Allowlist → always LEGITIMATE ──────────────────
        String hostNoWww = host.startsWith("www.") ? host.substring(4) : host;
        for (String allowed : ALLOWLIST) {
            if (hostNoWww.equals(allowed) || hostNoWww.endsWith("." + allowed)) {
                return new PredictResult("legitimate", 0f, new ArrayList<>(), "allowlist");
            }
        }

        // ── Layer 2: Hard rules (2+ hits → PHISHING) ───────────────
        int hardHits = 0;
        if (Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}").matcher(host).find()) hardHits++;
        if (url.contains("@") && !url.contains("mailto"))                      hardHits++;
        if (BRAND_MIMICRY_PATTERN.matcher(host).find())                        hardHits++;
        if (host.startsWith("xn--"))                                           hardHits++;

        if (hardHits >= 2) {
            float[] raw = extractFeatures(url);
            List<String> reasons = buildXaiReasons(raw, url, host);
            return new PredictResult("phishing", 100f, reasons, "hard_rules");
        }

        // ── Layer 3: TFLite ML inference ────────────────────────────
        float[] raw    = extractFeatures(url);
        float[] scaled = scaleFeatures(raw);

        float[][] input  = new float[1][nFeatures];
        float[][] output = new float[1][2];
        input[0] = scaled;
        tflite.run(input, output);

        float phishingProb = output[0][1] * 100f;
        String label = (output[0][1] >= threshold) ? "phishing" : "legitimate";

        List<String> reasons = new ArrayList<>();
        if ("phishing".equals(label)) {
            reasons = buildXaiReasons(raw, url, host);
        }

        return new PredictResult(label, phishingProb, reasons, "ml");
    }

    // ════════════════════════════════════════════════════════════════
    // SINHALA XAI — mirrors Python get_xai_explanation_sinhala()
    // ════════════════════════════════════════════════════════════════
    private List<String> buildXaiReasons(float[] f, String url, String host) {
        List<String> flags = new ArrayList<>();
        String urlLower = url.toLowerCase();

        // 1. IP address instead of domain name
        if (f[17] > 0) {
            flags.add("🔢 මෙම සබැඳිය වෙබ් අඩවියක නම වෙනුවට අංක පෙළක් " +
                    "(192.168.x.x වැනි) භාවිතා කරයි. " +
                    "සාමාන්‍ය නීත්‍යානුකූල වෙබ් අඩවි මෙසේ නොකරයි.");
        }

        // 2. @ symbol trick
        if (f[18] > 0) {
            flags.add("📧 මෙම සබැඳියේ \"@\" සලකුණ ඇත. " +
                    "Browser ඔබව ව්‍යාජ වෙබ් අඩවියකට රැගෙන යයි. " +
                    "ඉතා රවටාලිකාරී ක්‍රමයකි.");
        }

        // 3. Brand mimicry (paypa1, g00gle etc.)
        if (f[28] > 0) {
            flags.add("🏦 PayPal, Google, Facebook, Bank වැනි ප්‍රසිද්ධ " +
                    "ආයතනයක නමක් ව්‍යාජ ලෙස copy කර ඇත. " +
                    "ඔබේ password සහ bank details steal කිරීමට design කළ අඩවියකි.");
        }

        // 4. Phishing keywords — 2+ triggers
        int kwCount = (int) f[22];
        if (kwCount >= 2) {
            flags.add("🔑 \"login\", \"verify\", \"account\" වැනි ව්‍යාජ " +
                    "login page වල බහුලව දකින වචන " + kwCount + "ක් ඇත.");
        } else if (kwCount == 1 && (f[30] > 0 || f[17] > 0 || f[28] > 0)) {
            flags.add("🔑 ව්‍යාජ login indicator සහ අනෙකුත් suspicious signals " +
                    "ඒකාබද්ධව ඇත.");
        }

        // 5. Non-standard port
        if (f[20] > 0) {
            flags.add("🔌 සාමාන්‍ය නොවන port number (:8080 ආදිය) භාවිතා කෙරේ. " +
                    "නිල වෙබ් අඩවි port number hide කරයි.");
        }

        // 6. Suspicious file extension (.exe, .zip, etc.)
        if (f[27] > 0) {
            flags.add("⚠️ .exe, .apk, .bat වැනි file download link ඇත. " +
                    "Click කළොත් ඔබේ device ලේ harmful software install විය හැකිය.");
        }

        // 7. Very long URL
        int urlLen = (int) f[0];
        if (urlLen > 200) {
            flags.add("📏 මෙම සබැඳිය ඉතා දිගු (" + urlLen + " අකුරු). " +
                    "ව්‍යාජ සබැඳි සැබෑ ලිපිනය සැඟවීම සඳහා දිගු කෙරේ.");
        } else if (urlLen > 100) {
            flags.add("📏 මෙම සබැඳිය සාමාන්‍යයට වඩා දිගු (" + urlLen + " අකුරු). " +
                    "ව්‍යාජ අඩවිවල සබැඳි බොහෝ විට දිගු වේ.");
        }

        // 8. Complex subdomains (3+ levels)
        if (f[24] >= 3) {
            flags.add("🌐 සබැඳියේ ඉදිරිපිට domain ස්ථර ගොඩක් ඇත. " +
                    "ඇත්ත ගමනාන්තය domain name ලේ අවසාන කොටස. " +
                    "හොඳින් බලන්න.");
        }

        // 9. Suspicious TLD
        String tld = getTld(host);
        if (f[30] > 0) {
            flags.add("🌍 \"." + tld + "\" domain extension භාවිතා කෙරේ. " +
                    "නොමිලේ ලබාගත හැකි නිසා scammers ලා ප්‍රිය කරයි.");
        }

        // 10. No HTTPS
        if (f[15] == 0) {
            flags.add("🔓 මෙම සබැඳිය ආරක්ෂිත නොවේ (https:// නෑ). " +
                    "ඔබ enter කරන passwords, OTP, bank details රිංගා ගැනීම පහසු වේ.");
        }

        // 11. Brand name in path (bankofamerica, paypal etc. on unknown domain)
        if (f[31] > 0 && f[21] == 0) {
            flags.add("🏦 URL path ලේ ප්‍රසිද්ධ bank/brand නමක් ඇත නමුත් " +
                    "official domain නොවේ. ව්‍යාජ copy page ලක්ෂණයකි.");
        }

        // 12. WordPress paths (common phishing hosting)
        if (f[33] > 0) {
            flags.add("🖥️ WordPress ගොඩනැගිලි ව්‍යාජ login page host කිරීමට " +
                    "බොහෝ විට භාවිතා කෙරේ.");
        }

        // 13. AI-only fallback — no specific reason found
        if (flags.isEmpty()) {
            flags.add("🤖 ස්වයංක්‍රීය AI පරීක්ෂාවෙදී ව්‍යාජ යයි හඳුනාගනු ලැබීය. " +
                    "සබැඳියේ ස්වරූපය ව්‍යාජ අඩවිවලට සමානය. " +
                    "හොඳින් නොදන්නා සබැඳියකනම් visit නොකිරීම ආරක්ෂිතයි.");
        }

        return flags;
    }

    // ════════════════════════════════════════════════════════════════
    // Feature Extraction — 42 features, Java-aligned with Python Cell 5
    // ════════════════════════════════════════════════════════════════
    public float[] extractFeatures(String url) {
        float[] f = new float[nFeatures];
        String lowerUrl = url.toLowerCase();

        // ── Parse URL parts ────────────────────────────────────────
        String domain = extractHost(url);
        String path   = extractPath(url);
        String query  = url.contains("?") ? url.substring(url.indexOf("?") + 1) : "";

        String[] parts = domain.split("\\.");
        String domainCore = parts.length >= 2 ? parts[parts.length - 2] : domain;
        String tld = parts.length >= 1 ? "." + parts[parts.length - 1].toLowerCase() : "";

        // ── 0–4: Lengths ───────────────────────────────────────────
        f[0] = url.length();
        f[1] = domain.length();
        f[2] = path.length();
        f[3] = query.length();
        f[4] = tld.length() > 0 ? tld.length() - 1 : 0; // exclude leading dot

        // ── 5–14: Character counts ─────────────────────────────────
        f[5]  = countChar(url, '.');
        f[6]  = countChar(url, '-');
        f[7]  = countChar(url, '_');
        f[8]  = countChar(url, '/');
        f[9]  = countChar(url, '?');
        f[10] = countChar(url, '=');
        f[11] = countChar(url, '&');
        f[12] = countChar(url, '@');
        f[13] = countChar(url, '%');
        int digits = 0;
        for (char c : url.toCharArray()) if (Character.isDigit(c)) digits++;
        f[14] = digits;

        // ── 15–16: Protocol ────────────────────────────────────────
        f[15] = url.startsWith("https://") ? 1f : 0f;
        f[16] = (url.startsWith("http://") && !url.startsWith("https://")) ? 1f : 0f;

        // ── 17: has_ip_address ─────────────────────────────────────
        f[17] = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}").matcher(domain).find() ? 1f : 0f;

        // ── 18: has_at_symbol ──────────────────────────────────────
        f[18] = url.contains("@") ? 1f : 0f;

        // ── 19: has_double_slash (after protocol) ──────────────────
        String afterProto = url.replaceFirst("https?://", "");
        f[19] = afterProto.contains("//") ? 1f : 0f;

        // ── 20: has_port ───────────────────────────────────────────
        // netloc = domain part; check if port exists
        String netloc = domain;
        f[20] = netloc.matches(".*:\\d+$") ? 1f : 0f;

        // ── 21: is_trusted_domain ──────────────────────────────────
        float isTrusted = 0f;
        for (String t : TRUSTED_DOMAINS_FEAT) {
            if (domain.equals(t) || domain.endsWith("." + t)) { isTrusted = 1f; break; }
        }
        f[21] = isTrusted;

        // ── 22–23: Phishing keywords ───────────────────────────────
        int kwCount = 0;
        for (String kw : PHISH_KEYWORDS) if (lowerUrl.contains(kw)) kwCount++;
        f[22] = kwCount;
        f[23] = kwCount > 0 ? 1f : 0f;

        // ── 24: num_subdomains ─────────────────────────────────────
        int dotCount = 0;
        for (char c : domain.toCharArray()) if (c == '.') dotCount++;
        f[24] = Math.max(0, dotCount - 1);

        // ── 25–26: Domain digit/hyphen ─────────────────────────────
        boolean domDigit = false;
        for (char c : domainCore.toCharArray()) if (Character.isDigit(c)) { domDigit = true; break; }
        f[25] = domDigit ? 1f : 0f;
        f[26] = domainCore.contains("-") ? 1f : 0f;

        // ── 27: has_suspicious_ext ─────────────────────────────────
        f[27] = lowerUrl.matches(".*(\\.(exe|zip|bat|cmd|msi|vbs|ps1)).*") ? 1f : 0f;

        // ── 28: has_brand_mimicry ──────────────────────────────────
        f[28] = BRAND_MIMICRY_PATTERN.matcher(domain).find() ? 1f : 0f;

        // ── 29: all_digits_domain ──────────────────────────────────
        String cleanDomain = domainCore.replace(".", "");
        boolean allDigits = !cleanDomain.isEmpty();
        for (char c : cleanDomain.toCharArray()) if (!Character.isDigit(c)) { allDigits = false; break; }
        f[29] = allDigits ? 1f : 0f;

        // ── 30: suspicious_tld ─────────────────────────────────────
        float hasSuspTld = 0f;
        for (String st : SUSP_TLD_ALL) if (tld.equals(st)) { hasSuspTld = 1f; break; }
        f[30] = hasSuspTld;

        // ── 31: brand_in_path ──────────────────────────────────────
        String[] brandNames = {"paypal","google","amazon","microsoft","apple",
                "facebook","netflix","instagram","twitter","bank"};
        float brandInPath = 0f;
        for (String b : brandNames) if (path.toLowerCase().contains(b)) { brandInPath = 1f; break; }
        f[31] = brandInPath;

        // ── 32: has_script_endpoint ────────────────────────────────
        f[32] = (lowerUrl.contains(".php") || lowerUrl.contains(".asp") ||
                lowerUrl.contains(".aspx") || lowerUrl.contains(".cgi")) ? 1f : 0f;

        // ── 33: has_wp_path ────────────────────────────────────────
        f[33] = lowerUrl.contains("wp-") ? 1f : 0f;

        // ── 34–35: Vowel/consonant ratios ──────────────────────────
        int vowels = 0, letters = 0;
        for (char c : domainCore.toLowerCase().toCharArray()) {
            if (Character.isLetter(c)) {
                letters++;
                if ("aeiou".indexOf(c) >= 0) vowels++;
            }
        }
        f[34] = letters > 0 ? (float) vowels / letters : 0f;
        f[35] = letters > 0 ? (float)(letters - vowels) / letters : 0f;

        // ── 36: domain_trigram_entropy ─────────────────────────────
        f[36] = calculateEntropy(domainCore.toLowerCase());

        // ── 37: min_brand_levenshtein ──────────────────────────────
        float minDist = 10f;
        for (String b : LEV_BRANDS) {
            float dist = levenshteinSimple(domainCore.toLowerCase(), b);
            if (dist < minDist) minDist = dist;
        }
        f[37] = minDist;

        // ── 38: tld_risk_score ─────────────────────────────────────
        float tldRisk = 0f;
        for (String t : SUSP_TLD_HIGH) if (tld.equals(t)) { tldRisk = 1f; break; }
        if (tldRisk == 0f) for (String t : SUSP_TLD_MED) if (tld.equals(t)) { tldRisk = 0.5f; break; }
        f[38] = tldRisk;

        // ── 39: path_depth ─────────────────────────────────────────
        if (path.isEmpty() || path.equals("/")) {
            f[39] = 0f;
        } else {
            int depth = 0;
            for (char c : path.toCharArray()) if (c == '/') depth++;
            f[39] = Math.max(0, depth - 1);
        }

        // ── 40: query_param_count ──────────────────────────────────
        f[40] = query.isEmpty() ? 0f : countChar(query, '&') + 1f;

        // ── 41: domain_token_count ─────────────────────────────────
        f[41] = domainCore.split("[-._]").length;

        return f;
    }

    // ════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════

    // Extract hostname (no port, no path)
    private String extractHost(String url) {
        try {
            String noProto = url.replaceFirst("https?://", "");
            String host = noProto.contains("/") ? noProto.substring(0, noProto.indexOf("/")) : noProto;
            host = host.contains("?") ? host.substring(0, host.indexOf("?")) : host;
            host = host.contains(":") ? host.substring(0, host.indexOf(":")) : host;
            return host.toLowerCase();
        } catch (Exception e) { return ""; }
    }

    // Extract path component
    private String extractPath(String url) {
        try {
            String noProto = url.replaceFirst("https?://", "");
            return noProto.contains("/") ? noProto.substring(noProto.indexOf("/")) : "";
        } catch (Exception e) { return ""; }
    }

    // Extract TLD from host (e.g. ".com")
    private String getTld(String host) {
        int dot = host.lastIndexOf(".");
        return dot >= 0 ? host.substring(dot + 1) : "";
    }

    private float calculateEntropy(String s) {
        if (s.isEmpty()) return 0f;
        int[] freq = new int[256];
        for (char c : s.toCharArray()) if (c < 256) freq[c]++;
        float entropy = 0f;
        for (int count : freq) {
            if (count > 0) {
                float p = (float) count / s.length();
                entropy -= p * (float)(Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    private float levenshteinSimple(String a, String b) {
        int la = Math.min(a.length(), 10);
        int lb = Math.min(b.length(), 10);
        a = a.substring(0, la);
        b = b.substring(0, lb);
        int[][] dp = new int[la + 1][lb + 1];
        for (int i = 0; i <= la; i++) dp[i][0] = i;
        for (int j = 0; j <= lb; j++) dp[0][j] = j;
        for (int i = 1; i <= la; i++)
            for (int j = 1; j <= lb; j++)
                dp[i][j] = a.charAt(i-1) == b.charAt(j-1)
                        ? dp[i-1][j-1]
                        : 1 + Math.min(dp[i-1][j-1], Math.min(dp[i-1][j], dp[i][j-1]));
        return dp[la][lb];
    }

    private float[] scaleFeatures(float[] raw) {
        float[] scaled = new float[raw.length];
        for (int i = 0; i < raw.length; i++)
            scaled[i] = (raw[i] - scalerMean[i]) / scalerScale[i];
        return scaled;
    }

    private int countChar(String s, char target) {
        int count = 0;
        for (char c : s.toCharArray()) if (c == target) count++;
        return count;
    }

    public void close() {
        if (tflite != null) tflite.close();
    }
}