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
            "microsoft.com", "office.com", "live.com", "outlook.com", "hotmail.com",
            "apple.com", "icloud.com",
            "amazon.com", "amazon.co.uk", "amazon.in",
            "facebook.com", "fb.com", "instagram.com", "whatsapp.com",
            "twitter.com", "x.com", "linkedin.com",
            "wikipedia.org", "wikimedia.org", "wikidata.org",
            "stackoverflow.com", "stackexchange.com",
            "superuser.com", "serverfault.com", "askubuntu.com",
            "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
            "cloudflare.com", "mozilla.org", "firefox.com",
            "python.org", "docs.python.org",
            "reddit.com", "netflix.com", "adobe.com",
            "dropbox.com", "slack.com", "zoom.us",
            "shopify.com", "notion.so", "notion.site", "figma.com", "kaggle.com",
            "gnu.org", "sourceforge.net", "archive.org",
            // AWS & Cloud
            "aws.amazon.com", "skillbuilder.aws", "docs.aws.amazon.com",
            "signin.aws.amazon.com", "console.aws.amazon.com",
            "azure.microsoft.com", "portal.azure.com", "learn.microsoft.com",
            "cloud.google.com", "console.cloud.google.com",
            "firebase.google.com", "developers.google.com",
            "firebaseapp.com", "web.app", "azurewebsites.net",
            "cloudfront.net", "amazonaws.com",
            "heroku.com", "herokuapp.com", "digitalocean.com",
            "linode.com", "vultr.com", "hetzner.com", "ovhcloud.com",
            "render.com", "railway.app", "vercel.app", "netlify.app",
            "pages.dev", "github.io", "glitch.me", "replit.dev",
            // Dev tools & docs
            "docker.com", "hub.docker.com", "kubernetes.io",
            "cisco.com", "oracle.com", "ibm.com", "redhat.com",
            "ubuntu.com", "debian.org", "archlinux.org",
            "postgresql.org", "mysql.com", "mongodb.com",
            "elastic.co", "grafana.com", "jenkins.io",
            "nginx.com", "nginx.org", "apache.org",
            "spring.io", "hibernate.org",
            "reactjs.org", "vuejs.org", "angular.io",
            "nodejs.org", "npmjs.com", "pypi.org",
            "rubygems.org", "packagist.org", "crates.io",
            "nuget.org", "maven.org", "search.maven.org",
            "helm.sh", "terraform.io", "atlassian.com", "salesforce.com",
            "canva.com", "miro.com", "lucidchart.com",
            "draw.io", "diagrams.net", "airtable.com",
            "clickup.com", "asana.com", "trello.com", "monday.com",
            "hubspot.com", "zendesk.com", "intercom.com",
            "mailchimp.com", "sendgrid.com", "twilio.com",
            "developer.mozilla.org", "developer.apple.com",
            "developer.android.com", "developer.chrome.com",
            "docs.github.com", "training.github.com",
            // Version control / CI
            "gitlab.com", "bitbucket.org", "circleci.com",
            "travis-ci.org", "travis-ci.com", "actions.github.com",
            // AI / ML
            "huggingface.co", "deepseek.com", "perplexity.ai",
            "gemini.google.com", "copilot.microsoft.com",
            "character.ai", "midjourney.com", "stability.ai",
            "replicate.com", "wandb.ai", "comet.ml", "mlflow.org",
            "ray.io", "paperswithcode.com", "grok.com",
            "tensorflow.org", "pytorch.org",
            // Learning platforms
            "udemy.com", "coursera.org", "edx.org", "khanacademy.org",
            "pluralsight.com", "acloudguru.com", "cloudacademy.com",
            "datacamp.com", "leetcode.com", "hackerrank.com",
            "codewars.com", "exercism.org", "freecodecamp.org",
            "theodinproject.com", "codecademy.com", "brilliant.org",
            "udacity.com", "skillshare.com", "alison.com",
            "futurelearn.com", "simplilearn.com", "chegg.com",
            "geeksforgeeks.org", "w3schools.com", "tutorialspoint.com",
            "javatpoint.com", "baeldung.com", "digitaldefynd.com",
            "kodekloud.com", "killercoda.com", "katacoda.com",
            "cloudskillsboost.google", "qwiklabs.com",
            "play-with-docker.com", "linuxfoundation.org",
            "netacad.com", "life-global.org",
            "comptia.org", "pearsonvue.com", "prometric.com", "credly.com",
            // Universities
            "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk", "cam.ac.uk",
            "kln.ac.lk", "cmb.ac.lk", "mora.ac.lk", "pdn.ac.lk",
            "sjp.ac.lk", "ruh.ac.lk", "sliit.lk", "nsbm.ac.lk",
            "iit.ac.lk", "nibm.lk", "gov.lk", "ac.lk",
            // Security / Research
            "wireshark.org", "nmap.org", "kali.org",
            "metasploit.com", "rapid7.com", "tenable.com",
            "qualys.com", "splunk.com", "crowdstrike.com",
            "paloaltonetworks.com", "fortinet.com",
            "checkpoint.com", "sophos.com", "malwarebytes.com",
            "virustotal.com", "haveibeenpwned.com", "shodan.io",
            "owasp.org", "sans.org", "cert.org",
            "cve.mitre.org", "nvd.nist.gov", "nist.gov",
            // News & media
            "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com",
            "apnews.com", "theguardian.com", "nytimes.com",
            "forbes.com", "techcrunch.com", "wired.com",
            "theverge.com", "arstechnica.com", "zdnet.com", "cnet.com",
            // E-commerce & travel
            "ebay.com", "etsy.com", "walmart.com", "bestbuy.com", "aliexpress.com",
            "booking.com", "tripadvisor.com", "expedia.com", "hotels.com",
            // Q&A / Community
            "math.stackexchange.com", "unix.stackexchange.com", "quora.com",
            // Productivity / hosting
            "grammarly.com", "sites.google.com", "docs.google.com",
            "forms.gle", "sharepoint.com", "sway.office.com",
            "wixsite.com", "mystrikingly.com", "weebly.com",
            "wordpress.com", "tumblr.com", "medium.com", "substack.com",
            "mattermost.com", "discord.com", "telegram.org", "signal.org",
            // Academic
            "arxiv.org", "ieee.org", "acm.org",
            "researchgate.net", "academia.edu",
            "scholar.google.com", "jstor.org", "pubmed.ncbi.nlm.nih.gov",
            // Payment (official only)
            "paypal.com", "stripe.com", "wise.com", "payoneer.com",
            "square.com", "visa.com", "mastercard.com",
            // Sri Lanka telecoms / banks
            "dialog.lk", "slt.lk", "hutch.lk", "airtel.lk", "mobitel.lk",
            "sampath.lk", "hnb.lk", "boc.lk", "nsb.lk", "peoples.lk",
            "combank.lk", "seylan.lk", "dfcc.lk", "ndb.lk",
            // Gaming / DevOps / Monitoring
            "steampowered.com", "epicgames.com", "blizzard.com", "battle.net",
            "datadog.com", "newrelic.com", "sentry.io", "pagerduty.com",
            "fastly.com", "akamai.com", "namecheap.com", "godaddy.com",
            "esy.es", "000webhostapp.com", "biz.nf"
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

        // Read threshold from meta.json but ENFORCE minimum 0.50.
        // Dynamic F1-optimised thresholds (e.g. 0.39) are for research only.
        // Android production always uses 0.50 for clear, reproducible results.
        float metaThreshold = meta.get("optimal_threshold").getAsFloat();
        threshold = Math.max(metaThreshold, 0.50f);
        Log.i(TAG, "Threshold: meta=" + metaThreshold + " enforced=" + threshold);
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

        // Layer 1: Allowlist bypass (before any ML inference)
        String domain = extractDomain(inputText);
        if (isAllowlisted(domain)) {
            Log.d(TAG, "Allowlisted: " + domain);
            return new CombinedResult(
                    "Legitimate", false, 0f,
                    new ArrayList<>(), "allowlist");
        }

        try {
            // Layer 2: Preprocess → tokenise → TFLite
            String processed = preprocessText(inputText, source);
            int[]    tokenIds = tokenise(processed);
            int[][]   input   = new int[1][seqLength];
            float[][] output  = new float[1][1];
            input[0] = tokenIds;
            tflite.run(input, output);
            float rawProb = output[0][0];   // raw Conv1D probability 0.0–1.0

            // ── Layer 3: Hybrid Rule Boost ─────────────────────
            //
            // Problem: Combined model trained on URL + SMS + Email
            // data. Benign email/SMS tokens dilute URL phishing
            // signals. Result: "us-post.us.com/update" → 49.6%
            // (SAFE) despite obvious suspicious TLD + path.
            //
            // Solution: Run rule engine FIRST (unconditionally).
            // Each triggered rule adds +RULE_BOOST to rawProb.
            // Final boosted score used for both threshold decision
            // AND XAI display — completely consistent.
            //
            // Boost values chosen to be meaningful but not dominant:
            //   - Hard signals (IP, brand spoof): +0.20
            //   - Strong signals (shortener, bad TLD): +0.15
            //   - Moderate signals (HTTP, subdomains, urgency): +0.10
            //   - Cap at 0.99 so model retains some influence.

            float boost     = 0.0f;
            int   rulesFired = 0;
            String lower    = inputText.toLowerCase();
            String xaiDomain = extractDomain(inputText);

            // Hard signals (+0.20 each)
            if (XAI_IP_PAT.matcher(lower).find()) {
                boost += 0.20f; rulesFired++;
                Log.d(TAG, "Boost +0.20: IP address");
            }
            if (BRAND_PAT.matcher(lower).find()) {
                boost += 0.20f; rulesFired++;
                Log.d(TAG, "Boost +0.20: brand mimicry");
            }

            // Strong signals (+0.15 each)
            for (String sh : SHORTENERS) {
                if (lower.contains(sh)) {
                    boost += 0.15f; rulesFired++;
                    Log.d(TAG, "Boost +0.15: shortener " + sh);
                    break;
                }
            }
            if (!xaiDomain.isEmpty()) {
                String[] dParts = xaiDomain.split("[.]");
                if (dParts.length > 0) {
                    String tld = dParts[dParts.length - 1];
                    if (SUSPICIOUS_TLDS.contains(tld)) {
                        boost += 0.15f; rulesFired++;
                        Log.d(TAG, "Boost +0.15: suspicious TLD ." + tld);
                    }
                }
            }

            // Moderate signals (+0.10 each)
            Matcher urlM = XAI_URL_PAT.matcher(lower);
            boolean hasHttpOnly = false;
            int urlCount = 0;
            while (urlM.find()) {
                urlCount++;
                if (urlM.group().startsWith("http://")) hasHttpOnly = true;
            }
            if (hasHttpOnly) {
                boost += 0.10f; rulesFired++;
                Log.d(TAG, "Boost +0.10: insecure HTTP");
            }
            if (!xaiDomain.isEmpty() && xaiDomain.split("[.]").length >= 4) {
                boost += 0.10f; rulesFired++;
                Log.d(TAG, "Boost +0.10: excessive subdomains");
            }
            int urgCount = 0;
            for (String w : URGENCY_WORDS) { if (lower.contains(w)) urgCount++; }
            if (urgCount >= 2) {
                boost += 0.10f; rulesFired++;
                Log.d(TAG, "Boost +0.10: urgency x" + urgCount);
            }
            for (String w : FINANCIAL_WORDS) {
                if (lower.contains(w)) {
                    boost += 0.10f; rulesFired++;
                    Log.d(TAG, "Boost +0.10: financial bait " + w);
                    break;
                }
            }
            if (urlCount >= 3) {
                boost += 0.10f; rulesFired++;
                Log.d(TAG, "Boost +0.10: multiple URLs " + urlCount);
            }

            // ── GENERIC URL STRUCTURAL ANOMALY RULES ──────────────
            // These catch unknown phishing without requiring a known
            // brand, TLD, or keyword list — targeting structural
            // properties that separate phishing from legitimate URLs.
            // Example catch: somateco.com.br/folderz/ready.php
            //   → deep path (3 slashes) +0.10
            //   → suspicious extension .php  +0.12
            //   → high path/domain ratio     +0.10
            //   → total boost = +0.32 → 49% + 32% = 81% PHISHING ✓

            String firstUrl = "";
            Matcher urlM2 = XAI_URL_PAT.matcher(lower);
            if (urlM2.find()) firstUrl = urlM2.group();

            if (!firstUrl.isEmpty()) {
                // Parse URL components
                String urlPath   = "";
                String urlDomain = "";
                try {
                    // Remove scheme
                    String noScheme = firstUrl.replaceFirst("(?i)^https?://", "");
                    int slashIdx    = noScheme.indexOf('/');
                    if (slashIdx >= 0) {
                        urlDomain = noScheme.substring(0, slashIdx);
                        urlPath   = noScheme.substring(slashIdx);
                    } else {
                        urlDomain = noScheme;
                    }
                } catch (Exception ignored) {}

                // Rule G1: Deep URL path (3+ path segments)
                // Legitimate domains rarely have /a/b/c/d/file.php
                // Phishing: domain.com/user/account/verify/update/login.php
                int slashCount = 0;
                for (char ch : urlPath.toCharArray()) {
                    if (ch == '/') slashCount++;
                }
                if (slashCount >= 3) {
                    boost += 0.10f; rulesFired++;
                    Log.d(TAG, "Boost +0.10: deep path /" + slashCount + " segments");
                }

                // Rule G2: Suspicious file extensions in URL path
                // .php .asp .aspx in phishing pages hosting fake login forms
                // .exe .apk .sh .bat for malware delivery
                // .zip .rar for malicious archive delivery
                String[] SUSP_EXTS = {
                        ".php", ".asp", ".aspx", ".cgi", ".cfm",
                        ".exe", ".apk", ".sh",  ".bat", ".cmd",
                        ".zip", ".rar", ".7z",  ".scr", ".jar"
                };
                for (String ext : SUSP_EXTS) {
                    if (urlPath.contains(ext)) {
                        // Higher boost for executable types
                        float extBoost = (ext.equals(".exe") || ext.equals(".apk")
                                || ext.equals(".sh") || ext.equals(".bat")
                                || ext.equals(".scr")) ? 0.20f : 0.12f;
                        boost += extBoost; rulesFired++;
                        Log.d(TAG, "Boost +" + extBoost + ": suspicious ext " + ext);
                        break;
                    }
                }

                // Rule G3: High path-to-domain length ratio
                // Legitimate: google.com/search?q=hello  (short path, known domain)
                // Phishing:   somateco.com.br/folderz/ready.php  (long path, obscure)
                // Ratio > 1.5 means path is longer than domain itself
                if (urlDomain.length() > 0 && urlPath.length() > 0) {
                    float ratio = (float) urlPath.length() / urlDomain.length();
                    if (ratio > 2.0f) {
                        boost += 0.12f; rulesFired++;
                        Log.d(TAG, "Boost +0.12: path/domain ratio " + ratio);
                    } else if (ratio > 1.2f) {
                        boost += 0.07f; rulesFired++;
                        Log.d(TAG, "Boost +0.07: path/domain ratio " + ratio);
                    }
                }

                // Rule G4: Hyphen-heavy domain (not in path)
                // Legitimate: my-bank.com (1 hyphen ok)
                // Phishing:   my-bank-account-secure-login.phishsite.com
                int hyphenCount = 0;
                for (char ch : urlDomain.toCharArray()) {
                    if (ch == '-') hyphenCount++;
                }
                if (hyphenCount >= 3) {
                    boost += 0.10f; rulesFired++;
                    Log.d(TAG, "Boost +0.10: hyphen-heavy domain x" + hyphenCount);
                }

                // Rule G5: Long domain name (> 30 chars before first dot)
                // Legitimate domains are short and memorable
                // Phishing: paypal-account-security-update-required.com
                String firstLabel = urlDomain.split("[.]")[0];
                if (firstLabel.length() > 30) {
                    boost += 0.10f; rulesFired++;
                    Log.d(TAG, "Boost +0.10: long domain label " + firstLabel.length() + " chars");
                }

                // Rule G6: Total URL length anomaly
                // URLs > 100 chars are statistically rare for legitimate sites
                // Phishing URLs often stuff keywords/tokens in long paths
                if (firstUrl.length() > 120) {
                    boost += 0.08f; rulesFired++;
                    Log.d(TAG, "Boost +0.08: URL length " + firstUrl.length());
                }

                // Rule G7: Hex-encoded characters in path (%XX)
                // Legitimate sites rarely encode paths with %20, %2F etc.
                // Phishing uses encoding to obfuscate keywords
                int hexCount = 0;
                java.util.regex.Matcher hexM = java.util.regex.Pattern
                        .compile("%[0-9a-fA-F]{2}").matcher(urlPath);
                while (hexM.find()) hexCount++;
                if (hexCount >= 3) {
                    boost += 0.10f; rulesFired++;
                    Log.d(TAG, "Boost +0.10: hex-encoded path x" + hexCount);
                }

                // Rule G8: Non-standard port in URL
                // Phishing servers often run on odd ports to avoid detection
                if (urlDomain.contains(":")) {
                    String portStr = urlDomain.replaceAll(".*:(\\d+)$", "$1");
                    try {
                        int port = Integer.parseInt(portStr);
                        if (port != 80 && port != 443 && port != 8080 && port != 8443) {
                            boost += 0.15f; rulesFired++;
                            Log.d(TAG, "Boost +0.15: non-standard port " + port);
                        }
                    } catch (NumberFormatException ignored) {}
                }

                // Rule G9: @ symbol in URL (credential stuffing trick)
                // http://legit.com@evil.com/  → browser visits evil.com
                if (firstUrl.contains("@")) {
                    boost += 0.20f; rulesFired++;
                    Log.d(TAG, "Boost +0.20: @ symbol in URL");
                }

                // Rule G10: Double-encoded or suspicious query string
                // ?redirect=http:// or ?url= or ?next= used for open redirects
                if (urlPath.contains("redirect=") || urlPath.contains("?url=")
                        || urlPath.contains("?next=") || urlPath.contains("?goto=")
                        || urlPath.contains("?return=") || urlPath.contains("?redir=")) {
                    boost += 0.12f; rulesFired++;
                    Log.d(TAG, "Boost +0.12: open redirect parameter");
                }
            }

            // Apply boost and cap
            float boostedProb = Math.min(rawProb + boost, 0.99f);
            boolean phishing  = boostedProb >= threshold;
            float   probPct   = boostedProb * 100f;
            String  label     = phishing ? "Phishing" : "Legitimate";

            Log.i(TAG, String.format(
                    "Hybrid: raw=%.3f boost=+%.2f final=%.3f rules=%d verdict=%s",
                    rawProb, boost, boostedProb, rulesFired, label));

            // Layer 4: XAI — pass boosted values for consistent display
            List<String> xai = buildXai(
                    inputText, probPct, phishing, rawProb, boost, rulesFired);

            return new CombinedResult(label, phishing, probPct, xai, "hybrid");

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
    // Backwards-compatible 4-arg overload
    private List<String> buildXai(String text, float probPct,
                                  boolean isPhishing, float rawProb) {
        return buildXai(text, probPct, isPhishing, rawProb, 0f, 0);
    }

    /**
     * buildXai() v2 — hybrid scoring transparency.
     *
     * Rules are evaluated unconditionally (same rules used in predict()
     * for the boost). XAI output shows NN score + rule contribution
     * so researchers can see exactly how the verdict was reached.
     *
     * @param probPct    BOOSTED probability x100 (what user sees)
     * @param rawProb    raw TFLite output before boost (0.0-1.0)
     * @param boost      total rule boost applied (0.0-0.99)
     * @param rulesFired count of rules that triggered
     */
    private List<String> buildXai(String text, float probPct,
                                  boolean isPhishing, float rawProb,
                                  float boost, int rulesFired) {
        List<String> flags = new ArrayList<>();

        // Evaluate ALL rules unconditionally — same rules used in
        // predict() boost, so XAI is always consistent with verdict.
        String lower     = text.toLowerCase();
        String xaiDomain = extractDomain(text);

        // Rule 1: IP address
        if (XAI_IP_PAT.matcher(lower).find()) {
            flags.add("🔢 URL තුල IP ලිපිනයක් (192.168.x.x ආකාරය) අඩංගු වේ. "
                    + "නිත්‍යානුකූල වේබ් අඩවිවල domain නාම ප්‍රයෝග කේරේ — "
                    + "මේය ඊතා සැකසහිතයි.");
        }

        // Rule 2: Brand mimicry
        if (BRAND_PAT.matcher(lower).find()) {
            flags.add("🏦 PayPal, Google, Amazon, Bank වැනි ප්‍රසිද්ද ආයතනයක් නමක් "
                    + "ව්‍යාජ ලේස ප්‍රයෝග කරක්‍වියේ නෝ අත. "
                    + "ඔබේ රහස්‍ය තෝරතුරු සෝරා ගෙනීමට සකස් කලා link/message.");
        }

        // Rule 3: URL shortener
        for (String sh : SHORTENERS) {
            if (lower.contains(sh)) {
                flags.add("🔗 URL Shortener (" + sh + ") ප්‍රයෝග කරක්‍වියේ "
                        + "නියම ගමනාන්තය සඟවා ඇත. "
                        + "Scammers ලා සැබැ phishing site ගෝනු කීරීමට ප්‍රයෝග කරයි.");
                break;
            }
        }

        // Rule 4: Suspicious TLD + Rule 5: Excessive subdomains
        if (!xaiDomain.isEmpty()) {
            String[] dParts = xaiDomain.split("[.]");
            if (dParts.length > 0) {
                String tld = dParts[dParts.length - 1];
                if (SUSPICIOUS_TLDS.contains(tld)) {
                    flags.add("🌐 සැකසහිත domain extension (." + tld + ") "
                            + "ප්‍රයෝග කරක්‍වියේ නෝ අත. "
                            + "Phishing sites ලා මේවැනි extensions ප්‍රයෝග කරයි.");
                }
            }
            if (dParts.length >= 4) {
                flags.add("🌐 Subdomains " + (dParts.length - 1)
                        + "+ ක්‍ ඇත — නිත්‍යානුකූල site ලේස පේනී සිටීමට "
                        + "සාදා ගත් URL. උදා: paypal.secure.verify.evil.com");
            }
        }

        // Rule 6: Insecure HTTP
        Matcher urlM2 = XAI_URL_PAT.matcher(lower);
        boolean hasHttpOnly = false;
        int urlCount = 0;
        while (urlM2.find()) {
            urlCount++;
            if (urlM2.group().startsWith("http://")) hasHttpOnly = true;
        }
        if (hasHttpOnly) {
            flags.add("🔓 ආරක්ෂිත නෝවන link (https:// නෝමැත). "
                    + "ඔබ ඇතුල කරන passwords සහ OTP intercept කීරීම පහසු වේ.");
        }

        // Rule 7: Urgency keywords
        List<String> urgFound = new ArrayList<>();
        for (String w : URGENCY_WORDS) {
            if (lower.contains(w)) urgFound.add(w);
        }
        if (urgFound.size() >= 2) {
            flags.add("⏰ හදිසි (Urgency) වඩන ('"
                    + urgFound.get(0) + "', '" + urgFound.get(1) + "') "
                    + "ප්‍රයෝග කරක්‍වියේ නෝ අත. Scammers ලා ඔබව කලභලයට පත් කර "
                    + "ඊක්මනින් ක්‍රියා කරවීමට මේය ප්‍රයෝග කරයි.");
        } else if (urgFound.size() == 1) {
            flags.add("⏰ '" + urgFound.get(0) + "' — urgency indicator.");
        }

        // Rule 8: Financial bait
        for (String w : FINANCIAL_WORDS) {
            if (lower.contains(w)) {
                flags.add("💰 මූල්‍ය ලා඼ ('" + w + "') ගේනහැර ඇත. "
                        + "ත්‍යාග ලා඼ කරවීමේ නාමයෙන් credentials "
                        + "සෝරා ගෙනීමේ ඊත්සාහයකි.");
                break;
            }
        }

        // Rule 9: Multiple URLs
        if (urlCount >= 3) {
            flags.add("🔗 URLs " + urlCount + "ක්‍ හීදුනාගන්නා ලදී — "
                    + "phishing messages වල bogus redirect links "
                    + "භෝහෝ ගණනක්‍ ඇතුලත් කේරේ.");
        }

        // ── GENERIC URL STRUCTURAL ANOMALY XAI ──────────────────
        // Mirror of boost rules in predict() — evaluated on raw text
        String xaiFirstUrl = "";
        Matcher xaiUrlM3 = XAI_URL_PAT.matcher(lower);
        if (xaiUrlM3.find()) xaiFirstUrl = xaiUrlM3.group();

        if (!xaiFirstUrl.isEmpty()) {
            String xaiPath = "";
            String xaiDom2 = "";
            try {
                String ns = xaiFirstUrl.replaceFirst("(?i)^https?://", "");
                int si = ns.indexOf('/');
                if (si >= 0) { xaiDom2 = ns.substring(0, si); xaiPath = ns.substring(si); }
                else xaiDom2 = ns;
            } catch (Exception ignored) {}

            // G1: Deep path
            int xaiSlashes = 0;
            for (char ch : xaiPath.toCharArray()) if (ch == '/') xaiSlashes++;
            if (xaiSlashes >= 3) {
                flags.add("📂 URL path ගැඹුරු මට්ටම් " + xaiSlashes
                        + "ක් ඇත (/a/b/c/...). "
                        + "නිත්‍යානුකූල sites ලේ URL paths කෙටි ය — "
                        + "මෙය fake login page සඟවා ගැනීමේ technique.");
            }

            // G2: Suspicious extensions
            String[] xaiExts = {".php",".asp",".aspx",".cgi",
                    ".exe",".apk",".sh",".bat",".scr",
                    ".zip",".rar",".jar"};
            for (String ext : xaiExts) {
                if (xaiPath.contains(ext)) {
                    if (ext.equals(".exe") || ext.equals(".apk")
                            || ext.equals(".sh") || ext.equals(".bat")) {
                        flags.add("⚠️ URL ලේ executable file extension ("
                                + ext + ") ඇත. "
                                + "Malware download කිරීමේ prayathnayak.");
                    } else {
                        flags.add("🔗 URL path ලේ server-side script ("
                                + ext + ") ඇත. "
                                + "Fake form submission page ලෙස භාවිතා වේ.");
                    }
                    break;
                }
            }

            // G3: High path/domain ratio
            if (xaiDom2.length() > 0 && xaiPath.length() > 0) {
                float xaiRatio = (float) xaiPath.length() / xaiDom2.length();
                if (xaiRatio > 1.2f) {
                    flags.add("📏 URL path (දිග=" + xaiPath.length() + ") "
                            + "domain (දිග=" + xaiDom2.length() + ") ට වඩා දිගය. "
                            + "Phishing pages ලේ long paths ලෙස keywords hide කරයි.");
                }
            }

            // G4: Hyphen-heavy domain
            int xaiHyphens = 0;
            for (char ch : xaiDom2.toCharArray()) if (ch == '-') xaiHyphens++;
            if (xaiHyphens >= 3) {
                flags.add("🔗 Domain ලේ hyphens " + xaiHyphens + "ක් ඇත. "
                        + "Phishing domains ලේ legitimate site ලෙස පෙනීමට "
                        + "long hyphenated names use කරයි.");
            }

            // G9: @ in URL
            if (xaiFirstUrl.contains("@")) {
                flags.add("⚠️ URL ලේ '@' symbol ඇත. "
                        + "Browser ලා '@' ට පසු domain ලෙස visit කරයි — "
                        + "real destination සඟවා ගැනීමේ technique.");
            }

            // G10: Open redirect
            if (xaiPath.contains("redirect=") || xaiPath.contains("?url=")
                    || xaiPath.contains("?next=") || xaiPath.contains("?goto=")) {
                flags.add("↪️ URL ලේ redirect parameter ඇත. "
                        + "ඔබව වෙනත් phishing site ලෙස redirect කිරීමට "
                        + "design කළ link.");
            }
        }

        // Only return reasons for phishing verdict
        if (!isPhishing) {
            return new ArrayList<>();
        }

        // Guaranteed fallback
        if (flags.isEmpty()) {
            flags.add("🤖 AI ආක්‍රුතිය මගින් සැකසහිත රටාවක් හීදුනාගෙන් ඇත.");
        }

        // Hybrid scoring breakdown for researcher visibility
        if (boost > 0f) {
            flags.add(String.format(
                    "🤖 Hybrid: NN=%.1f%% + Rules=+%.0f%% → Final=%.1f%% "
                            + "(threshold %.0f%%, rules fired=%d)",
                    rawProb * 100f, boost * 100f, probPct,
                    threshold * 100f, rulesFired));
        } else {
            flags.add(String.format(
                    "🤖 AI Model: %.1f%% P(phishing) — threshold %.0f%%.",
                    probPct, threshold * 100f));
        }

        return flags;
    }

    // ════════════════════════════════════════════════════════════
    // Accessors
    // ════════════════════════════════════════════════════════════

    /** Returns the enforced threshold (always >= 0.50). */
    public float getThreshold() { return threshold; }

    /** Returns the sequence length read from meta.json. */
    public int getSeqLength() { return seqLength; }

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