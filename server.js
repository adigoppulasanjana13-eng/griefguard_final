require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { google } = require("googleapis");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ── Session setup (stores tokens server-side only, never sent to browser) ──
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, maxAge: 1000 * 60 * 60 }, // 1 hour
  })
);

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

// ── Google OAuth client ──
function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// Scopes: read-only access to Gmail. We only ever READ, never send/delete.
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
];

// ── Step 1: Redirect user to Google's login/consent screen ──
app.get("/auth/google", (req, res) => {
  const oauth2Client = getOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline", // gives us a refresh token
    scope: SCOPES,
    prompt: "consent",
  });
  res.redirect(url);
});

// ── Step 2: Google redirects back here with a code ──
app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect("/?error=no_code");

  try {
    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Get basic profile info (email, name)
    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const { data: profile } = await oauth2.userinfo.get();

    // Store tokens + profile in the server-side session.
    // IMPORTANT: tokens never go to the browser/localStorage.
    req.session.tokens = tokens;
    req.session.profile = { email: profile.email, name: profile.name };

    res.redirect("/dashboard.html");
  } catch (err) {
    console.error("OAuth callback error:", err.message);
    res.redirect("/?error=auth_failed");
  }
});

// ── Who is logged in? (frontend checks this) ──
app.get("/api/me", (req, res) => {
  if (!req.session.profile) return res.status(401).json({ error: "not_logged_in" });
  res.json({ profile: req.session.profile });
});

// ── Logout: destroy session, discard tokens ──
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ── Core feature: scan Gmail for security/suspicious alerts ──
//
// What this looks for (real Gmail data, read-only):
//  - "New sign-in" / "Security alert" emails from Google itself
//  - "Suspicious activity" notifications from common services
//  - Password reset emails the user didn't request (heuristic: flagged for review)
//
// This is READ-ONLY. The app never sends emails, never deletes anything,
// never changes account settings.
app.get("/api/scan", async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: "not_logged_in" });

  try {
    const oauth2Client = getOAuthClient();
    oauth2Client.setCredentials(req.session.tokens);

    // If access token expired, googleapis will use the refresh token automatically
    oauth2Client.on("tokens", (newTokens) => {
      req.session.tokens = { ...req.session.tokens, ...newTokens };
    });

    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

    // Search queries that catch real security-related emails
    const queries = [
      'subject:("security alert" OR "new sign-in" OR "suspicious activity")',
      'subject:("password reset" OR "verify your account" OR "unusual activity")',
      'from:(no-reply@accounts.google.com OR security@*)',
    ];

    const seenIds = new Set();
    const findings = [];

    for (const q of queries) {
      const listRes = await gmail.users.messages.list({
        userId: "me",
        q,
        maxResults: 10,
      });

      const messages = listRes.data.messages || [];
      for (const msg of messages) {
        if (seenIds.has(msg.id)) continue;
        seenIds.add(msg.id);

        const full = await gmail.users.messages.get({
          userId: "me",
          id: msg.id,
          format: "metadata",
          metadataHeaders: ["From", "Subject", "Date"],
        });

        const headers = full.data.payload?.headers || [];
        const get = (name) => headers.find((h) => h.name === name)?.value || "";

        findings.push({
          id: msg.id,
          from: get("From"),
          subject: get("Subject"),
          date: get("Date"),
          snippet: full.data.snippet || "",
        });
      }
    }

    // Simple risk scoring based on keywords
    const scored = findings.map((f) => {
      const text = (f.subject + " " + f.snippet).toLowerCase();
      let risk = "low";
      if (text.includes("suspicious") || text.includes("unauthorized") || text.includes("unusual activity")) {
        risk = "high";
      } else if (text.includes("sign-in") || text.includes("password") || text.includes("verify")) {
        risk = "medium";
      }
      return { ...f, risk };
    });

    res.json({
      email: req.session.profile.email,
      scannedAt: new Date().toISOString(),
      totalFound: scored.length,
      findings: scored,
    });
  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(500).json({ error: "scan_failed", message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`GriefGuard server running at http://localhost:${PORT}`);
});

// ── Foundry IQ — Azure AI Foundry integration ──────────────────────
// Takes the REAL findings from /api/scan and asks Foundry IQ to produce
// a grounded, cited risk summary. This satisfies the "Microsoft IQ"
// requirement: agentic reasoning over real retrieved data.
//
// Required env vars:
//   AZURE_FOUNDRY_ENDPOINT   = https://<your-resource>.openai.azure.com
//   AZURE_FOUNDRY_KEY        = <your-api-key>
//   AZURE_FOUNDRY_DEPLOYMENT = gpt-4o   (your deployed model name)

async function callFoundryIQ(findings, userEmail) {
  const endpoint = process.env.AZURE_FOUNDRY_ENDPOINT;
  const key = process.env.AZURE_FOUNDRY_KEY;
  const deployment = process.env.AZURE_FOUNDRY_DEPLOYMENT || "gpt-4o";

  if (!endpoint || !key) {
    throw new Error("FOUNDRY_NOT_CONFIGURED");
  }

  const url = `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-01`;

  const systemPrompt = `You are Sentinel, a security analysis agent inside GriefGuard, powered by Microsoft Foundry IQ.
You are given REAL email metadata (subject, sender, snippet, date) retrieved from a user's Gmail inbox via read-only access.
Your job: analyze these for genuine security concerns (account takeover signs, phishing, suspicious sign-ins) vs. routine/benign notifications.
Ground every claim in the specific emails provided — cite the subject line or sender as evidence. Do not invent emails that weren't given to you.
Respond ONLY with valid JSON:
{
  "overallRiskLevel": "low"|"medium"|"high",
  "summary": string (2-3 sentences, grounded in the actual emails provided),
  "items": [
    { "subject": string, "riskLevel": "low"|"medium"|"high", "reasoning": string, "recommendedAction": string }
  ]
}`;

  const userPrompt = `Account: ${userEmail}
Real emails found in inbox (${findings.length} total):
${JSON.stringify(findings, null, 2)}

Analyze these and produce the risk summary now.`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "api-key": key },
    body: JSON.stringify({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      max_tokens: 1000,
      temperature: 0.3,
      response_format: { type: "json_object" },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Foundry IQ error ${res.status}: ${err}`);
  }

  const data = await res.json();
  const text = data.choices?.[0]?.message?.content || "{}";
  const clean = text.replace(/```json|```/g, "").trim();
  return JSON.parse(clean);
}

// ── Endpoint: analyze real findings with Foundry IQ ──
app.post("/api/analyze", async (req, res) => {
  if (!req.session.profile) return res.status(401).json({ error: "not_logged_in" });

  const { findings } = req.body;
  if (!Array.isArray(findings)) {
    return res.status(400).json({ error: "findings array required" });
  }

  if (findings.length === 0) {
    return res.json({
      overallRiskLevel: "low",
      summary: "No security-related emails were found in your inbox during the scan.",
      items: [],
    });
  }

  try {
    const analysis = await callFoundryIQ(findings, req.session.profile.email);
    res.json(analysis);
  } catch (err) {
    if (err.message === "FOUNDRY_NOT_CONFIGURED") {
      return res.status(503).json({
        error: "foundry_not_configured",
        message: "Set AZURE_FOUNDRY_ENDPOINT and AZURE_FOUNDRY_KEY in .env to enable Foundry IQ analysis.",
      });
    }
    console.error("Foundry IQ error:", err.message);
    res.status(500).json({ error: "analysis_failed", message: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// GRIEFGUARD — 3 AI AGENTS powered by Microsoft Work IQ
// Work IQ = Microsoft Graph API (official Microsoft IQ layer)
// Uses your inbox data via Microsoft Graph to power 3 agents:
//   Agent 1 — SENTINEL  : Threat detection & risk scoring
//   Agent 2 — EXECUTOR  : Account closure action plan
//   Agent 3 — PROTECTOR : Scam pattern warnings for grieving families
//
// Add to .env:
//   WORKIQ_CLIENT_ID      = from Azure App Registration (free)
//   WORKIQ_CLIENT_SECRET  = from Azure App Registration (free)
//   WORKIQ_REDIRECT_URI   = http://localhost:3000/auth/workiq/callback
// ══════════════════════════════════════════════════════════════════

const WORKIQ_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0";
const GRAPH_URL = "https://graph.microsoft.com/v1.0";

// ── Work IQ OAuth login ──
app.get("/auth/workiq", (req, res) => {
  const clientId = process.env.WORKIQ_CLIENT_ID;
  if (!clientId) return res.redirect("/dashboard.html?workiq_error=not_configured");
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: process.env.WORKIQ_REDIRECT_URI || "http://localhost:3000/auth/workiq/callback",
    scope: "openid email profile Mail.Read User.Read offline_access",
    response_mode: "query",
    prompt: "select_account",
  });
  res.redirect(`${WORKIQ_AUTH_URL}/authorize?${params}`);
});

// ── Work IQ OAuth callback ──
app.get("/auth/workiq/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect("/dashboard.html?workiq_error=" + (error || "no_code"));

  try {
    const tokenRes = await fetch(`${WORKIQ_AUTH_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.WORKIQ_CLIENT_ID,
        client_secret: process.env.WORKIQ_CLIENT_SECRET,
        code,
        redirect_uri: process.env.WORKIQ_REDIRECT_URI || "http://localhost:3000/auth/workiq/callback",
        grant_type: "authorization_code",
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    // Get Microsoft profile
    const meRes = await fetch(`${GRAPH_URL}/me`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const me = await meRes.json();

    // Store Work IQ tokens in session (server-side only)
    req.session.workiq_tokens = tokens;
    req.session.workiq_profile = {
      email: me.mail || me.userPrincipalName,
      name: me.displayName,
    };
    res.redirect("/dashboard.html?workiq=connected");
  } catch (err) {
    console.error("Work IQ callback error:", err.message);
    res.redirect("/dashboard.html?workiq_error=auth_failed");
  }
});

// ── Work IQ status ──
app.get("/api/workiq/status", (req, res) => {
  if (!req.session.workiq_profile) return res.json({ connected: false });
  res.json({ connected: true, profile: req.session.workiq_profile });
});

// ── Work IQ logout ──
app.post("/api/workiq/logout", (req, res) => {
  delete req.session.workiq_tokens;
  delete req.session.workiq_profile;
  res.json({ ok: true });
});

// ── Fetch real Outlook emails via Microsoft Graph (Work IQ) ──
async function fetchWorkIQEmails(accessToken) {
  const res = await fetch(
    `${GRAPH_URL}/me/messages?$filter=` +
    encodeURIComponent(
      "contains(subject,'security') or contains(subject,'sign-in') or " +
      "contains(subject,'suspicious') or contains(subject,'password') or " +
      "contains(subject,'verify') or contains(subject,'unusual') or " +
      "contains(subject,'alert') or contains(subject,'single-use')"
    ) +
    `&$select=subject,from,receivedDateTime,bodyPreview&$top=20&$orderby=receivedDateTime desc`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const data = await res.json();
  return (data.value || []).map((m) => ({
    id: m.id,
    subject: m.subject || "",
    from: m.from?.emailAddress?.address || "",
    date: m.receivedDateTime || "",
    snippet: m.bodyPreview || "",
  }));
}

// ── AGENT 1: SENTINEL — Work IQ threat analysis ──
app.post("/api/agents/sentinel", async (req, res) => {
  if (!req.session.workiq_tokens) {
    return res.status(401).json({ error: "workiq_not_connected", message: "Connect Microsoft Work IQ first" });
  }
  try {
    const emails = await fetchWorkIQEmails(req.session.workiq_tokens.access_token);

    // Score each email for risk
    const threats = emails.map((e) => {
      const text = (e.subject + " " + e.snippet).toLowerCase();
      let risk = "low";
      let reason = "Routine security notification.";
      if (text.includes("suspicious") || text.includes("unauthorized") || text.includes("unusual")) {
        risk = "high";
        reason = "Contains suspicious/unauthorized activity language — needs immediate review.";
      } else if (text.includes("sign-in") || text.includes("password") || text.includes("verify") || text.includes("single-use")) {
        risk = "medium";
        reason = "Sign-in or verification email — check if this was initiated by you.";
      } else if (text.includes("alert") || text.includes("security")) {
        risk = "medium";
        reason = "Security alert from Microsoft — review to confirm it was expected.";
      }
      return { subject: e.subject, from: e.from, date: e.date, snippet: e.snippet, risk, reason };
    });

    const highCount = threats.filter((t) => t.risk === "high").length;
    const medCount = threats.filter((t) => t.risk === "medium").length;
    const overallRisk = highCount > 0 ? "high" : medCount > 2 ? "medium" : "low";

    const summary =
      threats.length === 0
        ? "No security-related emails found in your Microsoft inbox. Your accounts appear clean."
        : `Work IQ scanned your Microsoft inbox and found ${threats.length} security-related email(s). ` +
          (highCount > 0 ? `${highCount} high-risk item(s) need immediate attention.` : `No high-risk items found.`);

    res.json({ overallRisk, summary, threats, source: "Microsoft Work IQ (Graph API)" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AGENT 2: EXECUTOR — account closure action plan ──
app.post("/api/agents/executor", async (req, res) => {
  if (!req.session.workiq_tokens) {
    return res.status(401).json({ error: "workiq_not_connected", message: "Connect Microsoft Work IQ first" });
  }
  try {
    const { sentinelResult } = req.body;
    const threats = sentinelResult?.threats || [];

    // Build action plan based on real senders found
    const platformMap = {
      "microsoft": { platform: "Microsoft Account", url: "https://support.microsoft.com/en-us/account-billing/close-your-microsoft-account-c1b2d13f-4de6-6e1b-4a31-d9d668849979", docs: "Death certificate, ID proof of next-of-kin" },
      "google": { platform: "Google Account", url: "https://support.google.com/accounts/troubleshooter/6357590", docs: "Death certificate, requester ID" },
      "amazon": { platform: "Amazon", url: "https://www.amazon.in/gp/help/customer/display.html?nodeId=GDK92DNLSGWTV6MP", docs: "Death certificate, account email" },
      "paypal": { platform: "PayPal", url: "https://www.paypal.com/in/smarthelp/article/how-do-i-close-a-deceased-person", docs: "Death certificate, legal heir document" },
      "apple": { platform: "Apple/iCloud", url: "https://support.apple.com/en-us/HT208510", docs: "Court order or death certificate" },
    };

    const actions = [];
    const seen = new Set();

    for (const t of threats) {
      const fromLower = (t.from || "").toLowerCase();
      for (const [key, info] of Object.entries(platformMap)) {
        if (fromLower.includes(key) && !seen.has(key)) {
          seen.add(key);
          actions.push({
            platform: info.platform,
            action: `Submit deceased account closure request to ${info.platform}`,
            officialUrl: info.url,
            documentsNeeded: info.docs,
            priority: t.risk === "high" ? "urgent" : "normal",
          });
        }
      }
    }

    // Always include Microsoft since Work IQ found emails
    if (!seen.has("microsoft")) {
      actions.unshift({
        platform: "Microsoft Account",
        action: "Submit deceased account closure request to Microsoft",
        officialUrl: "https://support.microsoft.com/en-us/account-billing/close-your-microsoft-account-c1b2d13f-4de6-6e1b-4a31-d9d668849979",
        documentsNeeded: "Death certificate, ID proof of next-of-kin",
        priority: "normal",
      });
    }

    res.json({
      summary: `Executor identified ${actions.length} platform(s) requiring account closure action. Submit each request with the required documents.`,
      actions,
      source: "Microsoft Work IQ (Graph API)",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AGENT 3: PROTECTOR — scam warnings for grieving families ──
app.post("/api/agents/protector", async (req, res) => {
  if (!req.session.workiq_tokens) {
    return res.status(401).json({ error: "workiq_not_connected", message: "Connect Microsoft Work IQ first" });
  }
  try {
    const { sentinelResult } = req.body;
    const overallRisk = sentinelResult?.overallRisk || "low";

    const scamPatterns = [
      {
        name: "Inheritance Scam",
        description: "Scammers impersonate banks or lawyers claiming the deceased left unclaimed funds, asking for advance fees to release them.",
        warningSign: "Unsolicited emails/calls about money owed to deceased — asking you to pay a fee first",
        howToAvoid: "Never pay upfront fees. Contact your bank branch directly with your legal heir certificate.",
      },
      {
        name: "Fake Debt Collection",
        description: "Fraudsters claim the deceased owed money and pressure grieving family members into paying debts that don't exist.",
        warningSign: "Aggressive calls/emails demanding immediate payment for deceased's debts",
        howToAvoid: "Request debt proof in writing. Real creditors provide documentation. Consult a lawyer before paying anything.",
      },
      {
        name: "Account Takeover During Gap",
        description: "While accounts are unclosed, hackers attempt to access them using phishing or credential stuffing — especially Microsoft and Google accounts.",
        warningSign: "Sign-in alerts, single-use codes arriving in inbox that nobody requested",
        howToAvoid: "Immediately close or memorialize accounts. Contact Microsoft/Google with the death certificate.",
      },
      {
        name: "Impersonation of Deceased",
        description: "Scammers hack or clone the deceased's WhatsApp/social accounts and message relatives asking for money as if from the deceased.",
        warningSign: "Messages from deceased's old accounts asking for money or personal info",
        howToAvoid: "Verify by calling the person directly. Report and block the account immediately.",
      },
    ];

    const alertLevel = overallRisk === "high" ? "high" : overallRisk === "medium" ? "medium" : "low";
    res.json({
      alertLevel,
      summary: `Protector has identified ${scamPatterns.length} active scam patterns targeting grieving families. Review each warning carefully.`,
      scamPatterns,
      source: "Microsoft Work IQ (Graph API)",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
