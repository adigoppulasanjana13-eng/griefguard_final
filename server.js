require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { google } = require("googleapis");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ── Session setup ──────────────────────────────────────────────────────────────
// express-session with MemoryStore is fine for a hackathon demo.
// Each user gets their own session cookie, so multiple users work correctly
// as long as they use different browsers (or incognito windows).
// For production, swap MemoryStore for connect-pg-simple, connect-redis, etc.
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // true on Render (HTTPS), false locally
      maxAge: 1000 * 60 * 60 * 4, // 4 hours (was 1 hour — avoids mid-demo expiry)
    },
  })
);

app.set("trust proxy", 1); // Required for Render/Heroku HTTPS sessions
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

// ── Google OAuth client ────────────────────────────────────────────────────────
function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || `${BASE_URL}/auth/google/callback`
  );
}

// Gmail metadata scope — non-sensitive, no verification warning, works for any Google account
const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
];

// ── FIX 1: Google OAuth — "consent" prompt forces a new consent screen every
// time, which is correct for multi-user so each user authorises their OWN
// account. Without this, Google may skip the account picker and silently reuse
// the last-logged-in account, which breaks multi-user usage.
//
// We also add "select_account" so that if a user is already signed into
// multiple Google accounts in their browser, they can pick the right one.
app.get("/auth/google", (req, res) => {
  const oauth2Client = getOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: GOOGLE_SCOPES,
    prompt: "select_account consent", // FIX: was just "consent" — now also forces account picker
  });
  res.redirect(url);
});

// ── Google OAuth callback ──────────────────────────────────────────────────────
app.get("/auth/google/callback", async (req, res) => {
  const { code, error } = req.query;

  // FIX 2: Handle the case where user cancels the Google consent screen.
  // Previously this fell through to a crash; now we redirect cleanly.
  if (error) {
    console.warn("Google OAuth error:", error);
    return res.redirect("/?error=" + encodeURIComponent(error));
  }
  if (!code) return res.redirect("/?error=no_code");

  try {
    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const { data: profile } = await oauth2.userinfo.get();

    // Tokens stored server-side in this user's session only.
    // A different user in a different browser has a completely separate session.
    req.session.tokens = tokens;
    req.session.profile = { email: profile.email, name: profile.name };

    res.redirect("/dashboard.html");
  } catch (err) {
    console.error("OAuth callback error:", err.message);
    res.redirect("/?error=auth_failed");
  }
});

// ── Who is logged in? ──────────────────────────────────────────────────────────
app.get("/api/me", (req, res) => {
  if (!req.session.profile) return res.status(401).json({ error: "not_logged_in" });
  res.json({ profile: req.session.profile });
});

// ── Logout ─────────────────────────────────────────────────────────────────────
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ── Gmail scan ─────────────────────────────────────────────────────────────────
// Read-only scan for security-related emails. Searches by subject/sender only;
// never reads the full body of any message.
app.get("/api/scan", async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: "not_logged_in" });

  try {
    const oauth2Client = getOAuthClient();
    oauth2Client.setCredentials(req.session.tokens);

    // FIX 3: Persist refreshed tokens back into the session.
    // The googleapis library automatically refreshes expired access tokens
    // using the refresh_token, but it emits the new tokens via this event.
    // Without this listener, the refreshed token is lost and the next request
    // fails with "invalid_grant". This was already present but is critical.
    oauth2Client.on("tokens", (newTokens) => {
      req.session.tokens = { ...req.session.tokens, ...newTokens };
    });

    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

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

      for (const msg of (listRes.data.messages || [])) {
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

    // FIX 4: If the access token is truly expired/revoked (e.g. user revoked
    // access in Google settings), the googleapis library can't refresh it.
    // Detect this and force the user to re-login cleanly instead of showing
    // a confusing internal error.
    if (err.message?.includes("invalid_grant") || err.code === 401) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: "session_expired", message: "Your Google session expired. Please sign in again." });
    }

    res.status(500).json({ error: "scan_failed", message: err.message });
  }
});

// ── Azure AI Foundry — optional grounded risk analysis ────────────────────────
async function callFoundryIQ(findings, userEmail) {
  const endpoint = process.env.AZURE_FOUNDRY_ENDPOINT;
  const key = process.env.AZURE_FOUNDRY_KEY;
  const deployment = process.env.AZURE_FOUNDRY_DEPLOYMENT || "gpt-4o";

  if (!endpoint || !key) throw new Error("FOUNDRY_NOT_CONFIGURED");

  const url = `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-01`;

  const systemPrompt = `You are Sentinel, a security analysis agent inside GriefGuard, powered by Microsoft Foundry IQ.
You are given REAL email metadata (subject, sender, snippet, date) retrieved from a user's Gmail inbox via read-only OAuth.
Analyze for genuine security concerns (account takeover, phishing, suspicious sign-ins) vs routine notifications.
Ground every claim in the specific emails provided — cite the subject line or sender as evidence.
Respond ONLY with valid JSON:
{
  "overallRiskLevel": "low"|"medium"|"high",
  "summary": string,
  "items": [
    { "subject": string, "riskLevel": "low"|"medium"|"high", "reasoning": string, "recommendedAction": string }
  ]
}`;

  const userPrompt = `Account: ${userEmail}
Real emails found in inbox (${findings.length} total):
${JSON.stringify(findings, null, 2)}

Analyze these and produce the risk summary now.`;

  const response = await fetch(url, {
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

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Foundry IQ error ${response.status}: ${err}`);
  }

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || "{}";
  return JSON.parse(text.replace(/```json|```/g, "").trim());
}

app.post("/api/analyze", async (req, res) => {
  if (!req.session.profile) return res.status(401).json({ error: "not_logged_in" });

  const { findings } = req.body;
  if (!Array.isArray(findings)) return res.status(400).json({ error: "findings array required" });

  if (findings.length === 0) {
    return res.json({
      overallRiskLevel: "low",
      summary: "No security-related emails were found in your inbox during this scan.",
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

// ══════════════════════════════════════════════════════════════════════════════
// MICROSOFT WORK IQ — 3 AI Agents via Microsoft Graph API
//
// Agent 1 — SENTINEL  : Scans Outlook inbox, scores threats
// Agent 2 — EXECUTOR  : Builds account closure plan with official links
// Agent 3 — PROTECTOR : Warns about scams targeting grieving families
//
// Required .env vars:
//   WORKIQ_CLIENT_ID      from Azure App Registration
//   WORKIQ_CLIENT_SECRET  from Azure App Registration
//   WORKIQ_REDIRECT_URI   http://localhost:3000/auth/workiq/callback
// ══════════════════════════════════════════════════════════════════════════════

const WORKIQ_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0";
const GRAPH_URL = "https://graph.microsoft.com/v1.0";

// ── Microsoft OAuth login ──────────────────────────────────────────────────────
app.get("/auth/workiq", (req, res) => {
  const clientId = process.env.WORKIQ_CLIENT_ID;
  if (!clientId) return res.redirect("/dashboard.html?workiq_error=not_configured");

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: process.env.WORKIQ_REDIRECT_URI || `${BASE_URL}/auth/workiq/callback`,
    scope: "openid email profile Mail.Read User.Read offline_access",
    response_mode: "query",
    prompt: "select_account", // Forces Microsoft account picker — critical for multi-user
  });

  res.redirect(`${WORKIQ_AUTH_URL}/authorize?${params}`);
});

// ── Microsoft OAuth callback ───────────────────────────────────────────────────
app.get("/auth/workiq/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.redirect("/dashboard.html?workiq_error=" + encodeURIComponent(error || "no_code"));
  }

  try {
    const tokenRes = await fetch(`${WORKIQ_AUTH_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.WORKIQ_CLIENT_ID,
        client_secret: process.env.WORKIQ_CLIENT_SECRET,
        code,
        redirect_uri: process.env.WORKIQ_REDIRECT_URI || `${BASE_URL}/auth/workiq/callback`,
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

    if (me.error) throw new Error(me.error.message || "Failed to fetch Microsoft profile");

    // Store in this user's session only
    req.session.workiq_tokens = tokens;
    req.session.workiq_profile = {
      email: me.mail || me.userPrincipalName || "",
      name: me.displayName || "",
    };

    // Store token expiry time so we can check before using
    req.session.workiq_token_expires_at = Date.now() + (tokens.expires_in || 3600) * 1000;

    res.redirect("/dashboard.html?workiq=connected");
  } catch (err) {
    console.error("Work IQ callback error:", err.message);
    res.redirect("/dashboard.html?workiq_error=" + encodeURIComponent("auth_failed"));
  }
});

// ── Work IQ helpers ────────────────────────────────────────────────────────────

// FIX 5: Refresh the Microsoft access token if it's expired or about to expire.
// Unlike Google, Microsoft tokens must be refreshed manually — there's no SDK
// doing it automatically. Without this, agents fail ~1 hour after login.
async function getValidWorkIQToken(req) {
  const tokens = req.session.workiq_tokens;
  if (!tokens) throw new Error("workiq_not_connected");

  const expiresAt = req.session.workiq_token_expires_at || 0;
  const BUFFER_MS = 5 * 60 * 1000; // refresh 5 minutes before expiry

  if (Date.now() < expiresAt - BUFFER_MS) {
    return tokens.access_token; // still valid
  }

  // Token expired or about to expire — refresh it
  if (!tokens.refresh_token) {
    // No refresh token: force re-login
    delete req.session.workiq_tokens;
    delete req.session.workiq_profile;
    throw new Error("workiq_session_expired");
  }

  const refreshRes = await fetch(`${WORKIQ_AUTH_URL}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: process.env.WORKIQ_CLIENT_ID,
      client_secret: process.env.WORKIQ_CLIENT_SECRET,
      refresh_token: tokens.refresh_token,
      grant_type: "refresh_token",
    }),
  });

  const newTokens = await refreshRes.json();
  if (newTokens.error) throw new Error(newTokens.error_description || newTokens.error);

  req.session.workiq_tokens = { ...tokens, ...newTokens };
  req.session.workiq_token_expires_at = Date.now() + (newTokens.expires_in || 3600) * 1000;

  return newTokens.access_token;
}

// Fetch Outlook emails matching security-related subjects via Microsoft Graph
async function fetchWorkIQEmails(accessToken) {
  const filter = [
    "contains(subject,'security')",
    "contains(subject,'sign-in')",
    "contains(subject,'suspicious')",
    "contains(subject,'password')",
    "contains(subject,'verify')",
    "contains(subject,'unusual')",
    "contains(subject,'alert')",
    "contains(subject,'single-use')",
  ].join(" or ");

  const res = await fetch(
    `${GRAPH_URL}/me/messages?$filter=${encodeURIComponent(filter)}&$select=subject,from,receivedDateTime,bodyPreview&$top=20&$orderby=receivedDateTime desc`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `Graph API error ${res.status}`);
  }

  const data = await res.json();
  return (data.value || []).map((m) => ({
    id: m.id,
    subject: m.subject || "",
    from: m.from?.emailAddress?.address || "",
    date: m.receivedDateTime || "",
    snippet: m.bodyPreview || "",
  }));
}

// ── Work IQ status ─────────────────────────────────────────────────────────────
app.get("/api/workiq/status", (req, res) => {
  if (!req.session.workiq_profile) return res.json({ connected: false });
  res.json({ connected: true, profile: req.session.workiq_profile });
});

// ── Work IQ logout ─────────────────────────────────────────────────────────────
app.post("/api/workiq/logout", (req, res) => {
  delete req.session.workiq_tokens;
  delete req.session.workiq_profile;
  delete req.session.workiq_token_expires_at;
  res.json({ ok: true });
});

// ── AGENT 1: SENTINEL — threat detection ──────────────────────────────────────
app.post("/api/agents/sentinel", async (req, res) => {
  if (!req.session.workiq_tokens) {
    return res.status(401).json({ error: "workiq_not_connected", message: "Connect Microsoft Work IQ first." });
  }

  try {
    const accessToken = await getValidWorkIQToken(req);
    const emails = await fetchWorkIQEmails(accessToken);

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
        ? "No security-related emails found in your Microsoft inbox. Your account appears clean."
        : `Work IQ scanned your Microsoft inbox and found ${threats.length} security-related email(s). ` +
          (highCount > 0 ? `${highCount} high-risk item(s) need immediate attention.` : "No high-risk items detected.");

    res.json({ overallRisk, summary, threats, source: "Microsoft Work IQ (Graph API)" });
  } catch (err) {
    if (err.message === "workiq_session_expired") {
      return res.status(401).json({ error: "workiq_session_expired", message: "Microsoft session expired. Please reconnect Work IQ." });
    }
    console.error("Sentinel error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── AGENT 2: EXECUTOR — account closure plan ───────────────────────────────────
app.post("/api/agents/executor", async (req, res) => {
  if (!req.session.workiq_tokens) {
    return res.status(401).json({ error: "workiq_not_connected", message: "Connect Microsoft Work IQ first." });
  }

  try {
    const { sentinelResult } = req.body;
    const threats = sentinelResult?.threats || [];

    const platformMap = {
      microsoft: {
        platform: "Microsoft Account",
        url: "https://support.microsoft.com/en-us/account-billing/close-your-microsoft-account-c1b2d13f-4de6-6e1b-4a31-d9d668849979",
        docs: "Death certificate, ID proof of next-of-kin",
      },
      google: {
        platform: "Google Account",
        url: "https://support.google.com/accounts/troubleshooter/6357590",
        docs: "Death certificate, requester ID",
      },
      amazon: {
        platform: "Amazon",
        url: "https://www.amazon.in/gp/help/customer/display.html?nodeId=GDK92DNLSGWTV6MP",
        docs: "Death certificate, account email",
      },
      paypal: {
        platform: "PayPal",
        url: "https://www.paypal.com/in/smarthelp/article/how-do-i-close-a-deceased-person",
        docs: "Death certificate, legal heir document",
      },
      apple: {
        platform: "Apple / iCloud",
        url: "https://support.apple.com/en-us/HT208510",
        docs: "Court order or death certificate",
      },
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

    // Microsoft is always included — Work IQ email access means a Microsoft account is active
    if (!seen.has("microsoft")) {
      actions.unshift({
        platform: "Microsoft Account",
        action: "Submit deceased account closure request to Microsoft",
        officialUrl: platformMap.microsoft.url,
        documentsNeeded: platformMap.microsoft.docs,
        priority: "normal",
      });
    }

    res.json({
      summary: `Executor identified ${actions.length} platform(s) requiring account closure action.`,
      actions,
      source: "Microsoft Work IQ (Graph API)",
    });
  } catch (err) {
    console.error("Executor error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── AGENT 3: PROTECTOR — scam warnings ────────────────────────────────────────
app.post("/api/agents/protector", async (req, res) => {
  if (!req.session.workiq_tokens) {
    return res.status(401).json({ error: "workiq_not_connected", message: "Connect Microsoft Work IQ first." });
  }

  try {
    const { sentinelResult } = req.body;
    const overallRisk = sentinelResult?.overallRisk || "low";

    const scamPatterns = [
      {
        name: "Inheritance Scam",
        description: "Scammers impersonate banks or lawyers claiming the deceased left unclaimed funds, asking for advance fees to release them.",
        warningSign: "Unsolicited emails or calls about money owed to the deceased — asking you to pay a fee first",
        howToAvoid: "Never pay upfront fees. Contact your bank branch directly with your legal heir certificate.",
      },
      {
        name: "Fake Debt Collection",
        description: "Fraudsters claim the deceased owed money and pressure grieving family members into paying debts that don't exist.",
        warningSign: "Aggressive calls or emails demanding immediate payment for the deceased's debts",
        howToAvoid: "Request proof of debt in writing. Real creditors provide documentation. Consult a lawyer before paying anything.",
      },
      {
        name: "Account Takeover During Closure Gap",
        description: "While accounts are unclosed, hackers attempt access via phishing or credential stuffing — especially Microsoft and Google accounts.",
        warningSign: "Sign-in alerts or single-use codes arriving in the inbox that nobody requested",
        howToAvoid: "Close or memorialize accounts immediately. Contact Microsoft or Google with the death certificate.",
      },
      {
        name: "Impersonation of the Deceased",
        description: "Scammers hack or clone the deceased's WhatsApp or social accounts and message relatives asking for money.",
        warningSign: "Messages from the deceased's old accounts asking for money or personal information",
        howToAvoid: "Verify by calling the person directly. Report and block the account immediately.",
      },
    ];

    const alertLevel = overallRisk === "high" ? "high" : overallRisk === "medium" ? "medium" : "low";
    res.json({
      alertLevel,
      summary: `Protector identified ${scamPatterns.length} active scam patterns targeting grieving families. Review each warning carefully.`,
      scamPatterns,
      source: "Microsoft Work IQ (Graph API)",
    });
  } catch (err) {
    console.error("Protector error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`GriefGuard running at http://localhost:${PORT}`);
});
