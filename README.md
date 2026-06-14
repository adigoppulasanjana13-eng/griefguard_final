# 🛡️ GriefGuard — Digital Estate Protection Agent

> **Agents League Hackathon 2025 · Reasoning Agents Track**
> Powered by **Microsoft Work IQ** (Microsoft Graph API) + Google OAuth

---

## 🧩 What is GriefGuard?

When someone dies, their **digital life doesn't die with them**.

Bank accounts, email inboxes, social profiles, and subscriptions remain active — often for months. Grieving families rarely know which accounts exist, how to close them, or that scammers actively exploit this confusion window to commit fraud.

**GriefGuard** is a multi-agent AI system that:
- Scans a family member's real inbox for security threats using **Microsoft Work IQ**
- Identifies suspicious login attempts, phishing emails, and unauthorized access signals
- Generates a legal account-closure action plan with official links
- Warns families about grief-targeted scam patterns before they become victims

This is **not a mock demo**. GriefGuard connects to real inboxes via OAuth, reads real emails, and runs real AI agents over real data.

---

## ⚡ Microsoft IQ Integration

| IQ Layer | How GriefGuard Uses It |
|----------|----------------------|
| **Work IQ** ✅ | Microsoft Graph API reads the user's real Outlook inbox. The 3 AI agents reason over this real retrieved data to produce grounded, cited threat analysis — exactly what Work IQ is designed for. |

---

## 🤖 The 3 AI Agents

```
Gmail / Outlook Inbox
        ↓
  🔍 SENTINEL AGENT          — Scans real emails, scores threat level (low/medium/high)
        ↓
  ⚡ EXECUTOR AGENT           — Builds account closure action plan with official links
        ↓
  🛡️ PROTECTOR AGENT         — Identifies active scam patterns targeting the family
```

### Agent 1 — Sentinel (Threat Detection)
Reads real security emails from your Microsoft inbox via Work IQ (Graph API). Scores each email for risk based on content analysis — unauthorized access signals, suspicious sign-ins, phishing patterns. Returns an overall risk level with per-email reasoning.

### Agent 2 — Executor (Action Planning)
Takes Sentinel's findings and generates a step-by-step account closure checklist. Each action includes the **official platform URL**, required documents (death certificate, legal heir ID), and a priority level. No guessing — direct links to Google, Microsoft, Amazon, PayPal, Apple deceased-account request pages.

### Agent 3 — Protector (Scam Defence)
Identifies the 4 most active scam patterns that target grieving families: inheritance fraud, fake debt collection, account takeover during the account-closure gap, and impersonation of the deceased. Each warning includes specific red flags and how to avoid them.

---

## 🔐 Privacy & Security

| What we do | What we never do |
|-----------|-----------------|
| ✅ Read-only OAuth (Gmail + Microsoft Graph) | ❌ Store passwords |
| ✅ Server-side session tokens only | ❌ Send, delete, or modify emails |
| ✅ `httpOnly` cookies (JS can't read them) | ❌ Access anyone else's account |
| ✅ User can revoke access anytime | ❌ Log or persist email content |

OAuth tokens are stored in server-side session memory only — never in localStorage, never written to a database, never sent to the browser. Scopes are strictly read-only.

---

## 🚀 Quick Start

### Prerequisites
- Node.js v18+
- A Google account (for Gmail scan)
- A Microsoft account (for Work IQ / Outlook scan + 3 agents)

### Step 1 — Install
```bash
cd griefguard_final
npm install
```

### Step 2 — Configure environment
```bash
cp .env.example .env
```
Open `.env` and fill in:

```env
# Google OAuth (Gmail scan)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback
SESSION_SECRET=any-random-string

# Microsoft Work IQ (3 AI Agents via Graph API)
WORKIQ_CLIENT_ID=your-microsoft-app-client-id
WORKIQ_CLIENT_SECRET=your-microsoft-app-client-secret
WORKIQ_REDIRECT_URI=http://localhost:3000/auth/workiq/callback
```

### Step 3 — Get Google OAuth credentials (~5 min)
1. Go to https://console.cloud.google.com → Create project
2. **APIs & Services → Library** → Enable **Gmail API**
3. **OAuth consent screen** → External → Add `gmail.readonly` scope → Add your email as test user
4. **Credentials → Create OAuth Client ID** → Web app → Redirect URI: `http://localhost:3000/auth/google/callback`
5. Copy Client ID + Secret into `.env`

### Step 4 — Get Microsoft Work IQ credentials (~10 min)
1. Go to https://portal.azure.com → **App registrations → New registration**
2. Name: `GriefGuard` → Redirect URI: `http://localhost:3000/auth/workiq/callback`
3. **API permissions → Add → Microsoft Graph → Delegated → `Mail.Read`**
4. **Certificates & secrets → New client secret** → Copy the value
5. Copy Application (client) ID + Secret into `.env`

### Step 5 — Run
```bash
npm start
```
Open **http://localhost:3000** in your browser.

---

## 🗺️ How It Works — Full Flow

```
User opens GriefGuard
        ↓
[1] Sign in with Google → Gmail scan → Real security emails displayed
        ↓
[2] Connect Microsoft Work IQ → Sign in with Microsoft account
        ↓
[3] Click "Run Work IQ Agents"
        ↓
[Sentinel]  → Reads Outlook inbox via Graph API → Scores threats
        ↓
[Executor]  → Builds account closure checklist → Official links per platform
        ↓
[Protector] → Warns about grief-targeted scam patterns
        ↓
Family has a complete action plan in under 60 seconds
```

---

## 📁 Project Structure

```
griefguardreal/
├── server.js          # Express backend — OAuth flows + all 3 agents + Work IQ
├── public/
│   ├── index.html     # Login page (Google OAuth)
│   └── dashboard.html # Dashboard — scan results + 3 agent pipeline
├── .env.example       # Environment variable template
├── package.json
└── README.md
```

---

## 🏆 Hackathon Rubric — How GriefGuard Scores

| Criterion | How GriefGuard Addresses It |
|-----------|----------------------------|
| **Accuracy & Relevance (20%)** | Real Gmail + Outlook data via OAuth. Work IQ (Microsoft Graph) satisfies the Microsoft IQ requirement. Agents reason over real retrieved emails, not mock data. |
| **Reasoning & Multi-step Thinking (20%)** | Clear 3-agent pipeline: Sentinel → Executor → Protector. Each agent takes the previous agent's output as context and builds on it. |
| **Creativity & Originality (15%)** | "Digital afterlife / grief tech" is an underserved, emotionally resonant niche. The honest pivot — orchestration + scam protection instead of fake "account blocking" — is more original and defensible. |
| **User Experience (15%)** | Live OAuth demo with real data. Agent pipeline shows live status transitions (running → done). Clean dark UI with risk badges and direct platform links. |
| **Reliability & Safety (20%)** | Read-only OAuth scopes. Server-side token storage. httpOnly cookies. No password storage. Explicit "what we never do" contract shown to users. |
| **Community Vote (10%)** | Post demo video + repo link in Discord: https://aka.ms/agentsleague/discord |

---

## 🔮 Future Roadmap

- **Real-time alerts** — Background cron job + Twilio SMS when new security emails arrive
- **Multi-platform OAuth** — Facebook, Instagram, bank portals (where APIs exist)
- **Automated closure letters** — Pre-filled PDF generation for each platform's deceased-account process
- **Legal document scanner** — Upload death certificate → OCR → auto-fill platform request forms
- **Family dashboard** — Multiple family members collaborating on the same case

---

## 👩‍💻 Built For

**Microsoft Agents League Hackathon · June 4–14, 2026**
Track: 🧠 Reasoning Agents · Tool: Microsoft Foundry / Work IQ

---

*GriefGuard does not access, modify, or delete any accounts. All email access is read-only and user-consented via official OAuth flows. Users can revoke access at any time via their Google or Microsoft account settings.*
