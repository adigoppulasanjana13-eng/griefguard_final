# GriefGuard

**Digital estate protection for grieving families.**  
Scans real inboxes for security threats, generates account closure plans, and warns about scams — using live email data via OAuth, read-only.

> Built for the **Microsoft AI Skill Fest Hackathon · June 2026**

---

## ⚡ Quick Start (Run Locally)

### 1. Install dependencies
```bash
cd griefguard_pro
npm install
```

### 2. Set up your `.env`
The `.env` file is already included with working credentials. Just run the app.

### 3. Start the app
```bash
npm start
```

### 4. Open in browser
```
http://localhost:3000
```

---

## ✅ Google OAuth — Works with ANY Google Account

The app is configured so **any Google account** can sign in:
- App is published (not in testing mode)
- Uses `gmail.metadata` scope — non-sensitive, no verification warning
- Forces account picker so each user selects their own Gmail

### When you see "Google hasn't verified this app":
1. Click **Advanced** (bottom left of the warning)
2. Click **"Go to griefguard (unsafe)"**
3. Click **Allow**

This is normal for hackathon apps — the app is safe and read-only.

---

## 🔑 Google Cloud Console Setup (if using your own credentials)

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. **APIs & Services → Library** → Enable **Gmail API**
3. **OAuth consent screen → Audience** → Set to **"In production"** (not Testing)
4. **Credentials → OAuth Client ID** → Add redirect URI:
   ```
   http://localhost:3000/auth/google/callback
   ```
5. Copy Client ID + Secret into `.env`

---

## 🤖 The Three AI Agents (Microsoft Work IQ)

```
Outlook Inbox (Microsoft Graph API)
        ↓
🔍 SENTINEL   — Scans emails, scores threats low/medium/high
        ↓
⚡ EXECUTOR   — Builds account closure checklist with official links
        ↓
🛡️ PROTECTOR  — Warns about scams targeting grieving families
```

---

## Privacy & Security

| We do | We never do |
|-------|------------|
| ✅ Read-only OAuth | ❌ Send or delete emails |
| ✅ Server-side session tokens | ❌ Store passwords |
| ✅ httpOnly cookies | ❌ Log email content |
| ✅ Revoke access anytime | ❌ Access without consent |

---

## Project Structure

```
griefguard_pro/
├── server.js          # Express backend — OAuth, Gmail scan, 3 agents
├── public/
│   ├── index.html     # Sign-in page
│   └── dashboard.html # Dashboard — results + agent pipeline
├── .env               # Credentials (already configured)
├── .env.example       # Template for reference
└── package.json
```
