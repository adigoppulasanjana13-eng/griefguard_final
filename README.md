# GriefGuard 🛡️

Digital estate protection for grieving families.
Scans real inboxes for security threats, generates account closure plans, and warns about scams — using live email data via OAuth, read-only.

> Built for the **Microsoft AI Skill Fest Hackathon · June 2026**

---

## 🚀 Live Demo

**👉 https://griefguard-final.onrender.com**
Demo mail:"adigoppulasanjana13@gmail.com"
if it says Scan failed: Insufficient Permission please run locally

> Just open the link, sign in with Google — no setup needed for judges.

---

## 🤖 The Three AI Agents (Microsoft Work IQ)

Outlook Inbox (Microsoft Graph API)
        ↓
🔍 SENTINEL   — Scans emails, scores threats low/medium/high
        ↓
⚡ EXECUTOR   — Builds account closure checklist with official links
        ↓
🛡️ PROTECTOR  — Warns about scams targeting grieving families

---

## ✅ Google OAuth — Works with ANY Google Account

- Uses gmail.readonly scope — read-only, safe
- Forces account picker so each user selects their own Gmail
- App is published (not in testing mode)

When you see "Google hasn't verified this app":
1. Click Advanced
2. Click "Go to griefguard (unsafe)"
3. Click Allow

---

## 🛠️ Run Locally

1. Clone the repo
git clone https://github.com/adigoppulasanjana13-eng/griefguard_final.git
cd griefguard_final

2. Install dependencies
npm install

3. Create .env file
cp .env.example .env
Fill in your own Google and Microsoft credentials from .env.example

4. Start
npm start

5. Open in browser
http://localhost:3000

---

## 🔒 Privacy & Security

| We do | We never do |
|-------|------------|
| ✅ Read-only OAuth | ❌ Send or delete emails |
| ✅ Server-side session tokens | ❌ Store passwords |
| ✅ httpOnly cookies | ❌ Log email content |
| ✅ Revoke access anytime | ❌ Access without consent |

---

## 📁 Project Structure

griefguard_final/
├── server.js          # Express backend — OAuth, Gmail scan, 3 agents
├── public/
│   ├── index.html     # Sign-in page
│   └── dashboard.html # Dashboard — results + agent pipeline
├── .env.example       # Template for credentials
└── package.json
