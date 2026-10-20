 # ARGUS

ARGUS (also called ShieldSense in the app) is an AI email security agent that flags suspicious emails (phishing and spam) by connecting to Gmail through the Gmail API and Google OAuth. Built as a team of 2 and demoed to judges.

> **"Your Gmail, protected by AI."**  
> *AI-inspired threat detection for phishing emails, malicious links, scams, and suspicious attachments.*

---

## 🎯 Post-Connection Gmail Security Dashboard

ShieldSense implements a dedicated **Gmail Security Dashboard** post-login experience matching modern enterprise cybersecurity platforms:

```
Landing Page
    ↓
Connect Gmail
    ↓
Google OAuth 2.0
    ↓
ShieldSense Gmail Security Dashboard (/dashboard)
```

---

## 🖥️ Dashboard Architecture & Views

### 1. Left Sidebar Navigation
- 🛡 **ShieldSense** Brand & Live Protection Indicator
- 📥 **Inbox** (Total Gmail email count & risk segregation)
- ⚠️ **Threat Inbox** (Active Dangerous & Suspicious threats)
- 📎 **Attachments** (Automatically aggregated files found across all emails)
- 🔗 **Links** (Automatically aggregated URLs found across all emails)
- ⚙️ **Settings** (Google OAuth 2.0 configuration, scope status, sync controls)
- 👤 **Account Profile** (Connected source display + Return to Landing link)

### 2. Main Inbox View
- **Title**: `Gmail Inbox`
- **Subtitle**: *"ShieldSense automatically analyzes your emails, embedded links, and attachments."*
- **Risk Filters**: `All`, `🟢 Safe`, `🟠 Suspicious`, `🔴 Dangerous`, `🛡 Quarantine`
- **Search Bar**: Live search across sender, subject, and email body
- **Email Row Components**:
  - Sender & Domain
  - Subject line & Preview snippet
  - Embedded indicators (`🔗 1 Link`, `📎 1 Attachment`)
  - Date & Timestamp
  - Overall Risk Badge & Score (`🔴 HIGH RISK — 94/100`, `🟠 SUSPICIOUS — 58/100`, `🟢 SAFE — 12/100`, `🛡 QUARANTINE`)

### 3. Discovered Attachments View
- Lists every attachment extracted from Gmail messages.
- Displays: *Filename*, *Size*, *Origin Email Subject*, *Sender*, *Risk Score (0-100)*, *Threat Status*, and 1-click **Inspect Email** action.
- **Zero manual uploads required**.

### 4. Discovered Links View
- Lists every hyperlink extracted from Gmail messages.
- Displays: *Target URL*, *Domain*, *Origin Email Subject*, *Sender*, *Risk Score (0-100)*, *Threat Status*, and 1-click **Inspect Email** action.
- **Zero manual URL pasting required**.

### 5. Multi-Signal Investigation Drawer
Clicking any email, threat item, attachment, or link opens the deep forensic panel:
- **Overall Threat Score**: `94/100 — HIGH RISK`
- **Email Information**: Sender, Subject, Date, Body excerpt
- **Email Analysis Checklist**: `✓ Sender analyzed`, `✓ Message intent analyzed`, `✓ Suspicious language checked`
- **Links Found**: Individual scores (e.g., `🔗 suspicious-example.com — Risk: 96/100`)
- **Attachments Found**: Individual scores (e.g., `📎 invoice.pdf — Risk: 72/100`)
- **WHY THIS EMAIL WAS FLAGGED**: Transparent plain-language reason summary
- **RECOMMENDED ACTION**: `🛡 QUARANTINE`
- **Reversible Action Controls**: `[ 🛡 Move to Quarantine ]`, `[ Keep in Inbox ]`, `[ 🔄 Release from Quarantine ]`

---

## ⚡ Quick Start & Judge Demonstration

### How to Run:
### How to Run:
1. Clone the repository
2. Run `npm install`
3. Copy `.env.example` to `.env` and add your own Google OAuth credentials
4. Run `npm start` (or `node server.js`)
5. Open `http://localhost:3000` in your browser

### 2-Minute Presentation Script:
1. **Landing Page**: Show the hero section (*"Your Gmail, protected by AI"*) with 4 trust indicators and the live product preview card.
2. **Connect Gmail**: Click **`[ Connect Gmail → ]`** to open the Google OAuth modal or launch the **Dashboard Demo Stream**.
3. **Explore Dashboard**:
   - Navigate between **Inbox**, **Threat Inbox**, **Attachments**, and **Links** on the left sidebar.
   - Show how the filters (`All`, `Safe`, `Suspicious`, `Dangerous`, `Quarantine`) organize the inbox.
4. **Deep Investigation**:
   - Click the suspicious email (*"Urgent: Verify your account"*).
   - Show the **Investigation Drawer** breakdown: *Sender findings*, *Intent findings*, *Link score (99/100)*, *Attachment score (85/100)*, and the plain-language *"Why this email was flagged"* box.
5. **Reversible Quarantine**:
   - Click **`[ 🛡 Move to Quarantine ]`** to isolate the threat.
   - Switch to the Quarantine filter and click **`[ 🔄 Release from Quarantine ]`** to restore it to the inbox.

---

## 📁 Project Structure

```
├── index.html        # SPA layout: Landing page + Dedicated Gmail Security Dashboard
├── style.css         # Cyberpunk navy theme, responsive sidebar layout, and drawer animations
├── analyzer.js       # Unified multi-signal heuristic threat detection engines
├── app.js            # SPA view router, dashboard controller, Google OAuth & drawer UI
└── README.md         # Demonstration guide & competition cheat sheet
```

---

## 👥 Built for Cybersecurity Competition MVP
*ShieldSense - "Your Gmail, protected by AI"*
