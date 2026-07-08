# Operation NorthStar — DFIR CTF Challenge (Interactive)

A static, password-gated, single-file web application for the **Operation NorthStar** DFIR (Digital Forensics and Incident Response) CTF challenge. Twenty forensic questions covering the chain of compromise at a fictional satellite office — from initial ICMP reconnaissance through web exploitation, credential theft, lateral movement, and data exfiltration.

The challenge is presented as an interactive, self-validating site: every correct answer is confirmed in real time, every wrong answer reveals the correct one and unlocks the full investigation writeup (steps, CLI, forensic tip).

## Quick Start

Just open `index.html` in any modern browser. No server, no build step, no dependencies.

```bash
# Linux / macOS
xdg-open index.html   # or: open index.html

# Windows
start index.html
```

On first load you'll be prompted for the access password. After unlocking, all progress is saved to `localStorage` and persists across page refreshes.

## Changing the Password

The access password is a single line near the top of the inline `<script>` block. Open `index.html` in any text editor and find:

```javascript
// ====================================================================
// ACCESS PASSWORD — Change this single line to set a new password.
// ====================================================================
var ACCESS_PASSWORD = "aku jagoan neon bang";
```

Replace the value between the quotes with whatever you want, save, and reopen. The change takes effect immediately on next page load.

> **Note:** The password check is purely client-side. It is intended to keep casual viewers out, not to protect sensitive content. Anyone with the source can read the password in the JS. For real access control, place the file behind HTTP authentication or a login proxy.

## Deploying to GitHub Pages

This site is a single self-contained HTML file, so deploying to GitHub.io is trivial.

1. **Create a GitHub repository** for the challenge (e.g. `operation-northstar`).
2. **Copy `index.html` into the repository root.** If the site should serve at the root of your GitHub Pages URL, name the file `index.html` (already done). If you're hosting it as a project page under an existing user/org site, drop it into a subfolder.
3. **Commit and push** to the `main` branch.
4. **Enable GitHub Pages:** go to *Settings → Pages*, set *Source* to *Deploy from a branch*, choose `main` / `(root)`, and save.
5. After ~30 seconds the site is live at:
   - User page: `https://<username>.github.io/`
   - Project page: `https://<username>.github.io/operation-northstar/`

> If you've been locked out (someone else has unlocked on the same browser), the `localStorage` key is `northstar_progress_v1`. Clear it from DevTools → *Application* → *Local Storage*, or use the in-app *Reset* button.

## Features

- **Password gate** with shake animation on wrong input
- **Sticky score bar** with live progress bar and quick controls
- **Question index** (table of contents) showing solved / unsolved state per question
- **20 expandable question cards** with narrative forensic briefs
- **Real-time case-insensitive validation** (whitespace-collapsed, lowercase comparison)
- **Submit-once enforcement** (the input is disabled after first submission)
- **Investigation writeup** revealed only after submission, with multi-step CLI workflows and forensic tips
- **Completion modal** with verdict tiers (Perfect / Excellent / Good / Keep Learning)
- **`localStorage` persistence** — refresh-safe, with a Reset button
- **Fully responsive** — works on phones, tablets, and desktops
- **Zero external dependencies** — all CSS and JS inline, no fonts, no CDNs, no images

## Browser Support

Any evergreen browser (Chrome 90+, Firefox 90+, Safari 14+, Edge 90+). Uses only standard ES6+ features and CSS Grid/Flexbox.

## File Layout

```
Operation-NorthStar-web/
├── README.md       ← this file
└── index.html      ← the entire site (CSS, JS, content all in one file)
```

## Content & Attribution

- **Author:** PhyN
- **Difficulty:** Medium (11 questions) + Hard (9 questions) = 20 total
- **Domain:** DFIR, network forensics, web exploitation, lateral movement, data exfiltration
- **Scenario date:** 10 September 2024
- All log data referenced in the questions is synthetically generated for training purposes.

## License & Use

Use freely for training, classroom exercises, capture-the-flag events, and self-study. If you publish a derivative, please retain the author credit (PhyN) and link back to the original scenario.

---

*Built as a portable, GitHub.io-deployable interactive version of the static Operation NorthStar scenario brief.*
