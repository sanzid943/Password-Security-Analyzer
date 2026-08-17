# Vaultline — Password Security Analyzer

A fully client-side password analyzer and generator. No backend, no build step,
no dependencies — just HTML, CSS, and vanilla JavaScript. Nothing you type ever
leaves the browser tab.

## Features

**Analyzer**
- Real-time analysis as you type
- Strength meter with Weak / Medium / Strong rating + 0–100 score
- Length, uppercase, lowercase, number, and special-character checks
- Common/breached password detection (built-in list)
- Repeated-character and sequential-pattern detection (e.g. `aaa`, `1234`, `qwerty`)
- Shannon entropy calculation (bits)
- Estimated crack-time indicator across three attack scenarios (throttled online,
  slow offline hash, fast GPU offline hash)
- Password reuse warning — stores only a SHA-256 fingerprint of analyzed
  passwords in `localStorage`, never the password itself
- Show / hide password toggle
- Personalized improvement suggestions

**Generator**
- Adjustable length (6–48 characters)
- Toggle uppercase, lowercase, numbers, symbols
- Optional "exclude ambiguous characters" (`l`, `1`, `I`, `O`, `0`)
- Cryptographically secure randomness (`crypto.getRandomValues`)
- Guarantees at least one character from every selected character set
- Copy to clipboard
- One-click "send to analyzer" to immediately score a generated password

## Run it in VS Code

You don't need Node, npm, or any build tooling — it's static HTML/CSS/JS.

1. Open this folder (`password-security-analyzer`) in VS Code.
2. Easiest option: install the **Live Server** extension (by Ritwick Dey) from
   the Extensions panel, then right-click `index.html` → **"Open with Live Server"**.
   It will open at something like `http://127.0.0.1:5500`.
3. Alternative without any extension: just double-click `index.html` in your
   file explorer to open it directly in your browser — everything still works,
   since there's no server-side code.

## File structure

```
password-security-analyzer/
├── index.html    # Markup / layout
├── style.css     # Visual design (dark "vault" theme)
├── script.js     # All analysis, scoring, generator, and history logic
└── README.md
```

## Notes

- The common-password list and crack-time attack rates are illustrative, not
  exhaustive — this is an educational tool, not a substitute for a real breach
  database (e.g. Have I Been Pwned) in production systems.
- History fingerprints are stored only in your browser's `localStorage`. Use
  the "Clear" button in the Generator panel to wipe them.
