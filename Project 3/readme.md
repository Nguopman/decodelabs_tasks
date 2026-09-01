# Project 3: Phishing Awareness Analysis & Triage Toolkit 🔍

**Track:** Junior Analyst // DecodeLabs Industrial Kit (Batch 2026)  
**Phase:** Threat Identification & Human Firewall Defense[cite: 3]

## Overview
Welcome to Project 3 of the DecodeLabs Cybersecurity Internship. With **80% of security breaches involving phishing**, technical firewalls alone cannot compensate for human error[cite: 3]. This project establishes a structured Phishing Triage Toolkit and automated analyzer to parse email headers, detect psychological triggers, and categorize threats before enterprise impact occurs.

## Key Threat Taxonomy & Red Flags
- **Display Name & Header Spoofing:** Mismatch between the trusted friendly name and the underlying routing domain[cite: 3].
- **Typosquatting & Homoglyphs:** Subtle character substitutions (e.g., Cyrillic characters or misspelled brand domains like `amaz0n.com`)[cite: 3].
- **Subdomain Traps:** Burying malicious root domains at the end of a long, legitimate-looking string evaluated from right to left (e.g., `www.decodelabs.tech.login-update.com`)[cite: 3].
- **Psychological Triggers:** Exploiting **Urgency** (accounts locking in 30 minutes), **Authority** (unquestioned C-suite wire transfers), and **Fear** to bypass rational logic[cite: 3].
- **Dangerous File Smuggling:** Use of high-risk file attachments (`.iso`, `.scr`, `.js`, `.hta`) bypassing standard gateway inspections[cite: 3].

## Actionable Decision Tree
Every triage event results in a definitive operational outcome[cite: 3]:
1. **Safe:** Close ticket[cite: 3].
2. **Suspicious:** Warn user and enforce out-of-band verification via phone/directory[cite: 3].
3. **Malicious:** Block domain, purge message across all corporate inboxes, and escalate[cite: 3].

## Technical Implementation & Usage
- **Language:** Python 3[cite: 3]
- **Run the Triage Script:**
  ```bash
  python3 phishing_analyzer.py
