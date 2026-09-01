import re

def analyze_email(sender: str, subject: str, body: str, links: list, attachments: list) -> dict:
    """
    Parses email headers, links, and content against known phishing indicators
    to provide an automated triage classification (Safe, Suspicious, or Malicious).
    """
    red_flags = []
    score = 0

    # 1. Sender & Domain Mismatch Checks
    # Extract domain from sender string (e.g., "Name <support@logins-updates.com>")
    domain_match = re.search(r"@([A-Za-z0-9.-]+)", sender)
    if domain_match:
        sender_domain = domain_match.group(1).lower()
        # Look for suspicious generic webmail or lookalike domains
        if any(brand in sender_domain for brand in ["microsoft", "paypal", "amazon", "google"]) and not any(legit in sender_domain for legit in ["microsoft.com", "paypal.com", "amazon.com", "google.com"]):
            red_flags.append(f"Typosquatting/Spoofed Brand Domain detected in sender: {sender_domain}")
            score += 3
        elif "logins" in sender_domain or "update" in sender_domain or "secure" in sender_domain:
            red_flags.append(f"Combosquatting/Suspicious keyword in sender domain: {sender_domain}")
            score += 2

    # 2. Urgency & Psychological Trigger Checks
    urgency_keywords = ["urgent", "immediate action", "account locked", "suspended", "verify", "strict confidentiality", "wire transfer", "password expires"]
    content_text = f"{subject} {body}".lower()
    for keyword in urgency_keywords:
        if keyword in content_text:
            red_flags.append(f"Psychological trigger keyword detected: '{keyword}'")
            score += 1

    # 3. URL and Subdomain Trap Checks (Right-to-Left evaluation)
    for link in links:
        link_lower = link.lower()
        # Check for subdomain burial (e.g., legitimate root buried at the end or multi-subdomain tricks)
        parts = link_lower.replace("https://", "").replace("http://", "").split("/")[0].split(".")
        if len(parts) > 3:
            red_flags.append(f"Nested Subdomain Trap detected in URL: {link}")
            score += 3
        if any(ext in link_lower for ext in [ ".tk", ".ml", ".ga", ".cf", ".gq"]):
            red_flags.append(f"High-risk top-level domain in link: {link}")
            score += 2

    # 4. Dangerous Attachment Checks
    dangerous_extensions = [".iso", ".scr", ".js", ".hta", ".exe", ".vbs", ".html"]
    for att in attachments:
        if any(att.lower().endswith(ext) for ext in dangerous_extensions):
            red_flags.append(f"Dangerous attachment extension detected (Malware Smuggling Risk): {att}")
            score += 4

    # 5. Actionable Outcome Decision Tree
    if score >= 4:
        action = "Malicious"
        recommendation = "Block domain immediately, purge from all user inboxes, and escalate to Incident Response."
    elif score >= 2:
        action = "Suspicious"
        recommendation = "Warn user, flag email as external/untrusted, and require out-of-band verification."
    else:
        action = "Safe"
        recommendation = "Close triage ticket; no anomalous indicators found."

    return {
        "classification": action,
        "risk_score": score,
        "red_flags": red_flags,
        "recommendation": recommendation
    }

def main():
    print("=" * 60)
    print("  DecodeLabs: Project 3 - Phishing Triage Analyzer Tool")
    print("=" * 60)
    
    print("\n[+] Enter sample email details for triage simulation:")
    sender = input("Sender (e.g., 'Support <support@logins-updates.com>'): ")
    subject = input("Email Subject: ")
    body = input("Email Body Content: ")
    
    links_input = input("Enter URLs found in email (comma-separated, or leave blank): ")
    links = [l.strip() for l in links_input.split(",")] if links_input else []
    
    att_input = input("Enter Attachments (comma-separated, e.g., 'Security_Update.iso'), or leave blank: ")
    attachments = [a.strip() for a in att_input.split(",")] if att_input else []

    result = analyze_email(sender, subject, body, links, attachments)

    print("\n" + "-" * 40)
    print("  TRIPAGE RESULTS & AUDIT REPORT")
    print("-" * 40)
    print(f"[*] Threat Classification : {result['classification']}")
    print(f"[*] Cumulative Risk Score : {result['risk_score']}")
    print(f"[*] Actionable Outcome    : {result['recommendation']}")
    
    if result["red_flags"]:
        print("\n[!] Identified Red Flags:")
        for flag in result["red_flags"]:
            print(f"    - {flag}")
    else:
        print("\n[+] No suspicious indicators flagged.")

if __name__ == "__main__":
    main()
