# Suspicious Email Investigation — Header Forensics, Payload Analysis & Threat Attribution

An end-to-end investigation of two suspicious emails, tracing them back to shared attacker infrastructure through header forensics, attachment extraction, and OSINT — despite the two emails using completely different social-engineering pretexts.

## Summary

Two emails, two different lures — a fake Netflix billing notice and a fake $150K sales-contract job offer — turned out to share the same sending domain, the same BCC address, and infrastructure registered through the same registrar. Neither delivered an executable payload; both were social-engineering attacks designed to steal credentials, payment details, or money directly. Treating them as isolated one-offs would have missed the correlation that makes them worth blocking as a single campaign.

| | Email 1 — Netflix Phishing | Email 2 — Fake Job Offer |
|---|---|---|
| **Verdict** | Malicious | Malicious |
| **Risk** | High | Medium |
| **Type** | Credential/payment harvesting | Business Email Compromise / advance-fee fraud |
| **Executable payload?** | No | No |

## Methodology & Environment

All analysis was performed inside an isolated Linux VM (no shared clipboard/folders, clean snapshot beforehand). Internet access was permitted only for OSINT lookups and sandboxed URL detonation.

**Tools:** `cat`/`grep`/`xxd`/`strings`/`file` for raw `.eml` inspection · Python (`email`, `quopri`) for MIME parsing and attachment extraction · `md5sum`/`sha1sum`/`sha256sum` for hashing · `pdfid`/`pdf-parser` for static PDF analysis · `curl` for redirect tracing · [urlscan.io](https://urlscan.io) for safe sandboxed URL detonation · [VirusTotal](https://virustotal.com) for reputation checks · `whois` for domain registration lookups

## Email 1 — "Keeping Your Membership Active" (Fake Netflix Notice)

**The setup:** Display name and footer text impersonated Netflix ("Membership Netflix" via account@netflix.com), but the actual sending address had no relationship to Netflix at all. Recipient address was an oddly-formatted bulk-harvesting-style address, not a real inbox.

**Header analysis — the key finding:** SPF, DKIM, and DMARC all *passed*. That sounds reassuring, but they were validating the **attacker's own domain**, not Netflix's. This is a critical distinction: passing authentication checks only proves the sending domain is properly configured — it says nothing about whether that domain is legitimate. The sending IP resolved to Google's own mail infrastructure, confirming the email was sent from a Gmail-hosted account rather than a compromised Netflix server.

**Infrastructure reputation:**

| Indicator | Age | VirusTotal Result |
|---|---|---|
| Attacker sending domain | 8 years | 0/91 — clean, but tagged as DGA-style |
| Malicious redirector domain | 7 years | 3/91 — flagged Phishing / Malicious |
| Sending IP | — | Clean — legitimate Gmail relay |

Both attacker-associated domains were registered years ago through the same registrar — indicating a **reusable phishing infrastructure pool**, not a one-off campaign.

**Social engineering techniques identified:**
- Brand impersonation (with a misspelled brand name in the footer — a classic low-effort-phishing tell)
- Urgency/fear tactic ("payment failed," access at risk)
- CTA button linking to the credential-harvesting domain, not any real Netflix property
- Mismatched brand asset — the embedded logo image was generic, not Netflix's, suggesting a recycled phishing kit template

**Link analysis:** Traced the redirect chain via `curl -sIL` and detonated safely via urlscan.io. At time of analysis, the link had been switched to redirect to Google — consistent with either a time-limited campaign window or anti-analysis logic that redirects known scanner traffic away from the live payload while continuing to serve real victims. This doesn't change the malicious classification; the domain is independently flagged by multiple vendors regardless of its current live state.

**Payload analysis:** Two attachments extracted and hashed — both turned out to be benign PNG images (one the phishing kit's logo, one a stray unrelated branding image), declared with generic `application/octet-stream` MIME types and non-descriptive `.bin` filenames as a light obfuscation technique to discourage casual inspection. No executable code or scripts in either.

## Email 2 — "A Quick Note for You" (Fake Job Offer / BEC)

**The setup:** Same sending address as Email 1, despite an entirely different pretext — a fabricated $150,000 "non-recourse cash advance" sales contract, referencing a phone call that never happened.

**Header analysis:** Same SPF/DKIM-pass-on-attacker-domain pattern as Email 1. Sending IP fell within the same infrastructure block as Email 1's, and both emails shared an identical BCC address — strong evidence both were sent as part of the same batch/campaign.

**Key finding — borrowed identity, not domain spoofing:** The company name referenced in the email belongs to a real, 16-year-old, completely unrelated business with a clean reputation. The attacker didn't spoof or compromise that company's infrastructure — they simply borrowed the name to make a casual verification check (glancing at the company website) appear to confirm legitimacy. A second domain referenced in the signature (a legitimate email-signature-generation SaaS tool) was used only to render the fake sender's signature image.

**Social engineering techniques identified:**
- False pretext of prior contact ("thank you for your time on the phone earlier" — no call occurred)
- Financial lure — an unrealistically large advance framed as "non-recourse"
- Fabricated legitimacy — named contact, phone number, real-looking company link, LinkedIn profile
- Borrowed brand identity from an unrelated real business

**Payload analysis:** Two attachments — one a genuine, unrelated PDF (a mortgage remittance document, almost certainly harvested from an unrelated prior data exposure and reused as generic "proof of legitimacy" filler — itself a notable indicator of a broader BEC/invoice-fraud threat actor), and a second file with an alarming BEC-associated filename pattern ("inbox-rules," a name strongly associated with real mailbox-compromise attacks) that turned out to be only a few bytes of non-functional data — a psychological decoy rather than a working payload. Static PDF analysis (`pdfid`) confirmed zero JavaScript, auto-actions, launch triggers, or embedded files in the legitimate PDF.

## Cross-Email Correlation

Despite completely different lures, both emails shared:
- Identical sending domain and identical BCC address
- Sending IPs from the same infrastructure block
- Domains registered through the same registrar, both multiple years old

**Conclusion:** treat these as a single threat actor's infrastructure, not two isolated incidents — blocking should target the shared sending pattern as a whole, not just the individual lure domains.

## Recommendations

**For end users:** don't click links or open attachments in either email pattern; verify billing notices by navigating directly to the official site rather than clicking email links; treat unsolicited job offers involving large cash advances as a strong fraud signal regardless of how professional they look.

**For SOC/Blue Team:**
- Search mail logs for other messages from the same sending domain/IPs to find other targeted recipients
- Check proxy/DNS logs for any user interaction with the malicious redirector domain — treat hits as a credential-compromise incident
- Watch for the same infrastructure pattern (same registrar, same Gmail-relay-based sending, matching BCC test addresses) as an early-warning signal for this actor's future campaigns

**For email security controls:**
- Block the attacker's sending domain and the malicious redirector domain at the gateway/DNS resolver
- Strengthen DMARC enforcement (reject/quarantine) on internal domains to prevent similar display-name spoofing
- Flag emails where the DKIM/SPF-authenticated sending domain differs from the "From" display name — a strong indicator seen in both cases here
- Add a content rule flagging "inbox-rules"-style filenames combined with an external sender, given the pattern's association with real mailbox-compromise social engineering

---
*Tools: header/MIME forensics via Python + coreutils · urlscan.io · VirusTotal · whois*
*Both emails analyzed in an isolated VM per standard safe-handling practice; no live malware execution occurred.*
