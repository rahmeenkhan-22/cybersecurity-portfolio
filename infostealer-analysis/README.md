# Infostealer Malware Analysis — Six-Family Study & YARA Rule Testing

A hands-on study of six prevalent infostealer malware families, using real samples sourced from MalwareBazaar and testing public YARA detection rules against each to evaluate real-world rule effectiveness.

## Summary

Publicly available YARA rules are not, by themselves, a reliable detection mechanism against current infostealer builds. Across 15 rule executions spanning two GitHub repositories and six malware families, **only one produced a confirmed match**. MalwareBazaar's own internal rule engine detected all six samples using family-specific signatures — proving effective rules exist, but that the public repositories tested lag well behind the build velocity of active MaaS (Malware-as-a-Service) operators.

## Environment & Methodology

- **OS:** Kali Linux (isolated VM)
- **YARA:** v4.5.7
- **Extraction:** 7-Zip
- **Rule repositories tested:** [ail-project/ail-yara-rules](https://github.com/ail-project/ail-yara-rules), [RussianPanda95/Yara-Rules](https://github.com/RussianPanda95/Yara-Rules)
- **Sample source:** [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch)

For each of the six families:
1. **Sample selection** — pulled from MalwareBazaar, filtered to samples with at least one confirmed family-specific YARA match on the platform itself (vendor ground truth).
2. **Pre-download documentation** — recorded SHA-256 and MalwareBazaar's own detection signatures.
3. **Network isolation** — VM network adapter set to Host-Only before extracting any live binary.
4. **Extraction & integrity check** — password-protected sample extracted via 7z, hash re-verified against the MalwareBazaar record.
5. **YARA testing** — each family's rule file(s) run individually from both repositories.
6. **Cross-family false-positive testing** — rules for the other five families run against each sample to check for misfires.
7. **Static string analysis** — `strings` + `grep` for keyword indicators, to assess obfuscation level and infer capability.
8. **Cleanup** — sample deleted before reconnecting network.

## Families Analyzed

| Family | Language/Type | Obfuscation | ail-project | RussianPanda95 | Match? |
|---|---|---|---|---|---|
| Vidar/Arkei | PE32, packed | Full (packed) | No | No | **No** |
| RedLine | .NET | None (plaintext) | No | No rule | **No** |
| Raccoon V2 | PE32 | Partial | No | **Match ✓** | **Yes** |
| LummaC2 | Go binary | Full (XOR-encrypted) | No | No | **No** |
| StealC V2 | Rust, UPX-packed | Partial (string-split) | No | No | **No** |
| Meduza | PE32+ | Full (TLS + runtime) | No | No | **No** |

### Vidar/Arkei
Fork of Arkei Stealer, sold as MaaS, targets browser credentials, crypto wallets, VPN/FTP configs. Sample was tagged "Arkei" but matched two independently-authored *Vidar* rules on MalwareBazaar — showing how much lineage ambiguity complicates detection between closely related codebases. `strings` returned nothing; the binary is fully packed (`pe_no_import_table` hit), explaining both local rule misses.

### RedLine Stealer
One of the most widely deployed credential stealers, C#/.NET, unobfuscated — internal class/method names are fully readable in plaintext. MalwareBazaar matched **8 independent vendor rules** against this sample; the local ail-project rule still missed, and RussianPanda95 has no RedLine rule at all. Disrupted by law enforcement (Operation Magnus, Oct 2024), but new variants persist.

### Raccoon Stealer V2 (RecordBreaker)
**The only confirmed local match in the entire study** — RussianPanda95's `raccoonstealerv2.3.1.1.yar` hit, while a slightly older version-specific rule (`raccoonstealerv2_2.1.0-4_build.yar`) from the same author did not. That gap is a clean demonstration of the precision/coverage tradeoff in version-specific YARA rules. String analysis recovered a hardcoded SQL query (`SELECT origin_url, username_value, password_value FROM logins`) plus an embedded SQLite3 API — definitive evidence the malware ships its own database engine to pull credentials directly from Chrome's login store.

### LummaC2 Stealer
Go-based, actively developed MaaS, rebuilt frequently with new XOR-based string encryption per build — which is exactly why static rules age out so fast against it. All three local rules missed. MalwareBazaar's hits came from *structural* Go-binary detection rules (not string-based), which is why they succeeded where string-matching approaches failed. Despite a Microsoft-led infrastructure takedown (May 2025), this sample was first seen in June 2026 — confirming the family's continued operational activity.

### StealC V2
Delivered as a secondary payload by the **Amadey loader** (`dropped-by-amadey` tag) — a reminder that catching an infostealer payload alone isn't the whole incident; there's likely a loader with persistence upstream. UPX-packed, with partial string obfuscation: recovered fragments like `FtPx`, `Ftph` confirm FTP credential targeting even though full strings are split/garbled to dodge matching.

### Meduza Stealer
Notable for a built-in **UAC bypass** via the ICMLuaUtil Elevated COM interface (UACMe Method 41), confirmed via MalwareBazaar's `ICMLuaUtil_UACMe_M41` rule — meaning it can escalate privileges without a UAC prompt on vulnerable configurations. Also uses TLS callbacks to execute code before standard debugger breakpoints trigger. All three local rules missed, including a January-2024 dated rule against a September-2024 sample — the family had already diverged from that rule's baseline within months.

## Key Findings

**Rule staleness is the primary detection gap.** ail-project rules missed every single sample, despite MalwareBazaar's engine identifying all six via family-specific signatures. This strongly suggests the public rules were authored against earlier builds and haven't kept pace — especially damaging for fast-iterating families like LummaC2.

**Version specificity is a real tradeoff.** Raccoon V2's split result (one RussianPanda95 rule matched, a near-identical one didn't) shows why layered rule sets — combining broad family-level rules with narrow build-specific ones — outperform either approach alone.

**No cross-family false positives**, across any of the 30 cross-tests run. The tested rule sets are specific enough to avoid alert fatigue from family confusion — though a few generic heuristic rules (Go-binary detection, anti-VM detection, suspicious SQL-query patterns) did fire across multiple families on MalwareBazaar, and would need tuning for production use.

**Obfuscation level tracked directly with detectability.** The two families with recoverable plaintext strings (RedLine, Raccoon V2) were also the two with the richest static findings — and Raccoon V2 was the only confirmed match.

## Recommendations

- **Refresh cadence:** actively-developed MaaS families (LummaC2, StealC, Meduza) need YARA rule updates at least monthly — subscribing to YARAhub/Malpedia notifications helps.
- **Layer static with behavioral detection:** fully-packed families (Vidar/Arkei, LummaC2, Meduza) yield nothing to static analysis — Sigma rules and EDR telemetry are necessary complements.
- **Sandbox packed samples:** detonating in a sandbox (any.run, CAPE) recovers runtime-decrypted strings and C2 configs that can seed updated rules.
- **Watch the delivery chain, not just the payload:** StealC's Amadey-loader delivery is a reminder that IR needs to check for upstream loader persistence, not just the infostealer itself.
- **Monitor UAC bypass at the event-log level:** Meduza's ICMLuaUtil bypass (Event ID 4688, ICMLuaUtil.dll load) should be detected independently of file-based scanning.

---
*Tools: YARA 4.5.7 · MalwareBazaar (abuse.ch) · Kali Linux (isolated VM)*
*All samples sourced from MalwareBazaar, a public malware research repository; SHA-256 hashes verified prior to analysis.*
