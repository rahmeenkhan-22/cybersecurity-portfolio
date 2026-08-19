# System-Wide Threat Detection & Incident Response Simulation — LummaC2

A layered detection exercise combining host-based signature scanning, YARA rule matching, anomaly-based filesystem hunting, and Suricata network traffic analysis against a real, previously catalogued LummaC2 infostealer sample.

## Summary

Single detection tools are not enough. This exercise planted a verified LummaC2 sample (reused from an earlier infostealer family analysis) in a world-writable, rarely inspected directory, then ran it past four independent detection layers:

| Layer | Method | Result |
|---|---|---|
| 1 | ClamAV (signature-based) | **Miss** |
| 2 | YARA (rule-based) | **Miss** |
| 3 | Anomaly-based filesystem hunting | **Detected** |
| 4 | Suricata (network traffic analysis) | **Detected** |

Two of four layers missed the sample entirely — consistent with LummaC2's frequent-rebuild, packed-binary tradecraft. The other two caught it through complementary, non-signature-based means. That gap is the actual finding of the exercise: defense in depth isn't a slogan, it's what catches what your AV and rule sets miss.

## Environment & Tooling

- **OS:** Kali Linux
- **IDS:** Suricata 8.0.6, Emerging Threats Open ruleset (68,186 rules loaded / 52,245 enabled)
- **AV:** ClamAV 1.4.5 (`clamav`, `clamav-daemon`, `clamdscan`, `freshclam`)
- **YARA rules:** [ail-project/ail-yara-rules](https://github.com/ail-project/ail-yara-rules) — LummaC2-specific rules
- **PCAP source:** [malware-traffic-analysis.net](https://malware-traffic-analysis.net) — public "Lumma in the Room-Ah" exercise
- **Planted sample:** verified LummaC2 binary (SHA-256 confirmed via MalwareBazaar in a prior task)

## Methodology

1. **Tooling setup** — Suricata + ET Open ruleset, `tcpreplay`, ClamAV stack installed and verified.
2. **Scenario sourcing** — Used a public malware-traffic-analysis.net exercise, which documents a SOC alert for `ET MALWARE Lumma Stealer Victim Fingerprinting Activity` on an internal LAN segment.
3. **Simulated dropper placement** — Planted two artifacts in `/var/tmp` (a world-writable, infrequently inspected directory):
   - `.hidden_cache` — the exercise PCAP, disguised under an innocuous filename
   - `.sys_update_cache` — the verified LummaC2 binary, disguised as a legitimate-sounding system file
4. **Layer 1 — ClamAV:** full recursive scan, then a targeted scan of `/var/tmp`.
5. **Layer 2 — YARA:** ran ail-project LummaC2 rules directly against the planted binary.
6. **Layer 3 — Anomaly-based hunting:** used `find` to enumerate recently modified files across common dropper staging directories (`/var/tmp`, `/tmp`, `/dev/shm`), independent of any signature database.
7. **Layer 4 — Network analysis:** ran Suricata offline against the PCAP, parsed `fast.log` for alert volume and severity.
8. **Remediation:** removed all planted artifacts, verified `/var/tmp` clean.

## Layer 1 & 2 — Why the Signature-Based Tools Missed It

ClamAV and YARA both rely on matching known static indicators — hashes, byte sequences, string patterns — against a maintained database. LummaC2 operators are documented to rebuild the binary frequently with new string encoding and obfuscation, which erodes the shelf life of any static signature almost as soon as it's published. This sample's packed, Go-based structure left no recoverable plaintext strings for static analysis to key on.

> **Note on ClamAV noise:** an initial unrestricted `clamscan -r /` produced a large number of "FOUND" results unrelated to the planted sample — genuine signature hits against Kali's own bundled offensive-security tooling (Metasploit, PowerShell-Empire, Mimikatz, etc.). This is expected behavior when scanning a pentest distro, and was excluded from subsequent scans with `--exclude-dir`. Distinguishing real findings from expected tooling noise is itself a core SOC skill.

## Layer 3 — Anomaly-Based Filesystem Hunting

With both signature-based layers returning a miss, a behavioral approach was used instead:

```
find -newer /var/tmp/.hidden_cache
```

This located `/var/tmp/.sys_update_cache`. Two independent indicators confirmed the finding:

- `file` identified it as a **PE32 executable for MS Windows** — a Windows binary on a Linux filesystem is an immediate anomaly on its own.
- `sha256sum` matched the known LummaC2 sample hash exactly, independently confirming identity without relying on any signature engine.

**Result:** anomaly/behavioral hunting succeeded where signature matching failed — demonstrating why file-type and recency-based hunting is a necessary complement to signature engines against packed, frequently-rebuilt malware.

## Layer 4 — Suricata Network Traffic Analysis

The public LummaC2 C2 traffic capture was analyzed offline against the ET Open ruleset:

```
sudo suricata -r 2026-01-31-traffic-analysis-exercise.pcap \
  -c /etc/suricata/suricata.yaml -l ~/suricata_logs/ -k none
```

`fast.log` showed ET MALWARE alerts for CnC domains observed in DNS lookups and TLS SNI, plus repeated victim-fingerprinting activity flagged against the internal host.

Alert tally:

```
wc -l fast.log                          → 55 total alerts
grep "ET MALWARE" fast.log | wc -l      → 30
grep "Priority: 1" fast.log | wc -l     → 30
```

**Result:** Suricata independently and conclusively detected the LummaC2 C2 activity at the network layer. All 30 ET MALWARE alerts were rated Priority 1 (highest severity), correctly identifying both the malicious C2 domains and the fingerprinting behavior that triggered the original SOC alert in the source exercise.

## Remediation

```
sudo rm /var/tmp/.sys_update_cache
sudo rm /var/tmp/.hidden_cache
ls /var/tmp
```

Post-remediation listing confirmed only legitimate system directories remained — no trace of the planted files.

## Findings

| Detection Layer | Result | Basis |
|---|---|---|
| ClamAV (signature) | Miss | No signature match for this LummaC2 build |
| YARA (rule-based) | Miss | Rules stale against this rebuild |
| Anomaly-based hunting | Detected | File-type anomaly (PE32 on Linux) + exact SHA-256 match |
| Suricata (network) | Detected | 30 Priority-1 ET MALWARE alerts on C2 traffic |

Neither Layer 3 nor Layer 4 depended on a pre-existing signature for this specific build. Layer 3 caught a behavioral anomaly and confirmed it cryptographically; Layer 4 caught it by network behavior — DNS/TLS SNI to known C2 infrastructure and characteristic fingerprinting traffic — rather than inspecting the binary at all. That's exactly the kind of detection that keeps working even as the malware's on-disk form changes with every rebuild.

## Conclusion

Layered detection matters most against actively maintained, frequently rebuilt malware families like LummaC2. A single tool — even a well-maintained one — wasn't sufficient here: ClamAV and YARA both missed a real, verified sample due to the family's rapid rebuild cadence, while anomaly-based hunting and network analysis each independently caught the same threat through complementary means. The value of this exercise isn't a clean sweep of detections — it's the demonstrated case for defense in depth: when signature-based tools fail, behavioral and network-layer detection provide the redundancy needed to catch what static matching alone would miss.

---
*Tools: ClamAV · YARA · Suricata (Emerging Threats Open ruleset) · Linux filesystem forensics*
*Sample and PCAP sourced from MalwareBazaar and malware-traffic-analysis.net, public malware research resources.*
