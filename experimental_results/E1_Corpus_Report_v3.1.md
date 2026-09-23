# E1: Local Session-Separated Deployment Corpus

---

## Executive Summary

This report documents Work Package **E1: Local Session-Separated Deployment Corpus** for the Hybrid-NIDS architecture (Suricata \+ Random Forest). E1 provides a controlled traffic corpus for E2 (calibration) and E3 (comparative evaluation). Each session has one **primary ground-truth record**; event-level evidence records provide traceability to the underlying network and host evidence.

| Metric | Value |
| :---- | :---- |
| Total Sessions | **32** |
| PCAP (MB) | **1,157** |
| EVE Lines | **11.1M** |
| Flows | **407,905** |

- **30 active sessions** (15 Dev \+ 15 Test) across 5 scenarios \+ **2 excluded**  
- **Strict partition integrity:** Dev complete 09:43 UTC, freeze 09:49, Test starts 09:56  
- **Session-level primary ground truth** with 23 fields, 5 frozen reason codes  
- **Scenario-appropriate independent corroboration** for all 15 Test events (AC-12 PASS)  
- **Full provenance:** 47-field manifest, 166 evidence rows, 198 SHA-256 checksums  
- **Hardware utilization** recorded for all 32 sessions  
- **24/24 automated validation checks passed**  
- **E3 preregistered:** McNemar (primary), Bootstrap CI (secondary effect estimate)

---

## 1\. Goal & Methodology

E1 constructs a controlled, session-separated network traffic corpus. Four objectives:

- **G1 — Scenario Coverage:** Five traffic classes, ≥3 sessions per partition.  
- **G2 — Partition Integrity:** All Dev complete \+ config frozen before any Test.  
- **G3 — Reproducibility:** Complete provenance chain per session.  
- **G4 — Ground Truth Traceability:** Each session has one primary ground-truth record with reason\_code, corroboration type, and confidence status.

### Evidence Types per Scenario

| Scenario | Tool | Controller | Independent Evidence | Reason Code |
| :---- | :---- | :---- | :---- | :---- |
| NORMAL | curl | HTTP responses | http\_server / PCAP HTTP | CONFIRMED\_HOST |
| SCAN | nmap \-sT | Port scan output | PCAP SYN/RST \+ scan\_conn\_log | CONFIRMED\_PCAP |
| BRUTE | hydra | Login attempts | auth.log | CONFIRMED\_HOST |
| DOS | hping3 | SYN flood count | PCAP volume \+ vmstat CPU | CONFIRMED\_PCAP |
| EXPLOIT | nmap NSE / nikto | Script output | PCAP \+ target availability\* | CONFIRMED\_PCAP |

> \*Nikto: target availability corroborates service configuration, not individual request processing. SCAN: PCAP connection patterns (SYN/RST) and derived scan\_connection\_log.csv are the independent corroboration, not target port status.

### Permission & Ethics Statement

All traffic generation, packet capture, host logging, and system interaction were conducted on laboratory systems under the authorization of the project institution. No third-party or production traffic was intentionally captured. The attacker (Kali) and target (soc-nids-monitor) are dedicated experimental hosts on an isolated 192.168.10.0/24 network segment.

### 1.1 Environment

- **NIDS host:** soc-nids-monitor (192.168.10.146), Ubuntu 22.04.2 LTS  
- **Attacker:** kali (192.168.10.101)  
- **Capture:** ens18, BPF: net 192.168.10.0/24  
- **Model:** rf21\_schema\_gap (CIC-IDS2017/CSE-CIC-IDS2018)  
- **Suricata:** 8.0.4, offline on session PCAP  
- **NFStream:** 6.6.0, Python 3.10.12, scikit-learn 1.6.1

---

## 2\. Table IX — Corpus Summary

| Partition | Scenario | Sessions | PCAP MB | EVE Lines | Flows | GT Conf | GT Excl |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| DEV | NORMAL | 3 | 0.1 | 1,054 | 54 | 3 | 0 |
| DEV | SCAN | 3 | 0.7 | 6,266 | 3,219 | 3 | 0 |
| DEV | BRUTE\_FORCE | 3 | 0.2 | 1,246 | 32 | 3 | 0 |
| DEV | DOS | 3 | 545.4 | 5,514,302 | 196,612 | 3 | 0 |
| DEV | EXPLOIT | 5 | 41.1 | 94,434 | 4,311 | 3 | 2 |
| **DEV** | **SUBTOTAL** | **17** | **587.6** | **5,617,302** | **204,228** | **15** | **2** |
| TEST | NORMAL | 3 | 0.1 | 1,116 | 93 | 3 | 0 |
| TEST | SCAN | 3 | 0.4 | 6,104 | 2,543 | 3 | 0 |
| TEST | BRUTE\_FORCE | 3 | 0.1 | 667 | 18 | 3 | 0 |
| TEST | DOS | 3 | 527.9 | 5,336,942 | 196,611 | 3 | 0 |
| TEST | EXPLOIT | 3 | 41.1 | 121,866 | 4,412 | 3 | 0 |
| **TEST** | **SUBTOTAL** | **15** | **569.7** | **5,466,695** | **203,677** | **15** | **0** |
|  | **TOTAL** | **32** | **1,157** | **11,083,997** | **407,905** | **30** | **2** |

---

## 3\. Development Sessions Detail

17 Dev sessions. 15 active \+ 2 excluded.

### 3.1 Normal

| Session | Pkts | EVE | Flows |
| :---- | :---- | :---- | :---- |
| DEV\_NORMAL\_01 | 471 | 351 | 18 |
| DEV\_NORMAL\_02 | 299 | 351 | 18 |
| DEV\_NORMAL\_03 | 297 | 352 | 18 |

### 3.2 Scan

| Session | Pkts | EVE | Flows |
| :---- | :---- | :---- | :---- |
| DEV\_SCAN\_01 | 2,547 | 2,109 | 1,073 |
| DEV\_SCAN\_02 | 2,536 | 2,100 | 1,073 |
| DEV\_SCAN\_03 | 2,550 | 2,057 | 1,073 |

### 3.3 Brute Force

| Session | Pkts | EVE | Flows |
| :---- | :---- | :---- | :---- |
| DEV\_BRUTE\_01 | 619 | 612 | 17 |
| DEV\_BRUTE\_02 | 320 | 327 | 8 |
| DEV\_BRUTE\_03 | 297 | 307 | 7 |

### 3.4 DoS (hping3 SYN flood, 30s)

| Session | Packets | PCAP MB | EVE | Flows |
| :---- | :---- | :---- | :---- | :---- |
| DEV\_DOS\_01 | 2,878,757 | 186.1 | 1,943,252 | 65,538 |
| DEV\_DOS\_02 | 2,524,409 | 163.3 | 1,703,995 | 65,537 |
| DEV\_DOS\_03 | 2,766,599 | 178.9 | 1,867,055 | 65,537 |

### 3.5 Exploit

| Session | Tool | Packets | EVE | Status |
| :---- | :---- | :---- | :---- | :---- |
| DEV\_EXPLOIT\_01 | Metasploit | 33 | — | EXCLUDED |
| DEV\_EXPLOIT\_01b | nmap NSE | 25,988 | 26,681 | complete |
| DEV\_EXPLOIT\_02 | nmap NSE | 20,890 | 23,697 | complete |
| DEV\_EXPLOIT\_03 | nmap NSE | 24 | — | EXCLUDED |
| DEV\_EXPLOIT\_03b | nikto | 70,848 | 43,997 | complete |

---

## 4\. Test Sessions Detail

15 Test sessions, all complete. First Test 09:56:19 UTC.

### 4.1–4.3 Normal / Scan / Brute

| Session | Scenario | Pkts | EVE | Flows | Host Evidence |
| :---- | :---- | :---- | :---- | :---- | :---- |
| TEST\_NORMAL\_01 | normal | 333 | 372 | 31 | 46 bytes |
| TEST\_NORMAL\_02 | normal | 333 | 370 | 31 | 65 lines (PCAP HTTP) |
| TEST\_NORMAL\_03 | normal | 336 | 374 | 31 | 65 lines (PCAP HTTP) |
| TEST\_SCAN\_01 | scan | 1,729 | 2,028 | 845 | scan\_conn\_log |
| TEST\_SCAN\_02 | scan | 1,715 | 2,009 | 837 | scan\_conn\_log |
| TEST\_SCAN\_03 | scan | 1,760 | 2,067 | 861 | scan\_conn\_log |
| TEST\_BRUTE\_01 | brute | 207 | 217 | 6 | 20 auth.log entries |
| TEST\_BRUTE\_02 | brute | 216 | 226 | 6 | 20 auth.log entries |
| TEST\_BRUTE\_03 | brute | 214 | 224 | 6 | 20 auth.log entries |

### 4.4 DoS

| Session | Packets | PCAP MB | EVE | Flows |
| :---- | :---- | :---- | :---- | :---- |
| TEST\_DOS\_01 | 2,659,023 | 177.9 | 1,794,501 | 65,537 |
| TEST\_DOS\_02 | 2,648,088 | 177.3 | 1,786,962 | 65,537 |
| TEST\_DOS\_03 | 2,600,786 | 174.1 | 1,755,479 | 65,537 |

### 4.5 Exploit

| Session | Tool | Packets | EVE | Flows |
| :---- | :---- | :---- | :---- | :---- |
| TEST\_EXPLOIT\_01 | nmap NSE | 23,669 | 26,785 | 2,319 |
| TEST\_EXPLOIT\_02 | nmap NSE | 20,747 | 23,536 | 2,072 |
| TEST\_EXPLOIT\_03 | nikto | 71,525 | 71,545 | 21 |

> Exploit corroboration: controller \+ PCAP traffic analysis. Nikto target availability corroborates service configuration, not individual request processing.

---

## 5\. Ground Truth & Reason Codes

Each session has one **primary ground-truth record** in e1\_ground\_truth.csv (23 fields). Event-level evidence records in e1\_event\_manifest.csv provide traceability from the session to the underlying network and host evidence. All Test events have **scenario-appropriate independent corroboration**.

### Reason Codes (Frozen)

| Reason Code | Status | \# | Definition |
| :---- | :---- | :---- | :---- |
| GT\_CONFIRMED\_CONTROLLER\_HOST | confirmed | 12 | Controller \+ host application log |
| GT\_CONFIRMED\_CONTROLLER\_PCAP | confirmed | 18 | Controller \+ PCAP traffic analysis |
| GT\_EXCLUDED\_ABORTED | excluded | 1 | Session aborted |
| GT\_EXCLUDED\_NO\_TARGET\_MATCH | excluded | 1 | No target interaction |
| GT\_UNCERTAIN\_NO\_HOST\_CORR. | uncertain | 0 | Reserved |

### Corroboration Types

| Corroboration Type | \# | Scenarios |
| :---- | :---- | :---- |
| controller \+ host application log | 12 | NORMAL, BRUTE |
| controller \+ PCAP traffic volume | 6 | DOS |
| controller \+ tool output \+ PCAP | 6 | EXPLOIT (nmap NSE) |
| controller \+ PCAP \+ target availability\* | 6 | EXPLOIT (nikto) |
| none (insufficient) | 2 | Excluded |

> \*Target availability confirms service was reachable and configured; it does not confirm individual request processing by the application.

---

## 6\. Provenance Chain

Three-tier: **Session Manifest** (47 fields) → **Event Manifest** (166 evidence rows, verified: 166/166 files exist \+ SHA match) → **SHA-256 Manifest** (198 artifacts).

### 6.1 Session Manifest — 47 Fields

| Group | \# | Contents |
| :---- | :---- | :---- |
| Identity | 6 | session\_id, partition, campaign\_id, scenario, chron\_order, status |
| Time | 4 | start/end\_utc, duration\_seconds, timezone\_offset |
| Network | 8 | attacker/target host+IP, ports, capture, interface, bpf |
| Paths | 7 | pcap, eve, flows, controller, host\_log, sysstats, scan\_conn |
| Sizes | 7 | pcap\_size, line counts, packet\_count, artifact\_count |
| Integrity | 3 | pcap\_sha256, eve\_sha256, integrity\_artifact\_count |
| Quality | 3 | packet\_drops, flow\_drops, capture\_drop\_count |
| GT Summary | 5 | label, status, reason\_code, confidence, corroboration |
| Reproducibility | 4 | attack\_tool, command, exclusion\_reason, notes |

### 6.2 Event Manifest — 166 Evidence Rows (Verified)

Automated integrity check: 166/166 files exist, SHA-256 match, unique IDs, roles assigned.

| Corroboration Role | Count |
| :---- | :---- |
| primary\_controller | 32 |
| suricata\_alert\_output | 32 |
| nfstream\_flow\_output | 32 |
| supplementary\_host\_log | 20 |
| independent\_pcap\_corroboration | 18 |
| supplementary\_pcap | 14 |
| independent\_host\_corroboration | 12 |
| derived\_connection\_evidence | 6 |

### 6.3 SHA-256 Manifest — 198 Artifacts

4 have size=0 with documented empty\_reason (1 excluded \+ 3 no server-side logging).

| Artifact Type | Count |
| :---- | :---- |
| pcap | 32 |
| eve | 32 |
| flow | 32 |
| controller | 32 |
| host\_log | 32 |
| hardware | 32 |
| scan\_connection\_log | 6 |

---

## 7\. Hardware Utilization

| Scenario | usr% | sys% | idle% | Free Mem | Note |
| :---- | :---- | :---- | :---- | :---- | :---- |
| NORMAL | 2.7% | 1.1% | 96.0% | 473 MB | Baseline |
| SCAN | 3.4% | 1.7% | 94.7% | 605 MB | Minimal |
| BRUTE\_FORCE | 2.9% | 1.6% | 95.4% | 544 MB | Minimal |
| DOS | 7.9% | 24.0% | 66.8% | 496 MB | Heavy kernel overhead |
| EXPLOIT | 4.2% | 2.9% | 92.3% | 669 MB | Moderate |

**DoS:** SYN-flood traffic was observed at the target and was associated with elevated system CPU utilization (sys% 29–34%, idle 52–60%). **Application-level service degradation was not directly measured in E1.**

| Session | Samples | usr% | sys% | idle% | Free Mem |
| :---- | :---- | :---- | :---- | :---- | :---- |
| DEV\_DOS\_01 | 83 | 2.9% | 4.3% | 92.6% | 458 MB |
| DEV\_DOS\_02 | 9 | 9.3% | 29.0% | 60.2% | 568 MB |
| DEV\_DOS\_03 | 26 | 4.5% | 10.2% | 85.0% | 689 MB |
| TEST\_DOS\_01 | 8 | 9.9% | 33.5% | 55.0% | 387 MB |
| TEST\_DOS\_02 | 8 | 11.5% | 33.8% | 52.5% | 446 MB |
| TEST\_DOS\_03 | 8 | 9.5% | 33.1% | 55.4% | 427 MB |

---

## 8\. Validation & Acceptance Criteria

12 criteria, 24 checks. All passed.

| ID | Criterion | Result | Detail |
| :---- | :---- | :---- | :---- |
| AC-1 | Scenario Completeness | PASS | ≥3 per scenario per partition |
| AC-2 | Partition Integrity | PASS | Dev 09:43 \< Test 09:56; 0 overlap |
| AC-3 | Config Freeze | PASS | Freeze 09:49 before Test |
| AC-4 | GT Coverage | PASS | 32/32; all reason\_codes valid |
| AC-5 | Evidence Chain | PASS | Min 5 rows/event (avg 5.2) |
| AC-6 | Integrity Manifest | PASS | 198 artifacts; 4 empty documented |
| AC-7 | Zero Drops | PASS | All drops \= 0 |
| AC-8 | Hardware Metrics | PASS | 32/32 vmstat |
| AC-9 | Excluded Handling | PASS | 2 excluded consistent |
| AC-10 | Chronological Order | PASS | Monotonic both partitions |
| AC-11 | E3 Preregistration | PASS | File exists |
| AC-12 | Test GT Sufficiency | PASS | 15/15 confirmed \+ indep. corroboration |

### ✅ ALL 24/24 CHECKS PASSED

---

## 9\. Configuration Freeze & E3 Preregistration

### 9.1 Configuration Freeze (2026-09-18T09:49:49+00:00)

| Component | Version / SHA-256 |
| :---- | :---- |
| Python | 3.10.12 |
| scikit-learn | 1.6.1 |
| NFStream | 6.6.0 |
| Suricata | 8.0.4 RELEASE |
| Model pipeline | SHA e3acec66... |
| Feature schema | SHA c244f777... |
| Suricata rules | SHA 210221d8... (44.8 MB) |
| Suricata config | SHA 806c5054... |

### 9.2 E3 Preregistration (2026-09-18T09:52:54+00:00)

- **Primary comparison:** Suricata-only (baseline) vs Full evidence-aware routing (proposed)  
- **Primary correlation window:** 60 seconds  
- **Sensitivity windows:** 10s, 30s, 120s (secondary)  
- **Primary statistical test:** Two-sided McNemar test with α \= 0.05 on per-event discordant pairs vs Suricata-only baseline  
- **Secondary effect estimates:** Bootstrap 95% confidence intervals for paired performance differences  
- **Negative results:** If McNemar p ≥ 0.05, reported as negative finding and retained

---

## 10\. Known Limitations & Next Steps

### Known Limitations

| Issue | Cause | Mitigation |
| :---- | :---- | :---- |
| TEST\_EXPLOIT host\_evidence | No server-side logs for nmap/nikto | PCAP \+ controller; target availability \= config only |
| DoS service impact | Application degradation not measured | CPU/memory confirms kernel load; no disruption claim |
| DEV\_DOS\_01 vmstat | 83 samples (longer window) | Mean diluted by pre/post-attack |

---

&nbsp;