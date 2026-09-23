# **E1: Local Session-Separated Deployment Corpus**

**Hybrid-NIDS Experimental Work Package Report**

## **Executive Summary**

This report documents Work Package **E1: Local Session-Separated Deployment Corpus** for the Hybrid-NIDS architecture (Suricata \+ Random Forest). E1 provides a **controlled laboratory** traffic corpus for E2 (calibration) and E3 (comparative evaluation).

**32 1,157 11.1M 407,905** Sessions PCAP MiB EVE Lines Flows

- **30 active sessions** (15 Dev \+ 15 Test) across 5 scenarios \+ **2 excluded**

- **Controlled lab topology:** single attacker/target pair on isolated /24 subnet

- **Scenario-appropriate independent corroboration** for all 15 Test events (AC-12)

- **Full provenance:** 47-field manifest, 166 evidence rows, 198 SHA-256 checksums

- **25/25 validation checks passed** (including AC-13 post-clock-correction)

- **E3 preregistered:** McNemar (exploratory, n=15), Bootstrap CI (descriptive)

- **Known limitation:** DoS flows dominate (\~96%); normal traffic is controlled HTTP

- **Clock correction:** 9 Test sessions corrected for Kali attacker clock offset (+681–682 s)


## **1\. Goal & Methodology**

E1 constructs a controlled, session-separated laboratory traffic corpus. Four objectives:

- **G1 — Scenario Coverage:** Five traffic classes, \>=3 sessions per partition.

- **G2 — Partition Integrity:** All Dev complete \+ config frozen before any Test.

- **G3 — Reproducibility:** Complete provenance chain per session.

- **G4 — Ground Truth Traceability:** Each session has one primary ground-truth record.

### **Evidence Types per Scenario**

| Scenario | Tool | Controller | Independent Evidence | Reason Code |
| :---- | :---- | :---- | :---- | :---- |
| NORMAL | curl | HTTP responses | http\_server / PCAP HTTP | CONFIRMED\_HO ST |
| SCAN | nmap \-sT | Port scan output | PCAP SYN/RST \+ scan\_conn\_log | CONFIRMED\_PCA P |
| BRUTE | hydra | Login attempts | auth.log | CONFIRMED\_HO ST |
| DOS | hping3 | SYN flood count | PCAP volume \+ vmstat CPU | CONFIRMED\_PCA P |
| EXPLOIT | nmap NSE/nikto | Script output | PCAP \+ tool output | CONFIRMED\_PCA P |

*SCAN: PCAP connection patterns (SYN/RST) are the independent corroboration. Nikto: target availability corroborates service config, not request processing.*

### **Model Lineage**

The RF-21 model was trained on **UNSW-NB15 compatible flow records** (2,030,129 train / 508,039 test records; F1=0.9701 at threshold 0.8528). *RF-21 narrows the schema-gap discussion but does not prove live PCAP deployment performance.*

### **Permission & Ethics**

All traffic generation, capture, and logging were conducted on laboratory systems under institutional authorization. No third-party or production traffic was captured.


### **1.1 Corpus Scope & Known Limitations**

This is a **controlled laboratory corpus** , not representative of operational traffic at HCM City College of Transport.

| Constraint | Detail |
| :---- | :---- |
| Topology | Single attacker (192.168.10.101), single target (192.168.10.146), one /24 subnet |
| Normal traffic | Scripted HTTP (curl GET, 30 requests/session) — not institutional diversity |
| Flow dominance | DoS SYN-flood contributes \~96.3% of all Dev flows |
| Attack diversity | Limited tool diversity; most scenarios use a single tool, while Exploit includes nmap NSE and Nikto |
| Host count | 2 hosts — no multi-host/multi-VLAN interactions |

### **Flow Distribution per Scenario (Dev)**

| Scenario | Sessions | Flows | Percentage |
| :---- | :---- | :---- | :---- |
| normal | 3 | 54 | 0.0% |
| scan | 3 | 3,219 | 1.6% |
| brute\_force | 3 | 32 | 0.0% |
| dos | 3 | 196,612 | 96.3% |
| exploit | 3 | 4,309 | 2.1% |
| TOTAL | 15 | 204,226 | 100.0% |

### **1.2 Environment**

- **NIDS host:** soc-nids-monitor (192.168.10.146), Ubuntu 22.04.2 LTS

- **Attacker:** kali (192.168.10.101)

- **Capture:** ens18, BPF: net 192.168.10.0/24

- **Model:** RF-21 Schema-Gap (UNSW-NB15 compatible, 21 features)

- **Suricata:** 8.0.4, offline on session PCAP

- **NFStream:** 6.6.0, Python 3.10.12, scikit-learn 1.6.1

### **1.3 Clock Correction Disclosure**

Nine Test sessions (SCAN×3, BRUTE×3, DOS×3) executed attack tools on the Kali attacker via SSH. The Kali system clock was **\+681–682 seconds ahead** of the NIDS host clock (which provides authoritative PCAP kernel timestamps). Controller log timestamps for these 9 sessions were mechanically corrected to align with PCAP first/last packet times. The correction is documented in **E1\_CLOCK\_CORRECTION\_LOG.txt** . All integrity and validation checks were rerun after this correction.


## **2\. Table IX — Corpus Summary**

| Partitio n | Scenario | Sessio ns | PCAP MiB | EVE Lines | Flows | GT Conf | GT Excl |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| DEV | NORMAL | 3 | 0.1 | 1,054 | 54 | 3 | 0 |
| DEV | SCAN | 3 | 0.7 | 6,266 | 3,219 | 3 | 0 |
| DEV | BRUTE\_FOR CE | 3 | 0.2 | 1,246 | 32 | 3 | 0 |
| DEV | DOS | 3 | 545.4 | 5,514,302 | 196,612 | 3 | 0 |
| DEV | EXPLOIT | 5 | 41.1 | 94,434 | 4,311 | 3 | 2 |
| **DEV** | **SUBTOTAL** | **17** | **587.6** | **5,617,302** | **204,228** | **15** | **2** |
| TEST | NORMAL | 3 | 0.1 | 1,116 | 93 | 3 | 0 |
| TEST | SCAN | 3 | 0.4 | 6,104 | 2,543 | 3 | 0 |
| TEST | BRUTE\_FOR CE | 3 | 0.1 | 667 | 18 | 3 | 0 |
| TEST | DOS | 3 | 527.9 | 5,336,942 | 196,611 | 3 | 0 |
| TEST | EXPLOIT | 3 | 41.1 | 121,866 | 4,412 | 3 | 0 |
| **TEST** | **SUBTOTAL** | **15** | **569.7** | **5,466,695** | **203,677** | **15** | **0** |
|  | **TOTAL** | **32** | **1,157** | **11,083,997** | **407,905** | **30** | **2** |

*Sizes in MiB (binary). DoS SYN-flood dominates flow counts (\~96%).*


## **3\. Development Sessions**

17 Dev sessions. 15 active \+ 2 excluded.

### **3.1 Normal**

| Session | Pkts | EVE | Flows |
| :---- | :---- | :---- | :---- |
| DEV\_NORMAL\_01 | 471 | 351 | 20 |
| DEV\_NORMAL\_02 | 299 | 351 | 17 |
| DEV\_NORMAL\_03 | 297 | 352 | 17 |

### **3.2 Scan**

| Session | Pkts | EVE | Flows |
| :---- | :---- | :---- | :---- |
| DEV\_SCAN\_01 | 2,547 | 2,109 | 1,073 |
| DEV\_SCAN\_02 | 2,536 | 2,100 | 1,073 |
| DEV\_SCAN\_03 | 2,550 | 2,057 | 1,073 |

### **3.3 Brute Force**

| Session | Pkts | EVE | Flows |
| :---- | :---- | :---- | :---- |
| DEV\_BRUTE\_01 | 619 | 612 | 17 |
| DEV\_BRUTE\_02 | 320 | 327 | 8 |
| DEV\_BRUTE\_03 | 297 | 307 | 7 |


### **3.4 DoS**

| Session | Packets | PCAP MiB | EVE | Flows |
| :---- | :---- | :---- | :---- | :---- |
| DEV\_DOS\_01 | 2,878,757 | 186.1 | 1,943,252 | 65,538 |
| DEV\_DOS\_02 | 2,524,409 | 163.3 | 1,703,995 | 65,537 |
| DEV\_DOS\_03 | 2,766,599 | 178.9 | 1,867,055 | 65,537 |

### **3.5 Exploit**

| Session | Tool | Packets | EVE | Status |
| :---- | :---- | :---- | :---- | :---- |
| DEV\_EXPLOIT\_01 | Metasploit | 33 | — | EXCLUDE D |
| DEV\_EXPLOIT\_01b | nmap NSE | 25,988 | 26,681 | complete |
| DEV\_EXPLOIT\_02 | nmap NSE | 20,890 | 23,697 | complete |
| DEV\_EXPLOIT\_03 | nmap NSE | 24 | — | EXCLUDE D |
| DEV\_EXPLOIT\_03b | nikto | 70,848 | 43,997 | complete |


## **4\. Test Sessions**

15 Test sessions, all complete. GT timestamps corrected for Kali clock offset (+681–682 s, see §1.3).

### **4.1–4.3 Normal / Scan / Brute**

| Session | Scenari o | Pkts | EVE | Flow s | Host Evidence |
| :---- | :---- | :---- | :---- | :---- | :---- |
| TEST\_NORMAL\_ 01 | normal | 333 | 372 | 31 | 46 bytes |
| TEST\_NORMAL\_ 02 | normal | 333 | 370 | 31 | 65 lines |
| TEST\_NORMAL\_ 03 | normal | 336 | 374 | 31 | 65 lines |
| TEST\_SCAN\_01 | scan | 1,729 | 2,028 | 845 | scan\_conn\_log |
| TEST\_SCAN\_02 | scan | 1,715 | 2,009 | 837 | scan\_conn\_log |
| TEST\_SCAN\_03 | scan | 1,760 | 2,067 | 861 | scan\_conn\_log |
| TEST\_BRUTE\_01 | brute | 207 | 217 | 6 | 20 auth.log |
| TEST\_BRUTE\_02 | brute | 216 | 226 | 6 | 20 auth.log |
| TEST\_BRUTE\_03 | brute | 214 | 224 | 6 | 20 auth.log |


### **4.4 DoS**

| Session | Packets | PCAP MiB | EVE | Flows |
| :---- | :---- | :---- | :---- | :---- |
| TEST\_DOS\_01 | 2,659,023 | 177.9 | 1,794,501 | 65,537 |
| TEST\_DOS\_02 | 2,648,088 | 177.3 | 1,786,962 | 65,537 |
| TEST\_DOS\_03 | 2,600,786 | 174.1 | 1,755,479 | 65,537 |

### **4.5 Exploit**

| Session | Tool | Packets | EVE | Flows |
| :---- | :---- | :---- | :---- | :---- |
| TEST\_EXPLOIT\_01 | nmap NSE | 23,669 | 26,785 | 2,319 |
| TEST\_EXPLOIT\_02 | nmap NSE | 20,747 | 23,536 | 2,072 |
| TEST\_EXPLOIT\_03 | nikto | 71,525 | 71,545 | 21 |


## **5\. Ground Truth & Reason Codes**

Each session has one **primary ground-truth record** (23 fields). All Test events have **scenario-appropriate independent corroboration** .

### **Reason Codes (Frozen)**

| Reason Code | Status | \# | Definition |
| :---- | :---- | :---- | :---- |
| GT\_CONFIRMED\_CONTROLLER\_H OST | confirmed | 12 | Controller \+ host app log |
| GT\_CONFIRMED\_CONTROLLER\_P CAP | confirmed | 18 | Controller \+ PCAP analysis |
| GT\_EXCLUDED\_ABORTED | excluded | 1 | Session aborted (tool failure) |
| GT\_EXCLUDED\_NO\_TARGET\_MAT CH | excluded | 1 | No target interaction detected |
| GT\_UNCERTAIN\_NO\_HOST\_CORR. | uncertain | 0 | Reserved |

### **Corroboration Types**

| Corroboration Type | \# | Scenarios |
| :---- | :---- | :---- |
| controller \+ host application log | 12 | NORMAL, BRUTE |
| controller \+ PCAP traffic volume | 6 | DOS |
| controller \+ PCAP connection patterns | 6 | SCAN |
| controller \+ tool output \+ PCAP | 6 | EXPLOIT |
| none (insufficient) | 2 | Excluded |


## **6\. Provenance Chain**

Three-tier: **Session Manifest** (47 fields) → **Event Manifest** (166 rows) → **SHA-256 Manifest** (198 artifacts). All integrity and validation checks were rerun after the v3.4 clock correction and consistency updates.

## **7\. Hardware Utilization**

| Scenario | usr% | sys% | idle% | Free Mem | Note |
| :---- | :---- | :---- | :---- | :---- | :---- |
| NORMAL | 2.7% | 1.1% | 96.0% | 473 MiB | Baseline |
| SCAN | 3.4% | 1.7% | 94.7% | 605 MiB | Minimal |
| BRUTE | 2.9% | 1.6% | 95.4% | 544 MiB | Minimal |
| DOS | 7.9% | 24.0% | 66.8% | 496 MiB | Heavy kernel |
| EXPLOIT | 4.2% | 2.9% | 92.3% | 669 MiB | Moderate |


## **8\. Validation & Acceptance Criteria**

| ID | Criterion | Res ult | Detail |
| :---- | :---- | :---- | :---- |
| AC-1 | Scenario Completeness | PAS S | ≥3 per scenario per partition |
| AC-2 | Partition Integrity | PAS S | Dev 09:43 \< Test 09:56; 0 overlap |
| AC-3 | Config Freeze | PAS S | Freeze 09:49 before Test |
| AC-4 | GT Coverage | PAS S | 32/32; reason\_codes valid |
| AC-5 | Evidence Chain | PAS S | Min 5 rows/event |
| AC-6 | Integrity Manifest | PAS S | 198 artifacts; 4 empty documented |
| AC-7 | Zero Drops | PAS S | All drops \= 0 |
| AC-8 | Hardware Metrics | PAS S | 32/32 vmstat |
| AC-9 | Excluded Handling | PAS S | 2 excluded: 1 aborted, 1 no-target |
| AC-1 0 | Chronological Order | PAS S | Monotonic |
| AC-1 1 | E3 Preregistration | PAS S | File exists |
| AC-1 2 | Test GT Sufficiency | PAS S | 15/15 confirmed \+ indep. corr. |
| AC-1 3 | GT Within Capture | PAS S | 9 corrected; all 15 within PCAP |

### **ALL 25/25 CHECKS PASSED**


## **9\. Configuration Freeze & E3 Preregistration**

### **9.1 Configuration Freeze (2026-09-18T09:49:49+00:00)**

| Component | Version / SHA-256 |
| :---- | :---- |
| Python | 3.10.12 |
| scikit-learn | 1.6.1 |
| NFStream | 6.6.0 |
| Suricata | 8.0.4 RELEASE |
| RF-21 Model | UNSW-NB15 compatible; SHA e3acec66... |
| Feature schema | SHA c244f777... |
| Suricata rules | SHA 210221d8... (44.8 MiB) |

### **9.2 E3 Preregistration (2026-09-18T09:52:54+00:00)**

- **Primary comparison:** Suricata-only vs Full evidence-aware routing

- **Correlation window:** 60 s

- **Exploratory:** Two-sided McNemar, alpha=0.05, n=15

- **Secondary:** Bootstrap 95% CI (session-clustered)

- **Negative results:** If McNemar p ≥ 0.05, reported as negative finding


## **10\. Limitations & Next Steps**

| Limitation | Detail | Impact |
| :---- | :---- | :---- |
| Single attacker/target | 1 Kali, 1 NIDS, /24 subnet | No multi-hop/NAT/VLAN diversity |
| Controlled normal traffic | curl HTTP, 30 req/session | Not institutional diversity |
| DoS flow dominance | 96.3% of Dev flows are SYN-flood | Flow-level metrics skewed |
| Small Test sample | 15 independent events | McNemar exploratory; wide CIs |
| Lab vs production | Isolated segment, no background noise | External validity requires operational eval |
| Clock offset | Kali \+681–682 s; 9 sessions corrected | Documented in E1\_CLOCK\_CORRECTION\_LOG |
