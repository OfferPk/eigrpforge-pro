# EIGRPForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for network engineers, infrastructure architects, and NetDevOps teams deploying Zero-Trust EIGRP & DUAL loop-free routing.**

---

## 1\. Quickstart: Web Application Studio

The **EIGRPForge Pro Web Studio** runs 100% client-side with zero external dependencies. Open `source-code/index.html` directly in any modern web browser:

\# Optional local web server

cd product\_120/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Security & Topology Presets**: Switch between:  
   - **Enterprise WAN Named Mode (Grade A+)**: Complete Zero-Trust EIGRP with RFC 7868 HMAC-SHA-256 key-chain, BFD, EIGRP Stub mode, and verified Feasible Successors.  
   - **Data Center Core Wide Metrics (Grade A+)**: High-speed core deployment with 64-bit wide metrics, unequal-cost multipath (variance 2), and transit core mode.  
   - **Vulnerable Classic Cleartext (Grade F)**: Insecure baseline exposing unauthenticated peering, missing stub mode, and failing DUAL loop hazards.  
2. **RFC 7868 EIGRP Parameters**: Configure Packet Opcode (Hello, Update, Query, Reply, SIA-Query), Autonomous System Number (ASN), Authentication Type (HMAC-SHA-256, MD5, Cleartext, None), and interface Bandwidth/Delay.  
3. **Live DUAL Feasibility & Variance Simulator**: Evaluates candidate paths against the Feasibility Condition (\$AD \< FD\$), rendering status badges (`SUCCESSOR`, `FEASIBLE_SUCCESSOR_BACKUP`, `FEASIBLE_SUCCESSOR_LOAD_BALANCED`, `FAIL_LOOP_RISK`).  
4. **10-Point Zero-Trust Scorecard**: Real-time compliance rating (0–100%, Grades A+ to F) with granular remediation instructions.  
5. **Wireshark Hex Dissector**: Byte-aligned hex dump with 1-click clipboard export and binary `.pcap` packet generation.  
6. **Multi-Platform Synthesizer**: Instant production configuration generation for Cisco IOS-XE Named Mode, Cisco Classic Mode, Cisco NX-OS, Linux FRRouting (eigrpd), and Prometheus alerting rules.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/eigrpforge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/eigrpforge-cli.py \--dissect

### 2.2 Calculating Classic 32-bit vs RFC 7868 64-bit Wide Metrics

\# Calculate metrics for 1 Gbps link with 100 microseconds delay

./build/eigrpforge-cli.py \--metric

### 2.3 Running DUAL Feasibility & Variance UCMP Analysis

\# Evaluates candidate paths against primary FD

./build/eigrpforge-cli.py \--dual

### 2.4 Running 10-Point Zero-Trust EIGRP Audits

\# Audit Enterprise WAN preset

./build/eigrpforge-cli.py \--preset build/presets/enterprise-wan-named-mode.json \--audit

\# Audit vulnerable legacy deployment

./build/eigrpforge-cli.py \--preset build/presets/vulnerable-classic-cleartext.json \--audit

### 2.5 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing network decoders or validating with Wireshark:

./build/eigrpforge-cli.py \--preset build/presets/enterprise-wan-named-mode.json \--pcap enterprise-eigrp.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-n \-r enterprise-eigrp.pcap

### 2.6 Automated CI/CD Pipeline Gating (`--strict`)

Integrate EIGRPForge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit EIGRP Routing Security & DUAL Compliance

  run: |

    python3 build/eigrpforge-cli.py \\

      \--preset build/presets/production-eigrp.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and loop-free verified. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or loop hazard detected. Pipeline halts.*

---

## 3\. Production Hardening & Configuration Guide

### 3.1 Cisco IOS-XE Named Mode (Multi-AF)

key chain KC-EIGRP-SECURE

 key 1

  key-string E1grpS3cur3K3y2026\!

  cryptographic-algorithm hmac-sha-256

router eigrp PRO-ENTERPRISE-WAN

 address-family ipv4 unicast autonomous-system 100

  af-interface default

   passive-interface

  exit-af-interface

  af-interface GigabitEthernet0/0/1

   no passive-interface

   authentication mode hmac-sha-256 KC-EIGRP-SECURE

   hello-interval 1

   hold-time 3

   bfd

  exit-af-interface

  topology base

   variance 1

  exit-af-topology

  network 10.100.0.0 0.0.255.255

  eigrp stub connected summary

 exit-address-family

---

## 4\. Troubleshooting & High-Impact Failure Modes

1. **Stuck-in-Active (SIA) Outages**:  
   - *Cause*: A lost query or slow neighbor on a flapping link fails to reply within 180 seconds, causing neighbor reset.  
   - *Resolution*: Apply `eigrp stub connected summary` on all branch routers to halt query propagation at the hub.  
2. **K-Value Mismatch Disconnect**:  
   - *Cause*: Routers with differing K-values (e.g., one setting K2=1 for load) will reject incoming Hellos.  
   - *Resolution*: Ensure all participating routers use standard default K-values (\$K\_1=1, K\_2=0, K\_3=1, K\_4=0, K\_5=0, K\_6=0\$).  
3. **Variance Configured but Alternate Link Remains Idle**:  
   - *Cause*: The alternate path violates the Feasibility Condition (\$AD \\ge FD\_{\\text{best}}\$). EIGRP strictly forbids installing non-feasible successors to prevent loops.  
   - *Resolution*: Adjust bandwidth/delay or check upstream metric so that \$AD \< FD\_{\\text{best}}\$.  
4. **Metric Saturation on 100G / 400G Links**:  
   - *Cause*: Classic 32-bit metrics treat all interfaces \$\\ge 10\\text{G}\$ with identical metric values.  
   - *Resolution*: Migrate to RFC 7868 64-bit wide metrics via EIGRP Named Mode.