# EIGRPForge Pro \- Architecture & Technical Specification

> **IETF RFC 7868 (Cisco's Enhanced Interior Gateway Routing Protocol) & DUAL (Diffusing Update Algorithm) Architectural Specification**

---

## 1\. Executive Summary & Protocol Overview

The **Enhanced Interior Gateway Routing Protocol (EIGRP / IETF RFC 7868\)** is an advanced distance-vector routing protocol designed to deliver the rapid convergence of link-state protocols (like OSPF and IS-IS) with the scalability, simplicity, and low memory overhead of distance-vector algorithms.

Unlike link-state protocols that flood the entire topology graph and require CPU-intensive Dijkstra Shortest Path First (SPF) recalculations upon any network change, EIGRP relies on the mathematically proven **Diffusing Update Algorithm (DUAL)**, designed by Dr. J.J. Garcia-Luna-Aceves. DUAL guarantees loop-free routing at every single instant, even during transient topology changes.

\+-----------------------------------------------------------------------------------------+

|                                EIGRP ARCHITECTURAL ADVANTAGES                            |

\+--------------------------+---------------------------------------+----------------------+

| Feature                  | Mechanism                             | Operational Impact   |

\+--------------------------+---------------------------------------+----------------------+

| Instant Convergence      | Pre-computed Feasible Successors      | 0 ms sub-second      |

|                          | in topology table (\$AD \< FD\$).        | failover upon cut.   |

\+--------------------------+---------------------------------------+----------------------+

| Unequal-Cost Multipath   | Variance multiplier allows balancing  | Optimizes asymmetric |

|                          | across verified Feasible Successors.  | WAN bandwidth.       |

\+--------------------------+---------------------------------------+----------------------+

| Bounded Routing Queries  | EIGRP Stub mode halts query           | Prevents WAN-wide    |

|                          | propagation to branch routers.        | SIA outages.         |

\+--------------------------+---------------------------------------+----------------------+

| 64-bit Wide Metrics      | Measures bandwidth in picoseconds     | Prevents metric      |

|                          | with a 65,536 scaling factor.         | saturation on \>=10G. |

\+--------------------------+---------------------------------------+----------------------+

| Modern Crypto Security   | RFC 7868 Section 6 HMAC-SHA-256       | Thwarts rogue route  |

|                          | authentication TLVs.                  | injections.          |

\+--------------------------+---------------------------------------+----------------------+

---

## 2\. RFC 7868 Packet Wireframe & Header Anatomy

EIGRP operates directly over Layer 3 using **IP Protocol 88**. Multicast packets are addressed to `224.0.0.10` (IPv4) or `FF02::A` (IPv6).

Every EIGRP packet begins with a **20-octet fixed header**, followed by one or more Type-Length-Value (TLV) structures:

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|    Version    |    Opcode     |          Checksum             |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                             Flags                             |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                        Sequence Number                        |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                      Acknowledgment Number                    |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|   Virtual Router ID (VRID)    | Autonomous System Number(ASN) |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|  Type-Length-Value (TLV) Triples ...

\+-+-+-+-+-+-+-+-+-+-+-+-+-

### 2.1 Header Fields

- **Version (8 bits)**: Set to `2`.  
- **Opcode (8 bits)**:  
  - `1`: `Update` (Carries reachable routes).  
  - `3`: `Query` (Sent when a route loses its Successor and has no Feasible Successor).  
  - `4`: `Reply` (Sent in response to a Query).  
  - `5`: `Hello` (Discovers and maintains neighbor adjacencies). When sequence number is 0, functions as a Hello; when sequence number is non-zero, functions as an `ACK`.  
  - `10`: `SIA-Query` (Stuck-in-Active Query to probe neighbor health before tearing down adjacencies).  
  - `11`: `SIA-Reply` (Confirms router is still actively waiting for downstream queries).  
- **Checksum (16 bits)**: Standard RFC 1071 internet checksum over the entire EIGRP packet.  
- **Flags (32 bits)**:  
  - `0x00000001` (`INIT`): First packet sent during neighbor establishment.  
  - `0x00000002` (`CR`): Conditionally Received flag.  
  - `0x00000004` (`RESTART`): Graceful restart active.  
- **Sequence Number (32 bits)**: Sequence counter for reliable RTP transmission.  
- **Acknowledgment Number (32 bits)**: Sequence number being acknowledged.  
- **VRID (16 bits)**: Virtual Router ID (usually 0).  
- **ASN (16 bits)**: Autonomous System Number (1–65535).

---

## 3\. The DUAL Finite State Machine & Feasibility Condition

DUAL tracks three core distance metrics for every known destination prefix:

1. **Feasible Distance (FD)**: The lowest calculated metric to reach the destination since the route last transitioned from Active to Passive state.  
2. **Computed Distance (CD)**: The metric calculated through a specific neighbor (\$CD \= \\text{Metric}\_{\\text{local\_link}} \+ AD\$).  
3. **Advertised Distance / Reported Distance (AD)**: The metric reported by the neighboring router for that destination.

### 3.1 The Feasibility Condition (FC)

A neighboring router is declared a **Feasible Successor (FS)** if and only if its Advertised Distance is strictly less than the primary path's Feasible Distance: \$\$AD \< FD\_{\\text{best}}\$\$

       \[ Source Router \]

         /           \\

   Link Cost: 2560    Link Cost: 3840

       /               \\

   \[ Router A \]     \[ Router B \]

   (Successor)      (Candidate)

        \\               /

     AD: 25600       AD: 26880

          \\           /

        \[ Destination \]

- **Path through Router A**:  
  - \$AD \= 25,600\$  
  - \$\\text{Calculated } FD \= 25,600 \+ 2,560 \= 28,160\$ (Lowest metric \$\\rightarrow\$ **Successor**).  
  - Current \$FD\_{\\text{best}} \= 28,160\$.  
- **Path through Router B**:  
  - \$AD \= 26,880\$  
  - \$\\text{Calculated } FD \= 26,880 \+ 3,840 \= 30,720\$.  
  - Feasibility Check: Is \$AD (26,880) \< FD\_{\\text{best}} (28,160)\$? **YES\!**  
  - **Verdict**: Router B is a verified **Feasible Successor**. If Router A fails, Router B is immediately installed into the RIB with **0 ms failover delay**.

### 3.2 What Happens When FC Fails (\$AD \\ge FD\$)?

If Router B's AD had been \$29,000\$, \$29,000 \\ge 28,160\$. Installing Router B without checking could cause an infinite routing loop (e.g., if Router B was routing back through the Source). When Router A fails and no FS exists:

1. Route state transitions from `PASSIVE` to `ACTIVE`.  
2. Router floods `EIGRP Query` packets to all neighbors.  
3. Neighbors query their downstream routers until a boundary or alternative path is found.  
4. **Stuck-in-Active (SIA)** hazard: If any neighbor fails to reply within 180 seconds, EIGRP tears down the adjacency, dropping all routes across that link.

---

## 4\. Unequal-Cost Multipath (UCMP) via Variance

EIGRP is the only interior gateway protocol capable of unequal-cost multipath load balancing using the `variance` multiplier (\$V \\in \[1..128\]\$).

A path is eligible for UCMP installation if and only if:

1. It is a verified **Feasible Successor** (\$AD \< FD\_{\\text{best}}\$).  
2. Its calculated metric is less than or equal to the variance threshold: \$\$FD\_{\\text{candidate}} \\le V \\times FD\_{\\text{best}}\$\$

Traffic is automatically load-balanced across both links proportionally to their inverse metrics\!

---

## 5\. Metric Calculations: Classic vs RFC 7868 Wide Metrics

### 5.1 Classic 32-bit Metric

\$\$\\text{Metric} \= 256 \\times \\left( K\_1 \\times \\frac{10^7}{\\text{Bandwidth}*{\\min}} \+ K\_3 \\times \\frac{\\text{Delay}*{\\text{sum}}}{10} \\right)\$\$ *(Assuming default \$K\_1 \= 1, K\_2 \= 0, K\_3 \= 1, K\_4 \= 0, K\_5 \= 0\$)*

On 10 Gbps and faster links, \$\\frac{10^7}{10,000,000} \= 1\$, causing all high-speed interfaces (10G, 40G, 100G) to have identical costs.

### 5.2 RFC 7868 64-bit Wide Metrics

Wide metrics use a \$65,536\$ scaling factor and measure throughput in picoseconds: \$\$\\text{Throughput} \= \\frac{10^{14}}{\\text{Bandwidth in bps}}\$\$ \$\$\\text{Latency} \= \\frac{\\text{Delay in picoseconds}}{100}\$\$ \$\$\\text{Metric}\_{\\text{wide}} \= 65,536 \\times (K\_1 \\times \\text{Throughput} \+ K\_3 \\times \\text{Latency})\$\$ This scales seamlessly from 1 Mbps up to Terabits per second without metric compression or truncation.

---

## 6\. 10-Point Zero-Trust Interior Routing (EIGRP) Audit Framework

| Control ID | Evaluation Domain | Weight | Standards Baseline |
| :---- | :---- | :---: | :---- |
| **EGR-SEC-01** | RFC 7868 Cryptographic Authentication | 15 pts | Mandatory HMAC-SHA-256 key-chain (ban cleartext/MD5). |
| **EGR-SEC-02** | DUAL Feasibility Condition (\$AD \< FD\$) | 12 pts | Verified Feasible Successors; 0 ms loop-free failover. |
| **EGR-SEC-03** | EIGRP Stub Routing on Branch/Access Nodes | 12 pts | `eigrp stub connected summary` halts WAN query diffusion. |
| **EGR-SEC-04** | Passive-Interface Default Policy | 10 pts | Suppress Hellos on user ports; prevent rogue peering. |
| **EGR-SEC-05** | Sub-Second Convergence (BFD / Timers) | 10 pts | Sub-50ms hardware fault detection via BFD. |
| **EGR-SEC-06** | Hierarchical EIGRP Named Mode | 9 pts | Multi-AF `router eigrp <NAME>` with granular AF scopes. |
| **EGR-SEC-07** | RFC 7868 64-bit Wide Metrics | 9 pts | Scale factor 65,536 active for \$\\ge 10\\text{G}\$ interfaces. |
| **EGR-SEC-08** | Calibrated Variance Multiplier | 8 pts | UCMP active only across verified Feasible Successors. |
| **EGR-SEC-09** | CoPP & Multicast Control Plane Protection | 8 pts | IP protocol 88 traffic policed at Route Processor. |
| **EGR-SEC-10** | Route Summarization & Prefix Boundaries | 7 pts | Inter-area aggregation minimizes query storm depth. |

