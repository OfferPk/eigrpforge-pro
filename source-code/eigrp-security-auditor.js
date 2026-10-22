/**
 * EIGRPForge Pro - 10-Point Zero-Trust Interior Routing (EIGRP) Security & DUAL Resiliency Auditor
 * 
 * Implements a rigorous 100-point security rubric evaluating:
 * - RFC 7868 HMAC-SHA-256 Authentication
 * - DUAL Feasibility Condition ($AD < FD$) & Loop Prevention
 * - EIGRP Stub Routing (SIA Mitigation)
 * - Passive-Interface Defaulting
 * - Sub-Second BFD Convergence
 * - Modern Hierarchical Named Mode
 * - 64-bit Wide Metrics
 * - Calibrated Variance UCMP
 * - CoPP & Multicast TTL Security
 * - Route Summarization
 * 
 * Dual environment: Browser Window & Node.js CommonJS
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.EIGRPSecurityAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function auditConfiguration(config) {
    const findings = [];
    let totalScore = 0;

    // Check 1: RFC 7868 HMAC-SHA-256 Cryptographic Authentication (15 pts)
    const authType = (config.authType || 'NONE').toUpperCase();
    if (authType === 'HMAC-SHA-256' || authType === 'SHA256') {
      totalScore += 15;
      findings.push({
        id: 'EGR-SEC-01',
        title: 'RFC 7868 HMAC-SHA-256 Cryptographic Authentication Enforced',
        score: 15,
        maxScore: 15,
        status: 'PASS',
        description: 'Authentication TLV 0x0002 uses HMAC-SHA-256 key-chain. Immune to rogue route injection and packet tampering.'
      });
    } else if (authType === 'MD5') {
      totalScore += 6;
      findings.push({
        id: 'EGR-SEC-01',
        title: 'Legacy MD5 Authentication in Use',
        score: 6,
        maxScore: 15,
        status: 'WARN',
        description: 'MD5 is vulnerable to collision attacks and violates modern cryptographic standards (NIST SP 800-131A). Upgrade to HMAC-SHA-256.'
      });
    } else if (authType === 'CLEARTEXT') {
      totalScore += 2;
      findings.push({
        id: 'EGR-SEC-01',
        title: 'Cleartext Authentication Detected',
        score: 2,
        maxScore: 15,
        status: 'FAIL',
        description: 'Cleartext keys can be passively sniffed from IP protocol 88 frames on broadcast segments.'
      });
    } else {
      findings.push({
        id: 'EGR-SEC-01',
        title: 'VULNERABLE: Unauthenticated EIGRP Peering',
        score: 0,
        maxScore: 15,
        status: 'FAIL',
        description: 'No authentication configured. Any host on the local segment can inject forged EIGRP Updates, blackholing subnets.'
      });
    }

    // Check 2: Feasible Successor Verification & Loop Prevention (12 pts)
    const backupSatisfiesFC = !!config.backupSatisfiesFC;
    if (backupSatisfiesFC) {
      totalScore += 12;
      findings.push({
        id: 'EGR-SEC-02',
        title: 'DUAL Feasibility Condition Satisfied (AD < FD)',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'Backup paths satisfy AD < FD, guaranteeing instant zero-millisecond convergence without routing loops.'
      });
    } else {
      findings.push({
        id: 'EGR-SEC-02',
        title: 'Feasibility Condition Violated (AD >= FD) or Missing Backup Path',
        score: 0,
        maxScore: 12,
        status: 'FAIL',
        description: 'Backup paths violate AD < FD. In the event of primary link loss, route enters ACTIVE state and triggers query storms.'
      });
    }

    // Check 3: EIGRP Stub Routing on Access & Branch Nodes (12 pts)
    const isStubConfigured = !!config.isStubConfigured;
    if (isStubConfigured) {
      totalScore += 12;
      findings.push({
        id: 'EGR-SEC-03',
        title: 'EIGRP Stub Routing Active on Branch/Access Nodes',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'Configured with eigrp stub connected summary. Prevents WAN query flooding and halts Stuck-in-Active (SIA) outages.'
      });
    } else if (config.isCoreRouter) {
      totalScore += 12;
      findings.push({
        id: 'EGR-SEC-03',
        title: 'Transit Core Node (Stub Not Applicable)',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'Router is an enterprise transit core node expected to propagate routing queries.'
      });
    } else {
      findings.push({
        id: 'EGR-SEC-03',
        title: 'HAZARD: Missing EIGRP Stub on Non-Transit Router',
        score: 0,
        maxScore: 12,
        status: 'FAIL',
        description: 'Branch or leaf router is queried during upstream route flaps, risking transit traffic redirection and SIA neighbor resets.'
      });
    }

    // Check 4: Passive-Interface Default on User/Access Subnets (10 pts)
    const passiveDefault = !!config.passiveDefault;
    if (passiveDefault) {
      totalScore += 10;
      findings.push({
        id: 'EGR-SEC-04',
        title: 'Passive-Interface Default Policy Enforced',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'All interface subnets are passive by default; only explicitly configured router-to-router links emit Hellos.'
      });
    } else {
      totalScore += 3;
      findings.push({
        id: 'EGR-SEC-04',
        title: 'Unrestricted EIGRP Hellos on Edge Ports',
        score: 3,
        maxScore: 10,
        status: 'FAIL',
        description: 'Hellos broadcasted onto user VLANs allow unauthorized endpoints to form EIGRP adjacencies.'
      });
    }

    // Check 5: Sub-Second Convergence with BFD / Tuned Timers (10 pts)
    const bfdEnabled = !!config.bfdEnabled;
    const tunedTimers = !!config.tunedTimers;
    if (bfdEnabled) {
      totalScore += 10;
      findings.push({
        id: 'EGR-SEC-05',
        title: 'Hardware BFD (Bidirectional Forwarding Detection) Active',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Sub-50ms fault detection enabled via BFD. Tearing down dead adjacencies before packet loss escalates.'
      });
    } else if (tunedTimers) {
      totalScore += 6;
      findings.push({
        id: 'EGR-SEC-05',
        title: 'Fast Hello/Hold Timers (1s/3s) Configured',
        score: 6,
        maxScore: 10,
        status: 'PASS',
        description: 'Timers tuned down from default 5s/15s to 1s/3s, but lacks hardware ASIC offload.'
      });
    } else {
      totalScore += 2;
      findings.push({
        id: 'EGR-SEC-05',
        title: 'Default 15-Second Hold Timer (Slow Convergence)',
        score: 2,
        maxScore: 10,
        status: 'WARN',
        description: 'Physical link cuts take up to 15 seconds to trigger DUAL recalculation, dropping voice and critical session traffic.'
      });
    }

    // Check 6: Modern EIGRP Named Mode (Multi-AF) Deployment (9 pts)
    const namedMode = !!config.namedMode;
    if (namedMode) {
      totalScore += 9;
      findings.push({
        id: 'EGR-SEC-06',
        title: 'Hierarchical EIGRP Named Mode Active',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Configured under router eigrp <NAME> with unified IPv4/IPv6 address-family hierarchy and granular per-AF controls.'
      });
    } else {
      totalScore += 4;
      findings.push({
        id: 'EGR-SEC-06',
        title: 'Legacy Autonomous System Number (Classic Mode) in Use',
        score: 4,
        maxScore: 9,
        status: 'WARN',
        description: 'Classic mode scatters authentication and timer configurations across interface and global scopes.'
      });
    }

    // Check 7: Wide Metrics (64-bit) for High-Speed Interfaces (9 pts)
    const wideMetrics = !!config.wideMetrics;
    if (wideMetrics) {
      totalScore += 9;
      findings.push({
        id: 'EGR-SEC-07',
        title: 'RFC 7868 64-bit Wide Metrics Active',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Using 65,536 scale factor. Accurate metric differentiation across 10G, 40G, 100G, and 400G interfaces.'
      });
    } else {
      totalScore += 3;
      findings.push({
        id: 'EGR-SEC-07',
        title: 'Classic 32-bit Metrics (High-Speed Metric Saturation)',
        score: 3,
        maxScore: 9,
        status: 'WARN',
        description: 'Classic metrics cap out at 10 Gbps, treating 10G and 100G links identically and inducing ECMP polarization.'
      });
    }

    // Check 8: Calibrated Unequal-Cost Multipath (variance) Validation (8 pts)
    const variance = config.variance || 1;
    const hasUnsafeVariance = (variance > 1 && !backupSatisfiesFC);
    if (variance > 1 && backupSatisfiesFC) {
      totalScore += 8;
      findings.push({
        id: 'EGR-SEC-08',
        title: `Calibrated Unequal-Cost Multipath Active (Variance ${variance})`,
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: `Variance multiplier ${variance} is backed by verified Feasible Successors, balancing load without routing loops.`
      });
    } else if (variance === 1) {
      totalScore += 8;
      findings.push({
        id: 'EGR-SEC-08',
        title: 'Deterministic Equal-Cost Multipath (Variance 1)',
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: 'Standard ECMP mode active. Prevents packet jitter across asymmetric bandwidth links.'
      });
    } else if (hasUnsafeVariance) {
      findings.push({
        id: 'EGR-SEC-08',
        title: `HAZARD: Ineffective / Unsafe Variance Multiplier (${variance})`,
        score: 0,
        maxScore: 8,
        status: 'FAIL',
        description: 'Variance multiplier is set, but candidate paths FAIL the Feasibility Condition. EIGRP will not install them in the RIB.'
      });
    }

    // Check 9: Control Plane Policing (CoPP) & Multicast Protection (8 pts)
    const coppActive = !!config.coppActive;
    if (coppActive) {
      totalScore += 8;
      findings.push({
        id: 'EGR-SEC-09',
        title: 'CoPP (Control Plane Policing) Rate Limiting Enforced',
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: 'IP Protocol 88 (EIGRP) multicast traffic to 224.0.0.10 is policed, preventing supervisor CPU exhaustion floods.'
      });
    } else {
      totalScore += 2;
      findings.push({
        id: 'EGR-SEC-09',
        title: 'Unpoliced EIGRP Control Plane (CoPP Missing)',
        score: 2,
        maxScore: 8,
        status: 'WARN',
        description: 'Route Processor CPU vulnerable to denial-of-service from high-rate spoofed EIGRP Hello/Query packets.'
      });
    }

    // Check 10: Route Summarization & Prefix Filtering at Boundaries (7 pts)
    const summarizationActive = !!config.summarizationActive;
    if (summarizationActive) {
      totalScore += 7;
      findings.push({
        id: 'EGR-SEC-10',
        title: 'Route Summarization & Boundary Filtering Enforced',
        score: 7,
        maxScore: 7,
        status: 'PASS',
        description: 'Inter-site prefixes are summarized, constraining query diffusion boundaries and reducing routing table churn.'
      });
    } else {
      totalScore += 2;
      findings.push({
        id: 'EGR-SEC-10',
        title: 'Unfiltered Flat Routing Table',
        score: 2,
        maxScore: 7,
        status: 'WARN',
        description: 'Specific /24 and /32 routes leak throughout the network, amplifying query depth when leaf interfaces flap.'
      });
    }

    // Derive letter grade
    let grade = 'F';
    if (totalScore >= 90) grade = 'A+';
    else if (totalScore >= 80) grade = 'A';
    else if (totalScore >= 70) grade = 'B';
    else if (totalScore >= 60) grade = 'C';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      findings: findings
    };
  }

  return {
    auditConfiguration: auditConfiguration
  };
});
