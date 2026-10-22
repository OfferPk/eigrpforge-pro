/**
 * EIGRPForge Pro - Multi-Platform Configuration Synthesizer
 * 
 * Synthesizes production-hardened EIGRP stanzas for:
 * - Cisco IOS-XE Named Mode (Multi-AF)
 * - Cisco IOS Classic Mode
 * - Cisco NX-OS
 * - Linux FRRouting (FRR eigrpd)
 * - Prometheus Alertmanager Rules
 * 
 * Dual environment: Browser Window & Node.js CommonJS
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.EIGRPConfigSynthesizer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoNamedMode(config) {
    const instanceName = config.instanceName || 'PRO-ENTERPRISE-WAN';
    const asn = config.asn || 100;
    const authKey = config.sharedKey || 'E1grpS3cur3K3y2026!';
    const isStub = config.isStubConfigured !== false;
    const variance = config.variance || 1;
    const bfd = config.bfdEnabled !== false;

    return `! ==============================================================================
! Cisco IOS-XE Named Mode EIGRP Hardened Configuration (RFC 7868)
! Platform: Cisco Catalyst 8000 / 9000 / ASR 1000 running IOS-XE 17.x+
! ==============================================================================

! 1. Cryptographic Key-Chain Definition (RFC 7868 Section 6)
key chain KC-EIGRP-SECURE
 key 1
  key-string ${authKey}
  cryptographic-algorithm hmac-sha-256

! 2. Hierarchical Named Mode EIGRP Instance
router eigrp ${instanceName}
 ! IPv4 Address-Family Configuration
 address-family ipv4 unicast autonomous-system ${asn}
  ! Enforce Passive-Interface Defaulting on All Ports
  af-interface default
   passive-interface
  exit-af-interface

  ! Activate Routed Transit Uplinks (Un-passive & Secure)
  af-interface GigabitEthernet0/0/1
   no passive-interface
   authentication mode hmac-sha-256 KC-EIGRP-SECURE
   hello-interval 1
   hold-time 3
   ${bfd ? 'bfd' : '! bfd disabled'}
  exit-af-interface

  af-interface GigabitEthernet0/0/2
   no passive-interface
   authentication mode hmac-sha-256 KC-EIGRP-SECURE
   hello-interval 1
   hold-time 3
   ${bfd ? 'bfd' : '! bfd disabled'}
  exit-af-interface

  ! Topology & DUAL Settings
  topology base
   ${variance > 1 ? `variance ${variance}  ! Unequal-cost multipath load balancing` : 'variance 1   ! Deterministic ECMP'}
   auto-summary
  exit-af-topology

  ! Network Announcements
  network 10.100.0.0 0.0.255.255
  network 10.200.0.0 0.0.255.255

  ${isStub ? 'eigrp stub connected summary  ! Halt WAN query flooding & prevent SIA' : '! Transit Core Node: Stub disabled'}
 exit-address-family
!
! 3. Control Plane Policing (CoPP) Protection for EIGRP (IP Protocol 88)
ip access-list extended ACL-COPP-EIGRP
 permit eigrp any host 224.0.0.10
 permit eigrp any any
!
class-map match-all CM-COPP-EIGRP
 match access-group name ACL-COPP-EIGRP
!
policy-map PM-COPP-CONTROL-PLANE
 class CM-COPP-EIGRP
  police rate 100 pps burst 20 packets conform-action transmit exceed-action drop
!
control-plane
 service-policy input PM-COPP-CONTROL-PLANE
`;
  }

  function synthesizeCiscoClassicMode(config) {
    const asn = config.asn || 100;
    const authKey = config.sharedKey || 'E1grpS3cur3K3y2026!';
    const isStub = config.isStubConfigured !== false;
    const variance = config.variance || 1;

    return `! ==============================================================================
! Cisco IOS Classic Mode EIGRP Configuration
! Platform: Cisco ISR G2 / Legacy IOS 15.x
! ==============================================================================

key chain KC-EIGRP-CLASSIC
 key 1
  key-string ${authKey}
  cryptographic-algorithm md5

interface GigabitEthernet0/0
 ip address 10.100.0.1 255.255.255.0
 ip authentication mode eigrp ${asn} md5
 ip authentication key-chain eigrp ${asn} KC-EIGRP-CLASSIC
 ip hello-interval eigrp ${asn} 1
 ip hold-time eigrp ${asn} 3

router eigrp ${asn}
 passive-interface default
 no passive-interface GigabitEthernet0/0
 network 10.100.0.0 0.0.255.255
 ${variance > 1 ? `variance ${variance}` : '! variance 1'}
 ${isStub ? 'eigrp stub connected summary' : '! stub disabled'}
 no auto-summary
`;
  }

  function synthesizeCiscoNxos(config) {
    const asn = config.asn || 100;
    const authKey = config.sharedKey || 'E1grpS3cur3K3y2026!';
    const bfd = config.bfdEnabled !== false;

    return `! ==============================================================================
! Cisco Nexus NX-OS Data Center EIGRP Configuration
! Platform: Cisco Nexus 9300 / 9500 running NX-OS 9.x / 10.x
! ==============================================================================

feature eigrp
${bfd ? 'feature bfd' : ''}

key chain KC-NXOS-EIGRP
 key 1
  key-string ${authKey}
  cryptographic-algorithm hmac-sha-256

router eigrp ${asn}
 router-id 10.254.0.1
 passive-interface default

interface Ethernet1/1
 no switchport
 ip address 10.100.0.1/30
 ip router eigrp ${asn}
 no ip passive-interface eigrp ${asn}
 ip authentication mode eigrp ${asn} hmac-sha-256
 ip authentication key-chain eigrp ${asn} KC-NXOS-EIGRP
 ${bfd ? 'ip bfd' : ''}
 no shutdown
`;
  }

  function synthesizeLinuxFRR(config) {
    const asn = config.asn || 100;

    return `! ==============================================================================
! Linux FRRouting (FRR) eigrpd Configuration
! File: /etc/frr/eigrpd.conf
! ==============================================================================

frr version 8.x
frr defaults traditional
hostname host-eigrpd-01
log syslog informational

interface eth0
 ip eigrp hello-interval 1
 ip eigrp hold-time 3

router eigrp ${asn}
 eigrp router-id 10.254.0.1
 network 10.100.0.0/24
 network 10.200.0.0/24
 passive-interface default
 no passive-interface eth0
!
line vty
`;
  }

  function synthesizePrometheusAlerts(config) {
    const asn = config.asn || 100;

    return `# ==============================================================================
# Prometheus Alertmanager Rules for EIGRP Telemetry & Health
# File: /etc/prometheus/rules/eigrp_alerts.yml
# ==============================================================================

groups:
  - name: EIGRP_Routing_Alerts
    rules:
      - alert: EIGRPNeighborDown
        expr: cisco_eigrp_neighbor_state{asn="${asn}"} == 0
        for: 15s
        labels:
          severity: critical
          tier: networking
        annotations:
          summary: "EIGRP Neighbor Down on {{ $labels.instance }} (Peer {{ $labels.peer_ip }})"
          description: "EIGRP neighbor adjacency dropped. Link cut or authentication failure detected."

      - alert: EIGRPRcvSIAQuery
        expr: rate(cisco_eigrp_sia_queries_received_total{asn="${asn}"}[5m]) > 0
        for: 1m
        labels:
          severity: high
          tier: routing
        annotations:
          summary: "EIGRP Stuck-in-Active (SIA) Queries Received on {{ $labels.instance }}"
          description: "Router is receiving SIA queries. Possible downstream query loop or missing EIGRP stub configuration."

      - alert: EIGRPAuthFailureSpike
        expr: rate(cisco_eigrp_auth_failures_total{asn="${asn}"}[5m]) > 0.05
        for: 2m
        labels:
          severity: critical
          tier: security
        annotations:
          summary: "EIGRP Cryptographic Authentication Failures Detected on {{ $labels.instance }}"
          description: "High rate of EIGRP packets with invalid HMAC-SHA-256 or MD5 signatures. Rogue router or key mismatch."
`;
  }

  return {
    synthesizeCiscoNamedMode: synthesizeCiscoNamedMode,
    synthesizeCiscoClassicMode: synthesizeCiscoClassicMode,
    synthesizeCiscoNxos: synthesizeCiscoNxos,
    synthesizeLinuxFRR: synthesizeLinuxFRR,
    synthesizePrometheusAlerts: synthesizePrometheusAlerts
  };
});
