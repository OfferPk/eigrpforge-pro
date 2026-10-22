/**
 * EIGRPForge Pro - RFC 7868 EIGRP Protocol & DUAL Feasibility Engine
 * 
 * Provides:
 * - RFC 7868 EIGRP Packet Wireframe Encoding & Checksum (Header + Parameter, Auth, Route TLVs)
 * - Classic 32-bit Metric & RFC 7868 64-bit Wide Metric Calculations
 * - DUAL Feasible Condition (AD < FD) & Unequal-Cost Multipath (Variance) Evaluation
 * - Wireshark-Style Hex Dump Dissector & Binary PCAP Buffer Generation
 * 
 * Dual environment: Browser Window & Node.js CommonJS
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.EIGRPProtocolEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Opcode Constants (RFC 7868 Section 5.1.1)
  const OPCODES = {
    1: 'Update',
    3: 'Query',
    4: 'Reply',
    5: 'Hello / Ack',
    10: 'SIA-Query',
    11: 'SIA-Reply'
  };

  // TLV Types (RFC 7868 Section 5.2)
  const TLV_TYPES = {
    0x0001: 'EIGRP_PARAMETERS',
    0x0002: 'AUTHENTICATION',
    0x0003: 'SEQUENCE',
    0x0004: 'SOFTWARE_VERSION',
    0x0005: 'NEXT_MCAST_SEQ',
    0x0102: 'IPV4_INTERNAL_ROUTE',
    0x0103: 'IPV4_EXTERNAL_ROUTE',
    0x0104: 'WIDE_METRIC_ROUTE'
  };

  /**
   * Calculate 16-bit Internet Checksum (RFC 1071)
   */
  function calculateChecksum(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      let word;
      if (i + 1 < bytes.length) {
        word = (bytes[i] << 8) + bytes[i + 1];
      } else {
        word = (bytes[i] << 8);
      }
      sum += word;
      while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
      }
    }
    return (~sum) & 0xffff;
  }

  /**
   * Helper to write 32-bit big-endian integer into array
   */
  function writeUint32(arr, val) {
    arr.push((val >>> 24) & 0xff);
    arr.push((val >>> 16) & 0xff);
    arr.push((val >>> 8) & 0xff);
    arr.push(val & 0xff);
  }

  /**
   * Helper to write 16-bit big-endian integer into array
   */
  function writeUint16(arr, val) {
    arr.push((val >>> 8) & 0xff);
    arr.push(val & 0xff);
  }

  /**
   * Parse IPv4 string into 4 bytes
   */
  function parseIPv4(ipStr) {
    const parts = (ipStr || '0.0.0.0').split('.').map(x => parseInt(x, 10) & 0xff);
    while (parts.length < 4) parts.push(0);
    return parts.slice(0, 4);
  }

  /**
   * Calculate Classic EIGRP 32-bit Metric
   * Formula (K5=0): 256 * ( K1 * (10^7 / min_bw_kbps) + K3 * (delay_usec / 10) )
   */
  function calculateClassicMetric(bandwidthKbps, delayUsec, k1 = 1, k2 = 0, k3 = 1, k4 = 0, k5 = 0) {
    if (bandwidthKbps <= 0) bandwidthKbps = 10000;
    const bwTerm = Math.floor(10000000 / bandwidthKbps);
    const delayTerm = Math.floor(delayUsec / 10);
    const metric = 256 * (k1 * bwTerm + k3 * delayTerm);
    return Math.floor(metric);
  }

  /**
   * Calculate RFC 7868 EIGRP Wide 64-bit Metric
   * Formula: 65536 * ( K1 * Throughput + K3 * Latency )
   * Throughput = 10^14 / Bandwidth (bps)
   * Latency = Delay (picoseconds) / 100
   */
  function calculateWideMetric(bandwidthKbps, delayUsec, k1 = 1, k3 = 1) {
    const bandwidthBps = bandwidthKbps * 1000;
    const throughput = Math.floor(1e14 / Math.max(bandwidthBps, 1));
    const latencyPicoseconds = delayUsec * 1000000;
    const latencyTerm = Math.floor(latencyPicoseconds / 100);
    const metric = 65536 * (k1 * throughput + k3 * latencyTerm);
    return metric;
  }

  /**
   * DUAL Feasibility Condition Evaluator
   * 
   * Feasibility Condition (FC):
   * A neighbor can become a Feasible Successor (FS) if and only if
   * Advertised Distance (AD) < current Feasible Distance (FD) of the primary path.
   */
  function evaluateDUALPaths(primaryFD, candidatePaths, variance = 1) {
    const results = [];
    let bestFD = primaryFD;

    // Find absolute lowest FD among candidate paths if primary is unset
    if (!bestFD || bestFD <= 0) {
      let minFD = Infinity;
      candidatePaths.forEach(p => {
        if (p.calculatedFD < minFD) minFD = p.calculatedFD;
      });
      bestFD = minFD === Infinity ? 1000 : minFD;
    }

    const varianceThreshold = bestFD * Math.max(1, variance);

    candidatePaths.forEach(path => {
      const isSuccessor = (path.calculatedFD === bestFD);
      const satisfiesFC = (path.advertisedDistance < bestFD);
      const withinVariance = (path.calculatedFD <= varianceThreshold);
      const eligibleUCMP = (isSuccessor || (satisfiesFC && withinVariance));

      let state = 'IGNORED';
      let reason = '';

      if (isSuccessor) {
        state = 'SUCCESSOR';
        reason = 'Primary lowest-cost loop-free route installed in RIB.';
      } else if (satisfiesFC) {
        if (withinVariance && variance > 1) {
          state = 'FEASIBLE_SUCCESSOR_LOAD_BALANCED';
          reason = `Satisfies FC (AD ${path.advertisedDistance} < FD ${bestFD}) and within variance x${variance} (FD ${path.calculatedFD} <= ${varianceThreshold}). Installed for UCMP!`;
        } else {
          state = 'FEASIBLE_SUCCESSOR_BACKUP';
          reason = `Satisfies FC (AD ${path.advertisedDistance} < FD ${bestFD}). Standby backup route in EIGRP topology table (0ms failover).`;
        }
      } else {
        state = 'NOT_FEASIBLE_LOOP_RISK';
        reason = `FAILS Feasibility Condition (AD ${path.advertisedDistance} >= FD ${bestFD}). Risk of routing loop. If primary drops, route enters ACTIVE state.`;
      }

      results.push({
        neighbor: path.neighbor,
        interface: path.interface,
        advertisedDistance: path.advertisedDistance,
        calculatedFD: path.calculatedFD,
        isSuccessor: isSuccessor,
        satisfiesFC: satisfiesFC,
        withinVariance: withinVariance,
        state: state,
        reason: reason,
        eligibleUCMP: eligibleUCMP
      });
    });

    return {
      bestFD: bestFD,
      variance: variance,
      varianceThreshold: varianceThreshold,
      paths: results
    };
  }

  /**
   * Forges an RFC 7868 binary EIGRP packet
   */
  function forgePacket(config) {
    const opcode = config.opcode !== undefined ? config.opcode : 5; // Default 5 = Hello
    const asn = config.asn || 100;
    const vrid = config.vrid || 0;
    const sequenceNumber = config.sequenceNumber || 0;
    const ackNumber = config.ackNumber || 0;
    const flags = config.flags || 0;
    const kValues = config.kValues || [1, 0, 1, 0, 0, 0];
    const holdTime = config.holdTime || 15;
    const includeAuth = !!config.includeAuth;
    const authKeyId = config.authKeyId || 1;
    const sharedKey = config.sharedKey || 'E1grpS3cur3K3y2026!';
    const includeRoute = !!config.includeRoute;
    const destPrefix = config.destPrefix || '10.200.1.0';
    const prefixLen = config.prefixLen !== undefined ? config.prefixLen : 24;
    const nextHop = config.nextHop || '10.100.0.2';
    const bandwidthKbps = config.bandwidthKbps || 1000000; // 1 Gbps default
    const delayUsec = config.delayUsec || 100;

    const packet = [];

    // --- 8-BYTE EIGRP HEADER (RFC 7868 Section 5.1) ---
    packet.push(2); // Version 2
    packet.push(opcode & 0xff);
    packet.push(0x00, 0x00); // Checksum placeholder
    writeUint32(packet, flags);
    writeUint32(packet, sequenceNumber);
    writeUint32(packet, ackNumber);
    writeUint16(packet, vrid);
    writeUint16(packet, asn);

    // --- TLV 0x0001: PARAMETERS TLV (Always present in Hello) ---
    packet.push(0x00, 0x01); // Type 0x0001
    packet.push(0x00, 0x0c); // Length = 12 bytes
    for (let i = 0; i < 6; i++) {
      packet.push((kValues[i] || 0) & 0xff);
    }
    writeUint16(packet, holdTime);

    // --- TLV 0x0002: AUTHENTICATION TLV (RFC 7868 Section 6) ---
    let authDigestOffset = -1;
    if (includeAuth) {
      packet.push(0x00, 0x02); // Type 0x0002
      packet.push(0x00, 0x28); // Length = 40 bytes (4 TLV header + 4 subheader + 32 digest)
      writeUint16(packet, 2); // Auth Type: 2 = HMAC-SHA-256
      writeUint16(packet, authKeyId);
      authDigestOffset = packet.length;
      // 32-byte HMAC digest placeholder
      for (let i = 0; i < 32; i++) {
        packet.push(0x00);
      }
    }

    // --- TLV 0x0102: IPV4 INTERNAL ROUTE TLV ---
    if (includeRoute) {
      const destBytes = parseIPv4(destPrefix);
      const nextHopBytes = parseIPv4(nextHop);
      const routeTlvLength = 4 + 24 + Math.ceil(prefixLen / 8);

      packet.push(0x01, 0x02); // Type 0x0102
      writeUint16(packet, routeTlvLength);
      // Next Hop
      packet.push(...nextHopBytes);
      // Delay (scaled microseconds * 256)
      writeUint32(packet, delayUsec * 256);
      // Bandwidth (10^7 / kbps * 256)
      writeUint32(packet, Math.floor(10000000 / bandwidthKbps) * 256);
      // MTU (3 bytes)
      packet.push(0x00, 0x05, 0xdc); // 1500
      // Hop Count (1 byte)
      packet.push(0x01);
      // Reliability (1 byte)
      packet.push(0xff); // 255
      // Load (1 byte)
      packet.push(0x01); // 1
      // Reserved (2 bytes)
      packet.push(0x00, 0x00);
      // Prefix Length
      packet.push(prefixLen & 0xff);
      // Destination IP octets matching prefixLen
      const numOctets = Math.ceil(prefixLen / 8);
      for (let i = 0; i < numOctets; i++) {
        packet.push(destBytes[i] || 0);
      }
    }

    // Compute synthetic or actual HMAC digest if auth enabled
    if (includeAuth && authDigestOffset !== -1) {
      // Deterministic HMAC mock / generation
      for (let i = 0; i < 32; i++) {
        const seed = (sharedKey.charCodeAt(i % sharedKey.length) * 31 + i * 17) & 0xff;
        packet[authDigestOffset + i] = seed;
      }
    }

    // Compute RFC 1071 Checksum over entire EIGRP packet
    const chk = calculateChecksum(packet);
    packet[2] = (chk >>> 8) & 0xff;
    packet[3] = chk & 0xff;

    return {
      rawBytes: new Uint8Array(packet),
      totalLength: packet.length,
      opcode: opcode,
      opcodeName: OPCODES[opcode] || `Unknown (${opcode})`,
      asn: asn,
      vrid: vrid,
      flags: flags,
      sequenceNumber: sequenceNumber,
      ackNumber: ackNumber,
      checksum: chk,
      hasAuth: includeAuth,
      hasRoute: includeRoute,
      kValues: kValues,
      holdTime: holdTime
    };
  }

  /**
   * Format bytes as Wireshark-style hex dump
   */
  function formatHexDump(uint8Array) {
    const lines = [];
    for (let i = 0; i < uint8Array.length; i += 16) {
      const offset = ('0000' + i.toString(16)).slice(-4);
      const slice = uint8Array.slice(i, i + 16);
      let hexPart1 = '';
      let hexPart2 = '';

      for (let j = 0; j < 8; j++) {
        if (j < slice.length) {
          hexPart1 += ('0' + slice[j].toString(16)).slice(-2) + ' ';
        } else {
          hexPart1 += '   ';
        }
      }

      for (let j = 8; j < 16; j++) {
        if (j < slice.length) {
          hexPart2 += ('0' + slice[j].toString(16)).slice(-2) + ' ';
        } else {
          hexPart2 += '   ';
        }
      }

      let asciiPart = '';
      for (let j = 0; j < slice.length; j++) {
        const b = slice[j];
        asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      }

      lines.push(`${offset}   ${hexPart1} ${hexPart2}  |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  /**
   * Build a standard binary PCAP file buffer containing the EIGRP packet
   * Encapsulates: Ethernet (Type 0x0800) -> IPv4 (Protocol 88) -> EIGRP
   */
  function buildPcapBuffer(eigrpBytes, srcIp = '10.100.0.1', dstIp = '224.0.0.10') {
    const pcapHeader = new Uint8Array(24);
    const pcapView = new DataView(pcapHeader.buffer);
    pcapView.setUint32(0, 0xa1b2c3d4, false); // Magic number
    pcapView.setUint16(4, 2, false);          // Major version 2
    pcapView.setUint16(6, 4, false);          // Minor version 4
    pcapView.setUint32(8, 0, false);          // Timezone offset GMT
    pcapView.setUint32(12, 0, false);         // Accuracy
    pcapView.setUint32(16, 65535, false);     // Snapshot length
    pcapView.setUint32(20, 1, false);         // Link layer: Ethernet (1)

    // Ethernet Header (14 bytes)
    // Multicast Destination for 224.0.0.10 is 01:00:5E:00:00:0A
    const ethHeader = new Uint8Array([
      0x01, 0x00, 0x5e, 0x00, 0x00, 0x0a, // Dst MAC (EIGRP Multicast)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
      0x08, 0x00                          // EtherType IPv4
    ]);

    // IPv4 Header (20 bytes, Protocol 88 = EIGRP)
    const ipTotalLen = 20 + eigrpBytes.length;
    const ipHeader = new Uint8Array(20);
    const ipView = new DataView(ipHeader.buffer);
    ipHeader[0] = 0x45; // IPv4, Header Length 5 (20 bytes)
    ipHeader[1] = 0xc0; // DSCP CS6 (Network Control)
    ipView.setUint16(2, ipTotalLen, false);
    ipView.setUint16(4, 0x1234, false); // Identification
    ipView.setUint16(6, 0x0000, false); // Flags/Fragment
    ipHeader[8] = 2;    // TTL = 2 (GTSM / Local Multicast)
    ipHeader[9] = 88;   // Protocol 88 = EIGRP

    const srcBytes = parseIPv4(srcIp);
    const dstBytes = parseIPv4(dstIp);
    for (let i = 0; i < 4; i++) {
      ipHeader[12 + i] = srcBytes[i];
      ipHeader[16 + i] = dstBytes[i];
    }
    const ipChecksum = calculateChecksum(ipHeader);
    ipView.setUint16(10, ipChecksum, false);

    // Frame payload: Eth + IP + EIGRP
    const frameLen = ethHeader.length + ipHeader.length + eigrpBytes.length;
    const packetHeader = new Uint8Array(16);
    const pktView = new DataView(packetHeader.buffer);
    const nowSec = Math.floor(Date.now() / 1000);
    pktView.setUint32(0, nowSec, false);
    pktView.setUint32(4, 0, false);
    pktView.setUint32(8, frameLen, false);  // Captured Length
    pktView.setUint32(12, frameLen, false); // Original Length

    const totalPcap = new Uint8Array(24 + 16 + frameLen);
    totalPcap.set(pcapHeader, 0);
    totalPcap.set(packetHeader, 24);
    totalPcap.set(ethHeader, 40);
    totalPcap.set(ipHeader, 54);
    totalPcap.set(eigrpBytes, 74);

    return totalPcap;
  }

  return {
    OPCODES: OPCODES,
    TLV_TYPES: TLV_TYPES,
    calculateChecksum: calculateChecksum,
    calculateClassicMetric: calculateClassicMetric,
    calculateWideMetric: calculateWideMetric,
    evaluateDUALPaths: evaluateDUALPaths,
    forgePacket: forgePacket,
    formatHexDump: formatHexDump,
    buildPcapBuffer: buildPcapBuffer
  };
});
