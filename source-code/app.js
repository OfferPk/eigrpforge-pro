/**
 * EIGRPForge Pro - Studio Application Controller
 */

// Global State
let currentTab = 'cisco-named';
let activeCandidatePaths = [];

const PRESETS = {
  enterprise: {
    opcode: 5,
    asn: 100,
    authType: 'HMAC-SHA-256',
    authKey: 'E1grpS3cur3K3y2026!',
    bandwidthKbps: 1000000,
    delayUsec: 100,
    primaryFD: 28160,
    variance: 1,
    isStubConfigured: true,
    isCoreRouter: false,
    passiveDefault: true,
    bfdEnabled: true,
    namedMode: true,
    wideMetrics: true,
    coppActive: true,
    summarizationActive: true,
    paths: [
      { neighbor: 'R1 (Primary Core)', interface: 'Gi0/0/1', advertisedDistance: 25600, calculatedFD: 28160 },
      { neighbor: 'R2 (Backup WAN)', interface: 'Gi0/0/2', advertisedDistance: 26880, calculatedFD: 30720 },
      { neighbor: 'R3 (Drift Router)', interface: 'Gi0/0/3', advertisedDistance: 35840, calculatedFD: 40960 }
    ]
  },
  datacenter: {
    opcode: 1,
    asn: 65001,
    authType: 'HMAC-SHA-256',
    authKey: 'DC_SpineLeaf_E1grp$2026',
    bandwidthKbps: 100000000, // 100 Gbps
    delayUsec: 10,
    primaryFD: 15360,
    variance: 2,
    isStubConfigured: false,
    isCoreRouter: true,
    passiveDefault: true,
    bfdEnabled: true,
    namedMode: true,
    wideMetrics: true,
    coppActive: true,
    summarizationActive: true,
    paths: [
      { neighbor: 'Spine-01 (Primary)', interface: 'Eth1/1', advertisedDistance: 12800, calculatedFD: 15360 },
      { neighbor: 'Spine-02 (Alternate)', interface: 'Eth1/2', advertisedDistance: 14080, calculatedFD: 20480 }
    ]
  },
  vulnerable: {
    opcode: 5,
    asn: 1,
    authType: 'NONE',
    authKey: '',
    bandwidthKbps: 10000,
    delayUsec: 1000,
    primaryFD: 50000,
    variance: 4,
    isStubConfigured: false,
    isCoreRouter: false,
    passiveDefault: false,
    bfdEnabled: false,
    namedMode: false,
    wideMetrics: false,
    coppActive: false,
    summarizationActive: false,
    paths: [
      { neighbor: 'Legacy-R1', interface: 'Fa0/0', advertisedDistance: 45000, calculatedFD: 50000 },
      { neighbor: 'Legacy-R2', interface: 'Fa0/1', advertisedDistance: 55000, calculatedFD: 60000 }
    ]
  }
};

function loadPreset(name) {
  const p = PRESETS[name] || PRESETS.enterprise;

  document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById(`btn-preset-${name}`);
  if (btn) btn.classList.add('active');

  document.getElementById('input-opcode').value = p.opcode;
  document.getElementById('input-asn').value = p.asn;
  document.getElementById('input-auth-type').value = p.authType;
  document.getElementById('input-auth-key').value = p.authKey;
  document.getElementById('input-bandwidth').value = p.bandwidthKbps;
  document.getElementById('input-delay').value = p.delayUsec;
  document.getElementById('input-primary-fd').value = p.primaryFD;
  document.getElementById('input-variance').value = p.variance;

  document.getElementById('chk-stub').checked = p.isStubConfigured;
  document.getElementById('chk-passive').checked = p.passiveDefault;
  document.getElementById('chk-bfd').checked = p.bfdEnabled;
  document.getElementById('chk-named').checked = p.namedMode;
  document.getElementById('chk-wide').checked = p.wideMetrics;
  document.getElementById('chk-copp').checked = p.coppActive;
  document.getElementById('chk-summary').checked = p.summarizationActive;

  activeCandidatePaths = JSON.parse(JSON.stringify(p.paths));
  updateAll();
}

function updateAll() {
  const opcode = parseInt(document.getElementById('input-opcode').value, 10);
  const asn = parseInt(document.getElementById('input-asn').value, 10) || 100;
  const authType = document.getElementById('input-auth-type').value;
  const authKey = document.getElementById('input-auth-key').value;
  const bandwidthKbps = parseInt(document.getElementById('input-bandwidth').value, 10) || 1000000;
  const delayUsec = parseInt(document.getElementById('input-delay').value, 10) || 100;
  const primaryFD = parseInt(document.getElementById('input-primary-fd').value, 10) || 28160;
  const variance = parseInt(document.getElementById('input-variance').value, 10) || 1;

  const isStubConfigured = document.getElementById('chk-stub').checked;
  const passiveDefault = document.getElementById('chk-passive').checked;
  const bfdEnabled = document.getElementById('chk-bfd').checked;
  const namedMode = document.getElementById('chk-named').checked;
  const wideMetrics = document.getElementById('chk-wide').checked;
  const coppActive = document.getElementById('chk-copp').checked;
  const summarizationActive = document.getElementById('chk-summary').checked;

  // 1. Calculate Metrics
  const classicMetric = EIGRPProtocolEngine.calculateClassicMetric(bandwidthKbps, delayUsec);
  const wideMetric = EIGRPProtocolEngine.calculateWideMetric(bandwidthKbps, delayUsec);
  document.getElementById('metric-classic').textContent = classicMetric.toLocaleString();
  document.getElementById('metric-wide').textContent = wideMetric.toLocaleString();

  // 2. Evaluate DUAL Feasibility Paths
  const dualResult = EIGRPProtocolEngine.evaluateDUALPaths(primaryFD, activeCandidatePaths, variance);
  renderDualTable(dualResult);

  // Check if at least one backup path satisfies FC
  let backupSatisfiesFC = false;
  dualResult.paths.forEach(p => {
    if (!p.isSuccessor && p.satisfiesFC) backupSatisfiesFC = true;
  });

  // 3. Forge Packet & Hex Dump
  const forged = EIGRPProtocolEngine.forgePacket({
    opcode: opcode,
    asn: asn,
    includeAuth: (authType === 'HMAC-SHA-256' || authType === 'MD5'),
    sharedKey: authKey,
    includeRoute: (opcode === 1), // Include route if Update
    bandwidthKbps: bandwidthKbps,
    delayUsec: delayUsec
  });

  document.getElementById('wire-length-badge').textContent = `Length: ${forged.totalLength} B`;
  document.getElementById('hex-box').textContent = EIGRPProtocolEngine.formatHexDump(forged.rawBytes);
  window._lastEigrpBytes = forged.rawBytes;

  // 4. Run 10-Point Security Audit
  const auditResult = EIGRPSecurityAuditor.auditConfiguration({
    authType: authType,
    backupSatisfiesFC: backupSatisfiesFC,
    isStubConfigured: isStubConfigured,
    passiveDefault: passiveDefault,
    bfdEnabled: bfdEnabled,
    namedMode: namedMode,
    wideMetrics: wideMetrics,
    variance: variance,
    coppActive: coppActive,
    summarizationActive: summarizationActive
  });

  renderAuditScorecard(auditResult);

  // 5. Update Configuration Synthesizer Output
  renderConfig({
    asn: asn,
    sharedKey: authKey,
    isStubConfigured: isStubConfigured,
    variance: variance,
    bfdEnabled: bfdEnabled
  });
}

function renderDualTable(dualResult) {
  const tbody = document.getElementById('dual-paths-tbody');
  tbody.innerHTML = '';

  dualResult.paths.forEach(p => {
    const tr = document.createElement('tr');

    let badgeClass = 'status-loop';
    let badgeText = 'FAIL (Loop Risk)';
    if (p.isSuccessor) {
      badgeClass = 'status-successor';
      badgeText = 'SUCCESSOR';
    } else if (p.state === 'FEASIBLE_SUCCESSOR_LOAD_BALANCED') {
      badgeClass = 'status-fs';
      badgeText = 'FS (UCMP Active)';
    } else if (p.state === 'FEASIBLE_SUCCESSOR_BACKUP') {
      badgeClass = 'status-fs';
      badgeText = 'FS (Standby Backup)';
    }

    tr.innerHTML = `
      <td><strong>${p.neighbor}</strong><br><small style="color:var(--text-dim);">${p.interface}</small></td>
      <td style="color:${p.satisfiesFC || p.isSuccessor ? 'var(--primary-emerald)' : 'var(--primary-red)'};">${p.advertisedDistance.toLocaleString()}</td>
      <td style="color:var(--text-main);">${p.calculatedFD.toLocaleString()}</td>
      <td>
        <span class="status-badge ${badgeClass}">${badgeText}</span>
        <div style="font-size:10px; color:var(--text-dim); margin-top:2px;">${p.reason}</div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderAuditScorecard(audit) {
  const banner = document.getElementById('score-banner');
  const circle = document.getElementById('grade-circle');
  const header = document.getElementById('score-header');
  const subtext = document.getElementById('score-subtext');
  const gradeBadge = document.getElementById('score-grade-badge');

  circle.textContent = audit.grade;
  gradeBadge.textContent = `GRADE ${audit.grade}`;

  if (audit.score >= 80) {
    banner.className = 'score-banner score-banner-green';
    circle.className = 'grade-circle';
    gradeBadge.className = 'badge badge-emerald';
    header.textContent = `${audit.score} / 100 Points — Production-Grade Zero-Trust EIGRP`;
    subtext.textContent = 'RFC 7868 HMAC-SHA-256 enforced, DUAL loop-free verified, and EIGRP stub active.';
  } else {
    banner.className = 'score-banner score-banner-red';
    circle.className = 'grade-circle grade-circle-red';
    gradeBadge.className = 'badge badge-amber';
    header.textContent = `${audit.score} / 100 Points — Severe Security & Outage Risks Detected`;
    subtext.textContent = 'Unauthenticated peering, missing stub, or DUAL loop hazards present.';
  }

  const container = document.getElementById('findings-container');
  container.innerHTML = '';

  audit.findings.forEach(f => {
    const item = document.createElement('div');
    item.className = 'finding-item';

    let statusClass = 'finding-pass';
    if (f.status === 'FAIL') statusClass = 'finding-fail';
    else if (f.status === 'WARN') statusClass = 'finding-warn';

    item.innerHTML = `
      <div class="finding-title">
        <span class="${statusClass}">[${f.status}] ${f.id}</span>
        <span>${f.score}/${f.maxScore} pts</span>
      </div>
      <div style="font-weight:600; color:#fff; font-size:11px; margin-bottom:2px;">${f.title}</div>
      <div class="finding-desc">${f.description}</div>
    `;
    container.appendChild(item);
  });
}

function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  updateAll();
}

function renderConfig(params) {
  const box = document.getElementById('config-box');
  let content = '';

  if (currentTab === 'cisco-named') {
    content = EIGRPConfigSynthesizer.synthesizeCiscoNamedMode(params);
  } else if (currentTab === 'cisco-classic') {
    content = EIGRPConfigSynthesizer.synthesizeCiscoClassicMode(params);
  } else if (currentTab === 'cisco-nxos') {
    content = EIGRPConfigSynthesizer.synthesizeCiscoNxos(params);
  } else if (currentTab === 'linux-frr') {
    content = EIGRPConfigSynthesizer.synthesizeLinuxFRR(params);
  } else if (currentTab === 'prometheus') {
    content = EIGRPConfigSynthesizer.synthesizePrometheusAlerts(params);
  }

  box.textContent = content;
}

function copyHexDump() {
  const text = document.getElementById('hex-box').textContent;
  navigator.clipboard.writeText(text).then(() => alert('Wireshark Hex Dump copied to clipboard!'));
}

function copyConfig() {
  const text = document.getElementById('config-box').textContent;
  navigator.clipboard.writeText(text).then(() => alert('Configuration copied to clipboard!'));
}

function downloadPcap() {
  if (!window._lastEigrpBytes) return;
  const pcap = EIGRPProtocolEngine.buildPcapBuffer(window._lastEigrpBytes);
  const blob = new Blob([pcap], { type: 'application/vnd.tcpdump.pcap' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'eigrp-traffic.pcap';
  a.click();
  URL.revokeObjectURL(url);
}

// Initial boot
window.addEventListener('DOMContentLoaded', () => {
  loadPreset('enterprise');
});
