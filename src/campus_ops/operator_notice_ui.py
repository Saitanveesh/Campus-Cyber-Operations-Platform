OPERATOR_NOTICE_EXTENSION = r"""
<style>
#operatorNoticeBackdrop{position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:9998;display:flex;align-items:center;justify-content:center;padding:24px}
#operatorNotice{width:min(1180px,96vw);max-height:90vh;overflow:auto;background:#fff;color:#111;border:3px solid #111;box-shadow:0 18px 60px rgba(0,0,0,.35)}
.notice-head{padding:20px 24px;border-bottom:2px solid #111;display:flex;justify-content:space-between;gap:20px;align-items:end}.notice-head h1{margin:0;font-size:29px;letter-spacing:-.03em}.notice-head .small{max-width:560px;text-align:right}
.notice-body{padding:20px 24px}.notice-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid #bbb;border-left:1px solid #bbb}.notice-card{padding:15px;border-right:1px solid #bbb;border-bottom:1px solid #bbb;min-height:145px}.notice-card h3{font-size:11px;letter-spacing:.13em;text-transform:uppercase;margin:0 0 8px}.notice-card p,.notice-card li{font-size:11px;line-height:1.55}.notice-card ul{margin:7px 0 0;padding-left:17px}.notice-flow{border:1px solid #111;padding:14px;margin-top:16px;font:11px/1.65 Consolas,monospace;white-space:pre-wrap}.notice-footer{position:sticky;bottom:0;background:#fff;border-top:2px solid #111;padding:14px 24px;display:flex;justify-content:space-between;align-items:center;gap:18px}.notice-footer button{border:2px solid #111;background:#111;color:#fff;padding:11px 20px;font:800 11px Arial;letter-spacing:.09em;text-transform:uppercase;cursor:pointer}.notice-footer button:hover{background:#fff;color:#111}.notice-warning{font-size:10px;line-height:1.45;max-width:760px;color:#333}
@media(max-width:900px){.notice-grid{grid-template-columns:1fr}.notice-head{display:block}.notice-head .small{text-align:left;margin-top:8px}.notice-footer{display:block}.notice-footer button{width:100%;margin-top:10px}}
</style>
<div id="operatorNoticeBackdrop" role="dialog" aria-modal="true" aria-labelledby="operatorNoticeTitle">
 <div id="operatorNotice">
  <div class="notice-head"><div><div class="label">Campus Cyber Operations Platform</div><h1 id="operatorNoticeTitle">Operational Console — Operator Notice</h1></div><div class="small">Read this once on every fresh console load. It explains what the monitor can see, what each workspace means, and when active control is actually available.</div></div>
  <div class="notice-body">
   <div class="notice-grid">
    <div class="notice-card"><h3>1 · What this platform does</h3><p>It combines live packet capture, flow analysis, asset discovery, topology, security analytics, endpoint telemetry, forensics, incident correlation and controlled response in one console.</p><ul><li>Live values come from the current monitoring session.</li><li>Missing sensors are shown as unavailable, not invented.</li><li>Risk and confidence are different measurements.</li></ul></div>
    <div class="notice-card"><h3>2 · Wi‑Fi and LAN</h3><p>The monitor automatically follows the selected active interface.</p><ul><li><b>Wi‑Fi:</b> channel/link state, association, rates and packet visibility when supported.</li><li><b>LAN:</b> interface state, speed, addresses and capture on the Ethernet adapter.</li><li>SPAN/TAP, NetFlow/IPFIX, SNMP/LLDP, syslog and controller telemetry increase visibility.</li></ul></div>
    <div class="notice-card"><h3>3 · Overview / Network</h3><p><b>Overview</b> is the operator health board: interface, capture, packets, rates, assets, flows, alerts and incidents. <b>Network</b> explains the active link, DNS, infrastructure telemetry and sensor state.</p><p>If packet count is not increasing while the OS reports traffic, check capture health/Npcap binding before trusting deeper analytics.</p></div>
    <div class="notice-card"><h3>4 · Topology / Path Space</h3><p><b>Topology</b> shows observed live communication. <b>Path Space</b> provides a spatial relationship view. A line means communication was observed; it does not automatically mean a physical switch path or an exploitable attack path.</p><p>Physical topology is promoted only when LLDP/CDP/SNMP/controller evidence exists.</p></div>
    <div class="notice-card"><h3>5 · Assets / Security</h3><p><b>Assets</b> correlates observed endpoints and identities. <b>Security</b> combines alerts, incidents, behavior, risk and correlated evidence.</p><p>An alert is a lead. An incident should have independent supporting evidence. Use the investigation/forensics pivots before disruptive response.</p></div>
    <div class="notice-card"><h3>6 · System / Analytics</h3><p><b>System</b> shows watchdog health, analytics engines and optional external tooling. Engines should be treated as degraded when required telemetry is missing.</p><p>Optional tools such as Zeek, Suricata, Arkime, Nmap, osquery, Velociraptor, YARA and others are detected and reported by capability.</p></div>
    <div class="notice-card"><h3>7 · Admin workspaces</h3><p>Admin mode adds Command Center, SOC Desk, Red Team, Forensics and Infrastructure.</p><ul><li><b>SOC Desk:</b> cases and evidence.</li><li><b>Forensics:</b> deep host/network pivots.</li><li><b>Infrastructure:</b> switch/router/VLAN evidence.</li><li><b>Command Center:</b> operational readiness and response.</li></ul></div>
    <div class="notice-card"><h3>8 · Red / Purple Team</h3><p>Red Team models exposure, reach and authorized validation. Purple Team maps observed evidence to detection/control coverage. It does not treat an open service as proof of compromise.</p><p>Active discovery is restricted to explicitly authorized private/lab scope. No automatic brute force or destructive exploitation is performed.</p></div>
    <div class="notice-card"><h3>9 · Host control and isolation</h3><p>An IP address alone does not provide control. Snapshot, process actions, file quarantine and host isolation require an enrolled endpoint agent or an authorized external control plane such as NAC/switch/EDR.</p><p>Isolation is explicit, audited and reversible. Unmanaged systems remain analysis-only unless infrastructure control is connected.</p></div>
   </div>
   <div class="notice-flow">NORMAL OPERATOR FLOW
1. Confirm CAPTURE = ACTIVE and packet count is increasing.
2. Review Overview → Network → Topology/Path Space.
3. Investigate unusual assets, flows, alerts or incidents.
4. Correlate evidence in Security / SOC Desk / Forensics.
5. Use Red/Purple Team only for authorized validation.
6. Use containment only after identity and evidence are confirmed.
7. Restore isolated hosts through an explicit operator action.

WHEN SOMETHING LOOKS WRONG
Capture idle → verify interface/Npcap/TShark.  No physical topology → connect SNMP/LLDP/controller telemetry.  Unmanaged target → analysis only.  High risk + low confidence → collect more evidence before response.</div>
  </div>
  <div class="notice-footer"><div class="notice-warning"><b>Operator rule:</b> observed network behavior, analytical inference and verified endpoint/infrastructure evidence are kept separate. Do not interpret a heuristic score as proof of compromise.</div><button id="operatorNoticeContinue">I Understand &amp; Continue</button></div>
 </div>
</div>
<script>(()=>{const b=document.getElementById('operatorNoticeBackdrop'),x=document.getElementById('operatorNoticeContinue');if(x)x.onclick=()=>{if(b)b.remove()};document.addEventListener('keydown',e=>{if(e.key==='Escape'&&b)b.remove()})})();</script>
"""
