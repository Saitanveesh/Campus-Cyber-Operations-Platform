INVESTIGATION_EXTENSION = r"""
<style>
.invest-shell{max-width:1500px;margin-left:auto;margin-right:auto}
.invest-bar{display:grid;grid-template-columns:minmax(220px,420px) auto auto;gap:8px;align-items:center}
.invest-bar input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #999;background:#fff;color:#111;font:12px Consolas,Monaco,monospace}
.invest-summary{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin-top:12px}
.invest-stat{padding:11px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:62px}
.invest-stat strong{display:block;font-size:17px;margin-top:5px}
.invest-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:14px;margin-top:14px}
.invest-panel{border:1px solid #c7c7c7;padding:12px;min-width:0}
.invest-title{font-size:19px;font-weight:800;margin:6px 0 10px}
.invest-risk{font-size:28px;font-weight:900;line-height:1}
.invest-line{font-size:10px;line-height:1.55;border-bottom:1px solid #eee;padding:5px 0}
.invest-line:last-child{border-bottom:0}
.invest-controls{display:flex;gap:7px;flex-wrap:wrap;margin-top:11px}
.invest-tool-grid{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.invest-tool{border:1px solid #bbb;padding:4px 6px;font:700 9px Arial,Helvetica,sans-serif;letter-spacing:.05em}
.invest-tool.ready{border-color:#111}
.invest-list{max-height:260px;overflow:auto;margin-top:8px}
.invest-list-row{padding:7px 0;border-bottom:1px solid #ddd;font-size:10px;line-height:1.45}
.invest-output{border:1px solid #c7c7c7;background:#fff;min-height:150px;max-height:420px;overflow:auto;padding:12px;white-space:pre-wrap;font:10px/1.45 Consolas,Monaco,monospace;margin-top:9px}
.invest-warning{border-left:3px solid #111;padding:7px 9px;font-size:10px;line-height:1.45;margin-top:10px}
@media(max-width:1050px){.invest-summary{grid-template-columns:repeat(3,1fr)}.invest-grid{grid-template-columns:1fr}}
@media(max-width:700px){.invest-bar{grid-template-columns:1fr}.invest-summary{grid-template-columns:1fr 1fr}}
</style>
<script>
(()=>{
const I=id=>document.getElementById(id);
const ih=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtRate=v=>{v=Number(v||0);return v>=1e9?(v/1e9).toFixed(1)+' Gbps':v>=1e6?(v/1e6).toFixed(1)+' Mbps':v>=1e3?(v/1e3).toFixed(1)+' Kbps':v.toFixed(0)+' bps'};
const fmtBytes=v=>{v=Number(v||0);return v>=1e9?(v/1e9).toFixed(1)+' GB':v>=1e6?(v/1e6).toFixed(1)+' MB':v>=1e3?(v/1e3).toFixed(1)+' KB':v+' B'};
let investigation=null;

function injectInvestigation(){
  const security=I('view-security');if(!security||I('ipInvestigation'))return;
  const section=document.createElement('section');section.id='ipInvestigation';section.className='invest-shell';
  section.innerHTML=`
    <div class="sectionhead"><div><h2>IP Investigation</h2><div class="small">Pivot from observed traffic to evidence, endpoint telemetry and authorized response.</div></div></div>
    <div class="invest-bar"><input id="investTarget" placeholder="IP address, for example 10.20.87.158"><button class="btn" id="investRun">Investigate</button><button class="btn" id="investDeep">Authorized Deep Probe</button></div>
    <div id="investStatus" class="small" style="margin-top:7px">Enter an observed IP. Passive investigation does not generate network traffic.</div>
    <div class="invest-summary" id="investSummary"></div>
    <div class="invest-grid">
      <div class="invest-panel"><div class="label">Target Assessment</div><div id="investTargetDetail"></div><div class="invest-controls"><button class="btn" id="investSnapshot" disabled>Collect Endpoint Snapshot</button><button class="btn" id="investIsolate" disabled>Isolate Endpoint</button><button class="btn" id="investRestore" disabled>Restore Endpoint</button></div><div id="investControlNote" class="invest-warning">Endpoint response requires an enrolled managed agent mapped to this IP.</div></div>
      <div class="invest-panel"><div class="label">Forensic Capability</div><div id="investTools" class="invest-tool-grid"></div><div class="label" style="margin-top:14px">Evidence Reasons</div><div id="investReasons" class="invest-list"></div></div>
    </div>
    <div class="invest-grid">
      <div class="invest-panel"><div class="label">Top Peers / Services / Applications</div><div id="investPivots" class="invest-list"></div></div>
      <div class="invest-panel"><div class="label">Related Incidents</div><div id="investIncidents" class="invest-list"></div></div>
    </div>
    <div class="invest-panel" style="margin-top:14px"><div class="label">Live Flows</div><div class="tablewrap" style="max-height:300px"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Application</th><th>Rate</th><th>Packets</th></tr></thead><tbody id="investFlows"></tbody></table></div></div>
    <div class="invest-panel" style="margin-top:14px"><div class="label">Deep Probe Output</div><div class="small">Active probing is restricted to explicitly authorized private lab IPs.</div><pre id="investProbeOutput" class="invest-output">No deep probe has been run.</pre></div>`;
  const incident=I('contextIncidentPanel');
  if(incident&&incident.parentElement===security)incident.insertAdjacentElement('afterend',section);else security.insertBefore(section,security.firstChild);
  I('investRun').onclick=()=>runInvestigation();
  I('investDeep').onclick=()=>runDeepProbe();
  I('investSnapshot').onclick=()=>queueTargetAction('snapshot');
  I('investIsolate').onclick=()=>queueTargetAction('isolate');
  I('investRestore').onclick=()=>queueTargetAction('restore');
  I('investTarget').addEventListener('keydown',e=>{if(e.key==='Enter')runInvestigation();});
}

function targetApp(flow){return flow.tls_sni||flow.dns_query||flow.http_host||flow.protocol||flow.transport||'—';}
function renderInvestigation(d){
  investigation=d;injectInvestigation();
  const s=d.summary||{},r=d.risk||{},a=d.asset||{},agent=d.managed_agent||{};
  const stats=[['Risk',`${Number(r.score||0)} / 100`],['Assessment',r.assessment||'—'],['Flows',s.flow_count||0],['Peers',s.peer_count||0],['Alerts',s.alert_count||0],['Open Incidents',s.open_incident_count||0]];
  I('investSummary').innerHTML=stats.map(x=>`<div class="invest-stat"><div class="label">${ih(x[0])}</div><strong>${ih(x[1])}</strong></div>`).join('');
  I('investTargetDetail').innerHTML=`<div class="invest-title mono">${ih(d.target)}</div><div class="invest-risk">${ih(r.assessment||'—')}</div><div class="invest-line"><b>Role:</b> ${ih(a.classification||a.role||'Observed peer')}</div><div class="invest-line"><b>Name:</b> ${ih(a.hostname||a.dhcp_hostname||agent.name||'—')}</div><div class="invest-line"><b>MAC:</b> ${ih(a.mac||'—')}</div><div class="invest-line"><b>Observed:</b> ${ih(s.packets||0)} packets · ${ih(fmtBytes(s.bytes))} · ${ih(fmtRate(s.observed_bps))}</div><div class="invest-line"><b>Managed endpoint:</b> ${d.manageable?`${ih(agent.endpoint_id)} · ${ih(agent.status||'UNKNOWN')}`:'No'}</div><div class="invest-line"><b>Isolation state:</b> ${ih((agent.telemetry||{}).isolation_state||'UNKNOWN')}</div>`;
  I('investReasons').innerHTML=(r.reasons||[]).map(x=>`<div class="invest-list-row">${ih(x)}</div>`).join('')||'<div class="muted">No strong evidence-backed risk reason is currently present.</div>';
  I('investTools').innerHTML=Object.entries(d.forensic_tools||{}).map(([k,v])=>`<span class="invest-tool ${v?'ready':''}">${ih(k.toUpperCase())} · ${v?'READY':'MISSING'}</span>`).join('');
  const piv=[];for(const [p,c] of s.top_peers||[])piv.push(`<div class="invest-list-row"><b>Peer</b> · <span class="mono">${ih(p)}</span> · ${ih(c)} packets</div>`);for(const [p,c] of s.top_services||[])piv.push(`<div class="invest-list-row"><b>Service</b> · ${ih(p)} · ${ih(c)} flow observations</div>`);for(const [p,c] of s.top_applications||[])piv.push(`<div class="invest-list-row"><b>Application</b> · ${ih(p)} · ${ih(c)} observations</div>`);I('investPivots').innerHTML=piv.join('')||'<div class="muted">No current pivots.</div>';
  I('investIncidents').innerHTML=(d.incidents||[]).map(x=>`<div class="invest-list-row"><b>${ih(x.severity||'')} · ${ih(x.title||'Incident')}</b><br>${ih(x.status||'OPEN')} · confidence ${ih(x.confidence||0)}% · ${ih(x.alert_count||0)} distinct alerts${Number(x.suppressed_repeats||0)?` · ${ih(x.suppressed_repeats)} repeats suppressed`:''}</div>`).join('')||'<div class="muted">No incident currently correlates to this IP.</div>';
  I('investFlows').innerHTML=(d.flows||[]).slice(0,50).map(f=>`<tr><td class="mono">${ih(f.src)}:${ih(f.src_port||'')}</td><td class="mono">${ih(f.dst)}:${ih(f.dst_port||'')}</td><td>${ih(f.protocol||f.transport||'—')}</td><td>${ih(targetApp(f))}</td><td>${ih(fmtRate(f.bps_ewma||0))}</td><td>${ih(f.packets||0)}</td></tr>`).join('')||'<tr><td colspan="6" class="muted">No active flow evidence for this IP.</td></tr>';
  for(const id of ['investSnapshot','investIsolate','investRestore'])I(id).disabled=!d.manageable;
  I('investControlNote').textContent=d.manageable?'Response actions are queued only to the authenticated endpoint agent for this IP. Isolation uses Windows Firewall and preserves the management channel.':'This IP is passive-only here. Isolation and endpoint snapshots require an enrolled endpoint agent mapped to this IP.';
}

async function runInvestigation(target){
  injectInvestigation();const input=I('investTarget');if(target)input.value=target;const value=(input.value||'').trim();if(!value)return;
  I('investStatus').textContent='Collecting current-session evidence...';
  try{const r=await fetch(`/api/v1/investigate/${encodeURIComponent(value)}`,{cache:'no-store'}),d=await r.json();if(!r.ok)throw new Error(d.detail||'Investigation failed');renderInvestigation(d);I('investStatus').textContent=`Passive investigation ready for ${d.target}. Assessment is evidence priority, not a malicious verdict.`;}catch(e){I('investStatus').textContent=e.message;}
}

async function runDeepProbe(){
  const target=(I('investTarget')?.value||'').trim();if(!target)return;
  if(!confirm(`Run authorized private-lab probe against ${target}? This generates network traffic.`))return;
  const out=I('investProbeOutput');out.textContent='Running authorized private-lab probe...';
  try{const r=await fetch(`/api/v1/investigate/${encodeURIComponent(target)}/deep-probe`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({authorized:true,include_services:true})}),d=await r.json();if(!r.ok)throw new Error(d.detail||'Deep probe failed');out.textContent=Object.entries(d.results||{}).map(([name,result])=>`=== ${name.toUpperCase()} · ${result.status||'UNKNOWN'} ===\n${result.output||''}`).join('\n\n')||'No probe output.';}catch(e){out.textContent=`ERROR: ${e.message}`;}
}

async function queueTargetAction(action){
  const target=investigation?.target;if(!target||!investigation?.manageable)return;
  if(action==='isolate'&&!confirm(`Isolate managed endpoint ${target}? Network traffic will be blocked except the Campus Ops management channel.`))return;
  if(action==='restore'&&!confirm(`Restore the saved Windows Firewall state on ${target}?`))return;
  const status=I('investStatus');status.textContent=`Queuing ${action} for ${target}...`;
  try{const r=await fetch(`/api/v1/investigate/${encodeURIComponent(target)}/${action}`,{method:'POST'}),d=await r.json();if(!r.ok)throw new Error(d.detail||`${action} failed`);status.textContent=`${action.toUpperCase()} queued · job ${d.job?.job_id||'created'}.`;setTimeout(()=>runInvestigation(target),1800);}catch(e){status.textContent=e.message;}
}

window.openInvestigation=target=>{if(typeof setView==='function')setView('security');setTimeout(()=>runInvestigation(target),100);};
injectInvestigation();
})();
</script>
"""
