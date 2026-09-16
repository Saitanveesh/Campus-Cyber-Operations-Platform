from __future__ import annotations


STABLE_OPERATOR_EXTENSION = r"""
<style>
.operator-shell{max-width:1500px;margin:0 auto}.operator-targetbar{display:grid;grid-template-columns:minmax(240px,430px) auto auto;gap:8px;margin:12px 0}.operator-targetbar input{height:35px;border:1px solid #999;padding:0 10px;font:12px Consolas,monospace}.operator-hero{display:grid;grid-template-columns:repeat(6,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:14px 0}.operator-hero>div{padding:11px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:68px}.operator-hero strong{display:block;font-size:17px;margin-top:5px}.operator-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.operator-panel{border:1px solid #c7c7c7;padding:13px;min-width:0}.operator-row{padding:8px 0;border-bottom:1px solid #ddd;font-size:10px;line-height:1.5}.operator-row:last-child{border-bottom:0}.operator-output{border:1px solid #c7c7c7;min-height:180px;max-height:460px;overflow:auto;padding:12px;white-space:pre-wrap;font:10px/1.5 Consolas,monospace;background:#fff}.operator-table{max-height:470px}.operator-badge{display:inline-block;border:1px solid #111;padding:3px 6px;font-size:9px;font-weight:700;margin-right:5px}.operator-empty{font-size:10px;color:#666;padding:10px 0}.operator-list{max-height:340px;overflow:auto}.operator-reason{border-left:2px solid #111;padding:5px 8px;margin:5px 0;font-size:10px}.watch-grid{display:grid;grid-template-columns:repeat(4,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:14px 0}.watch-grid>div{padding:12px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:72px}.watch-grid strong{display:block;font-size:18px;margin-top:6px}.watch-problem{border:1px solid #c7c7c7;padding:12px;margin-bottom:9px}.watch-problem.attention{border-left:4px solid #111}.watch-problem .watch-title{font-weight:800;font-size:12px}.watch-meta{font-size:10px;line-height:1.55;margin-top:7px;color:#333}.watch-ok{border:1px solid #c7c7c7;padding:14px;font-size:11px;line-height:1.55}.target-actions{display:flex;gap:5px;flex-wrap:wrap}
@media(max-width:1050px){.operator-grid{grid-template-columns:1fr}.operator-hero{grid-template-columns:repeat(3,1fr)}.operator-targetbar{grid-template-columns:1fr}.watch-grid{grid-template-columns:1fr 1fr}}
@media(max-width:650px){.operator-hero,.watch-grid{grid-template-columns:1fr 1fr}}
</style>
<script>
(()=>{
const O=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let lastReport=null,lastTargetsAt=0,lastWatchAt=0;
async function api(path){const response=await fetch(path,{cache:'no-store'});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||data));return data;}
function inject(){
  if(O('view-investigation'))return;
  const nav=document.querySelector('nav'),main=document.querySelector('main'),system=nav?.querySelector('button.tab[data-view="system"]'),foot=main?.querySelector('.foot');
  if(!nav||!main)return;
  try{
    pages.investigation=['Investigation','Evidence-backed investigation of an observed IP.'];
    pages.forensics=['Forensics','Current-session packet, flow, alert and relationship evidence.'];
    pages.watchdog=['Watchdog','Live MON runtime supervision and diagnostics.'];
  }catch{}
  for(const [view,label] of [['investigation','Investigation'],['forensics','Forensics'],['watchdog','Watchdog']]){
    const button=document.createElement('button');button.className='tab';button.dataset.view=view;button.textContent=label;
    button.onclick=()=>{setView(view);if(view==='investigation'&&Date.now()-lastTargetsAt>3000)loadTargets();if(view==='watchdog')loadWatchdog();};
    nav.insertBefore(button,system||null);
  }
  const holder=document.createElement('div');
  holder.innerHTML=`
  <div class="view" id="view-investigation"><section class="operator-shell"><div class="sectionhead"><div><h2>Investigation Workspace</h2><div class="small">Enter any IP. MON first proves whether the target was observed; unseen IPs receive no risk or safety verdict.</div></div></div><div class="operator-targetbar"><input id="investigationTarget" placeholder="Target IP"><button class="btn" id="investigationRun">Investigate</button><button class="btn" id="investigationRefresh">Refresh Targets</button></div><div class="operator-hero" id="investigationStats"></div><div class="operator-grid"><div class="operator-panel"><div class="label">Assessment</div><div id="investigationAssessment" class="operator-empty">Enter a target IP or choose an observed target below.</div></div><div class="operator-panel"><div class="label">Evidence Pivots</div><div id="investigationPivots" class="operator-empty">No target selected.</div></div></div><div class="operator-panel" style="margin-top:14px"><div class="label">Observed Targets</div><div class="tablewrap operator-table"><table><thead><tr><th>IP</th><th>Name</th><th>Class</th><th>Packets</th><th>Actions</th></tr></thead><tbody id="investigationTargets"><tr><td colspan="5" class="muted">Loading observed targets…</td></tr></tbody></table></div></div></section></div>
  <div class="view" id="view-forensics"><section class="operator-shell"><div class="sectionhead"><div><h2>Forensics Workbench</h2><div class="small">Passive correlation only. The report is limited to evidence in the active MON session.</div></div></div><div class="operator-targetbar"><input id="forensicsTarget" placeholder="Target IP"><button class="btn" id="forensicsRun">Build Report</button><button class="btn" id="forensicsUseInvestigation">Use Investigation Target</button></div><div class="operator-grid"><div class="operator-panel"><div class="label">Identity / Asset Evidence</div><div id="forensicsIdentity" class="operator-empty">Choose a target.</div><div class="label" style="margin-top:14px">Alerts / Incidents</div><div id="forensicsSecurity" class="operator-empty">No report loaded.</div></div><div class="operator-panel"><div class="label">Flows / Relationships</div><div id="forensicsRelationships" class="operator-list"><div class="operator-empty">No report loaded.</div></div></div></div><div class="operator-panel" style="margin-top:14px"><div class="label">Evidence Record</div><pre id="forensicsOutput" class="operator-output">No report has been built.</pre></div></section></div>
  <div class="view" id="view-watchdog"><section class="operator-shell"><div class="sectionhead"><div><h2>MON Watchdog</h2><div class="small">Supervises the selected interface, session, TShark process and stable workers. Quiet traffic is not treated as a failure.</div></div><button class="btn" id="watchdogRefresh">Refresh</button></div><div class="watch-grid" id="watchdogStats"></div><div class="operator-grid"><div class="operator-panel"><div class="label">Runtime Diagnostics</div><div id="watchdogProblems" class="operator-empty">Loading diagnostics…</div></div><div class="operator-panel"><div class="label">Current Anomalies</div><div id="watchdogAnomalies" class="operator-empty">Loading anomalies…</div></div></div></section></div>`;
  while(holder.firstChild)main.insertBefore(holder.firstChild,foot||null);
  O('investigationRun').onclick=()=>runInvestigation(O('investigationTarget').value);
  O('investigationTarget').addEventListener('keydown',e=>{if(e.key==='Enter')runInvestigation(e.currentTarget.value)});
  O('investigationRefresh').onclick=loadTargets;
  O('forensicsRun').onclick=()=>runForensics(O('forensicsTarget').value);
  O('forensicsTarget').addEventListener('keydown',e=>{if(e.key==='Enter')runForensics(e.currentTarget.value)});
  O('forensicsUseInvestigation').onclick=()=>{const value=O('investigationTarget').value.trim();O('forensicsTarget').value=value;if(value)runForensics(value)};
  O('watchdogRefresh').onclick=loadWatchdog;
  window.openInvestigation=target=>{target=String(target||'').trim();if(target)O('investigationTarget').value=target;setView('investigation');runInvestigation(target);};
  window.openForensics=target=>{target=String(target||'').trim();if(target)O('forensicsTarget').value=target;setView('forensics');runForensics(target);};
  loadTargets();
}
function stat(label,value){return`<div><div class="label">${esc(label)}</div><strong>${esc(value)}</strong></div>`}
function rows(values,empty='None observed'){
  if(!values||!values.length)return`<div class="operator-empty">${esc(empty)}</div>`;
  return values.map(value=>`<div class="operator-row">${esc(Array.isArray(value)?`${value[0]} · ${value[1]}`:value)}</div>`).join('');
}
async function loadTargets(){
  const body=O('investigationTargets');if(body)body.innerHTML='<tr><td colspan="5" class="muted">Loading…</td></tr>';
  try{
    const data=await api('/api/v1/operator/targets');const targets=data.targets||[];lastTargetsAt=Date.now();
    if(body)body.innerHTML=targets.map(item=>`<tr><td class="mono">${esc(item.ip)}</td><td>${esc(item.name||'—')}</td><td>${esc(item.classification||'—')}</td><td>${Number(item.packets||0).toLocaleString()}</td><td><div class="target-actions"><button class="btn" data-investigate-target="${esc(item.ip)}">Investigate</button><button class="btn" data-forensics-target="${esc(item.ip)}">Forensics</button></div></td></tr>`).join('')||'<tr><td colspan="5" class="muted">No packet-observed targets in the current session yet.</td></tr>';
    body?.querySelectorAll('[data-investigate-target]').forEach(button=>button.onclick=()=>window.openInvestigation(button.dataset.investigateTarget||''));
    body?.querySelectorAll('[data-forensics-target]').forEach(button=>button.onclick=()=>window.openForensics(button.dataset.forensicsTarget||''));
  }catch(error){if(body)body.innerHTML=`<tr><td colspan="5" class="muted">${esc(error.message)}</td></tr>`}
}
async function fetchReport(target,kind='investigate'){
  target=String(target||'').trim();if(!target)throw new Error('Enter a target IP.');
  const report=await api(`/api/v1/operator/${kind}/${encodeURIComponent(target)}`);lastReport=report;return report;
}
function assessmentLabel(value){return String(value||'OBSERVED').replaceAll('_',' ')}
async function runInvestigation(target){
  const assessment=O('investigationAssessment');if(assessment)assessment.textContent='Correlating current-session evidence…';
  try{
    const report=await fetchReport(target,'investigate');O('investigationTarget').value=report.target||target;O('forensicsTarget').value=report.target||target;
    const summary=report.summary||{},risk=report.risk||{},score=risk.score;
    O('investigationStats').innerHTML=stat('Target',report.target||'—')+stat('Observed',report.observed?'YES':'NO')+stat('Assessment',assessmentLabel(risk.assessment))+stat('Risk',score===null||score===undefined?'NO SCORE':`${Number(score)}/100`)+stat('Flows',summary.flow_count||0)+stat('Peers',summary.peer_count||0);
    const reasons=risk.reasons||[];
    O('investigationAssessment').innerHTML=`<div class="operator-row"><span class="operator-badge">${esc(assessmentLabel(risk.assessment))}</span>${report.observed?'Assessment is derived only from current-session evidence.':'MON has no evidence that this target participated in the current session; no safety or risk verdict is produced.'}</div>`+(reasons.length?reasons.map(reason=>`<div class="operator-reason">${esc(reason)}</div>`).join(''):'<div class="operator-empty">No anomaly evidence is currently associated with this observed target.</div>');
    O('investigationPivots').innerHTML='<div class="label">Top Peers</div>'+rows(summary.top_peers)+ '<div class="label" style="margin-top:10px">Top Services</div>'+rows(summary.top_services)+'<div class="label" style="margin-top:10px">Top Applications</div>'+rows(summary.top_applications)+`<div class="label" style="margin-top:10px">Evidence Counts</div><div class="operator-row">Alerts: ${Number(summary.alert_count||0)} · Incidents: ${Number(summary.incident_count||0)} · Packet-observed flows: ${Number(summary.flow_count||0)}</div>`;
  }catch(error){if(assessment)assessment.textContent=error.message;O('investigationStats').innerHTML='';O('investigationPivots').innerHTML='<div class="operator-empty">No evidence report available.</div>'}
}
async function runForensics(target){
  O('forensicsOutput').textContent='Building passive evidence report…';
  try{
    const report=await fetchReport(target,'forensics');O('forensicsTarget').value=report.target||target;O('investigationTarget').value=report.target||target;
    const asset=report.asset||{},summary=report.summary||{},risk=report.risk||{};
    O('forensicsIdentity').innerHTML=`<div class="operator-row"><b>${esc(report.target||'—')}</b> · ${esc(report.scope||'—')}</div><div class="operator-row">Observed: <b>${report.observed?'YES':'NO'}</b></div><div class="operator-row">Assessment: ${esc(assessmentLabel(risk.assessment))}</div><div class="operator-row">Name: ${esc(asset.hostname||asset.dhcp_hostname||'not observed')}</div><div class="operator-row">Role: ${esc(asset.classification||asset.role||'not classified')}</div><div class="operator-row">MAC: ${esc(asset.mac||asset.mac_address||'not observed')}</div><div class="operator-row">Flow packets: ${Number(summary.packets||0).toLocaleString()}</div>`;
    const alerts=report.alerts||[],incidents=report.incidents||[];
    O('forensicsSecurity').innerHTML=`<div class="operator-row">Alerts: <b>${alerts.length}</b></div><div class="operator-row">Incidents: <b>${incidents.length}</b></div>`+incidents.slice(0,8).map(item=>`<div class="operator-row"><span class="operator-badge">${esc(item.severity||'INFO')}</span>${esc(item.title||item.summary||item.type||'Incident evidence')}</div>`).join('');
    const flows=report.flows||[],edges=report.topology_edges||[];
    O('forensicsRelationships').innerHTML=(flows.slice(0,25).map(flow=>`<div class="operator-row"><b>${esc(flow.src||'?')}</b> → <b>${esc(flow.dst||'?')}</b> · ${esc(flow.protocol||flow.transport||'')} · ${Number(flow.packets||0).toLocaleString()} packets · ${Number(flow.bytes||0).toLocaleString()} bytes</div>`).join('')||'<div class="operator-empty">No packet-observed flows for this target.</div>')+(edges.length?`<div class="label" style="margin-top:12px">Observed Relationships</div>${edges.slice(0,20).map(edge=>`<div class="operator-row">${esc(edge.source||'?')} → ${esc(edge.target||'?')} · ${Number(edge.packets||0).toLocaleString()} packets</div>`).join('')}`:'');
    O('forensicsOutput').textContent=JSON.stringify(report,null,2);
  }catch(error){O('forensicsOutput').textContent=error.message;O('forensicsIdentity').innerHTML='<div class="operator-empty">No report available.</div>';O('forensicsRelationships').innerHTML='<div class="operator-empty">No report available.</div>'}
}
function diagLine(label,value){return`<div><div class="label">${esc(label)}</div><strong>${esc(value??'—')}</strong></div>`}
async function loadWatchdog(){
  try{
    const data=await api('/api/v1/system/watchdog');lastWatchAt=Date.now();const capture=data.capture||{},diagnostics=data.diagnostics||{},anomalies=data.anomalies||{};
    O('watchdogStats').innerHTML=diagLine('State',data.state||'UNKNOWN')+diagLine('Interface',data.interface||'—')+diagLine('Capture',capture.state||'—')+diagLine('TShark PID',capture.process_pid||'—')+diagLine('Activity',capture.traffic_activity||'—')+diagLine('Packets',Number(capture.packets||0).toLocaleString())+diagLine('Problems',diagnostics.problem_count||0)+diagLine('Anomalies',anomalies.count||0);
    const problems=diagnostics.problems||[];
    O('watchdogProblems').innerHTML=problems.length?problems.map(problem=>`<div class="watch-problem attention"><div class="watch-title">${esc(problem.problem||'Runtime problem')}</div><div class="watch-meta">Severity: ${esc(problem.severity||'INFO')}<br>${problem.evidence?`Evidence: ${esc(problem.evidence)}<br>`:''}${problem.cause?`Cause: ${esc(problem.cause)}<br>`:''}${problem.fix?`Fix: ${esc(problem.fix)}<br>`:''}${problem.verify?`Verify: ${esc(problem.verify)}`:''}</div></div>`).join(''):'<div class="watch-ok"><b>No runtime fault detected.</b><br>MON has an active session, selected interface, live TShark process and no failed/degraded stable worker.</div>';
    const top=anomalies.top||[];O('watchdogAnomalies').innerHTML=top.length?top.map(item=>`<div class="operator-row"><span class="operator-badge">${esc(item.severity||'INFO')}</span>${esc(item.kind||'EVENT')} · ${esc(item.title||'Observed anomaly')}</div>`).join(''):'<div class="operator-empty">No current alert/incident evidence.</div>';
  }catch(error){O('watchdogProblems').innerHTML=`<div class="watch-problem attention"><div class="watch-title">Watchdog API unavailable</div><div class="watch-meta">${esc(error.message)}</div></div>`}
}
setInterval(()=>{const active=document.querySelector('.tab.active')?.dataset?.view;if(active==='watchdog'&&Date.now()-lastWatchAt>3500)loadWatchdog();if(active==='investigation'&&Date.now()-lastTargetsAt>7000)loadTargets();},4000);
inject();
})();
</script>
"""
