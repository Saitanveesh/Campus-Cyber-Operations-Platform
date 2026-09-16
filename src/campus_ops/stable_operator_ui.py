from __future__ import annotations


STABLE_OPERATOR_EXTENSION = r"""
<style>
.operator-shell{max-width:1500px;margin:0 auto}.operator-targetbar{display:grid;grid-template-columns:minmax(240px,430px) auto auto;gap:8px;margin:12px 0}.operator-targetbar input{height:35px;border:1px solid #999;padding:0 10px;font:12px Consolas,monospace}.operator-hero{display:grid;grid-template-columns:repeat(6,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:14px 0}.operator-hero>div{padding:11px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:68px}.operator-hero strong{display:block;font-size:17px;margin-top:5px}.operator-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.operator-panel{border:1px solid #c7c7c7;padding:13px;min-width:0}.operator-row{padding:8px 0;border-bottom:1px solid #ddd;font-size:10px;line-height:1.5}.operator-row:last-child{border-bottom:0}.operator-table{max-height:470px}.operator-badge{display:inline-block;border:1px solid #111;padding:3px 6px;font-size:9px;font-weight:700;margin-right:5px}.operator-empty{font-size:10px;color:#666;padding:10px 0}.operator-reason{border-left:2px solid #111;padding:5px 8px;margin:5px 0;font-size:10px}.watch-grid{display:grid;grid-template-columns:repeat(5,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:14px 0}.watch-grid>div{padding:12px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:72px}.watch-grid strong{display:block;font-size:18px;margin-top:6px}.watch-problem{border:1px solid #c7c7c7;padding:12px;margin-bottom:9px}.watch-problem.attention{border-left:4px solid #111}.watch-problem .watch-title{font-weight:800;font-size:12px}.watch-meta{font-size:10px;line-height:1.55;margin-top:7px;color:#333}.watch-ok{border:1px solid #c7c7c7;padding:14px;font-size:11px;line-height:1.55}.truth-strip{border:1px solid #c7c7c7;padding:10px 12px;font-size:10px;line-height:1.5;margin:10px 0}.truth-strip b{font-weight:800}
@media(max-width:1050px){.operator-grid{grid-template-columns:1fr}.operator-hero{grid-template-columns:repeat(3,1fr)}.operator-targetbar{grid-template-columns:1fr}.watch-grid{grid-template-columns:1fr 1fr}}
@media(max-width:650px){.operator-hero,.watch-grid{grid-template-columns:1fr 1fr}}
</style>
<script>
(()=>{
const O=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let lastTargetsAt=0,lastWatchAt=0;
async function api(path){const response=await fetch(path,{cache:'no-store'});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||data));return data;}
function inject(){
  if(O('view-investigation'))return;
  const nav=document.querySelector('nav'),main=document.querySelector('main'),system=nav?.querySelector('button.tab[data-view="system"]'),foot=main?.querySelector('.foot');
  if(!nav||!main)return;
  try{pages.investigation=['Investigation','Investigate only IPs proven by the current TShark packet stream.'];pages.watchdog=['Watchdog','Live Windows adapter, TShark/Npcap and analysis-pipeline supervision.'];}catch{}
  for(const [view,label] of [['investigation','Investigation'],['watchdog','Watchdog']]){
    const button=document.createElement('button');button.className='tab';button.dataset.view=view;button.textContent=label;
    button.onclick=()=>{setView(view);if(view==='investigation')loadTargets();if(view==='watchdog')loadWatchdog();};
    nav.insertBefore(button,system||null);
  }
  const holder=document.createElement('div');
  holder.innerHTML=`
  <div class="view" id="view-investigation"><section class="operator-shell"><div class="sectionhead"><div><h2>Investigation</h2><div class="small">MON does not scan or invent hosts. A target must already exist in the current packet evidence before an investigation is produced.</div></div></div><div class="truth-strip"><b>REAL-IP CONTRACT:</b> target list = current-session TShark assets/flows/topology only. An unseen IP is rejected instead of receiving a green or fake result.</div><div class="operator-targetbar"><input id="investigationTarget" placeholder="Observed target IP"><button class="btn" id="investigationRun">Investigate</button><button class="btn" id="investigationRefresh">Refresh Real Targets</button></div><div class="operator-hero" id="investigationStats"></div><div class="operator-grid"><div class="operator-panel"><div class="label">Assessment</div><div id="investigationAssessment" class="operator-empty">Choose a real observed target below.</div></div><div class="operator-panel"><div class="label">Evidence Pivots</div><div id="investigationPivots" class="operator-empty">No target selected.</div></div></div><div class="operator-panel" style="margin-top:14px"><div class="label">Real Observed Targets</div><div class="tablewrap operator-table"><table><thead><tr><th>IP</th><th>Name</th><th>Class</th><th>Evidence</th><th>Packets</th><th>Action</th></tr></thead><tbody id="investigationTargets"><tr><td colspan="6" class="muted">Loading current packet evidence…</td></tr></tbody></table></div></div></section></div>
  <div class="view" id="view-watchdog"><section class="operator-shell"><div class="sectionhead"><div><h2>MON Watchdog</h2><div class="small">Supervises the native Windows adapter, session, TShark/Npcap process and analysis workers. Quiet traffic is not a capture failure.</div></div><button class="btn" id="watchdogRefresh">Refresh</button></div><div class="watch-grid" id="watchdogStats"></div><div class="operator-grid"><div class="operator-panel"><div class="label">Runtime Diagnostics</div><div id="watchdogProblems" class="operator-empty">Loading diagnostics…</div></div><div class="operator-panel"><div class="label">Current Security Anomalies</div><div id="watchdogAnomalies" class="operator-empty">Loading anomalies…</div></div></div></section></div>`;
  while(holder.firstChild)main.insertBefore(holder.firstChild,foot||null);
  O('investigationRun').onclick=()=>runInvestigation(O('investigationTarget').value);
  O('investigationTarget').addEventListener('keydown',e=>{if(e.key==='Enter')runInvestigation(e.currentTarget.value)});
  O('investigationRefresh').onclick=()=>loadTargets(true);
  O('watchdogRefresh').onclick=loadWatchdog;
  window.openInvestigation=target=>{target=String(target||'').trim();if(target)O('investigationTarget').value=target;setView('investigation');loadTargets();if(target)runInvestigation(target);};
  loadTargets();
}
function stat(label,value){return`<div><div class="label">${esc(label)}</div><strong>${esc(value)}</strong></div>`}
function rows(values,empty='None observed'){
  if(!values||!values.length)return`<div class="operator-empty">${esc(empty)}</div>`;
  return values.map(value=>`<div class="operator-row">${esc(Array.isArray(value)?`${value[0]} · ${value[1]}`:value)}</div>`).join('');
}
async function loadTargets(force=false){
  if(!force&&Date.now()-lastTargetsAt<2500)return;
  const body=O('investigationTargets');if(body)body.innerHTML='<tr><td colspan="6" class="muted">Loading…</td></tr>';
  try{
    const data=await api('/api/v1/operator/targets');const targets=data.targets||[];lastTargetsAt=Date.now();
    if(body)body.innerHTML=targets.map(item=>`<tr><td class="mono">${esc(item.ip)}</td><td>${esc(item.name||'—')}</td><td>${esc(item.classification||'—')}</td><td>${esc(item.evidence||'PACKET')}</td><td>${Number(item.packets||0).toLocaleString()}</td><td><button class="btn" data-investigate-target="${esc(item.ip)}">Investigate</button></td></tr>`).join('')||'<tr><td colspan="6" class="muted">No real packet-observed IP targets yet. Generate normal network traffic and refresh.</td></tr>';
    body?.querySelectorAll('[data-investigate-target]').forEach(button=>button.onclick=()=>window.openInvestigation(button.dataset.investigateTarget||''));
  }catch(error){if(body)body.innerHTML=`<tr><td colspan="6" class="muted">${esc(error.message)}</td></tr>`}
}
function assessmentLabel(value){return String(value||'OBSERVED').replaceAll('_',' ')}
async function runInvestigation(target){
  target=String(target||'').trim();if(!target)return;
  const assessment=O('investigationAssessment');if(assessment)assessment.textContent='Correlating current-session packet evidence…';
  try{
    const report=await api(`/api/v1/operator/investigate/${encodeURIComponent(target)}`);O('investigationTarget').value=report.target||target;
    const summary=report.summary||{},risk=report.risk||{},score=risk.score,asset=report.asset||{};
    O('investigationStats').innerHTML=stat('Target',report.target||'—')+stat('Observed','YES')+stat('Role',asset.classification||asset.role||'PACKET PEER')+stat('Priority',assessmentLabel(risk.assessment))+stat('Flows',summary.flow_count||0)+stat('Peers',summary.peer_count||0);
    const reasons=risk.reasons||[];
    O('investigationAssessment').innerHTML=`<div class="operator-row"><span class="operator-badge">${esc(assessmentLabel(risk.assessment))}</span>Current-session evidence only${score===null||score===undefined?'':` · priority ${Number(score)}/100`}.</div>`+(reasons.length?reasons.map(reason=>`<div class="operator-reason">${esc(reason)}</div>`).join(''):'<div class="operator-empty">Target is real/observed, but no current anomaly evidence is associated with it.</div>');
    O('investigationPivots').innerHTML='<div class="label">Top Peers</div>'+rows(summary.top_peers)+ '<div class="label" style="margin-top:10px">Top Services</div>'+rows(summary.top_services)+'<div class="label" style="margin-top:10px">Top Applications</div>'+rows(summary.top_applications)+`<div class="label" style="margin-top:10px">Evidence</div><div class="operator-row">Alerts: ${Number(summary.alert_count||0)} · Incidents: ${Number(summary.incident_count||0)} · Packet-observed flows: ${Number(summary.flow_count||0)}</div>`;
  }catch(error){if(assessment)assessment.innerHTML=`<div class="operator-reason"><b>NOT ACCEPTED</b><br>${esc(error.message)}</div>`;O('investigationStats').innerHTML='';O('investigationPivots').innerHTML='<div class="operator-empty">No investigation was fabricated for this IP.</div>'}
}
async function loadWatchdog(){
  try{
    const data=await api('/api/v1/system/watchdog');lastWatchAt=Date.now();const cap=data.capture||{},diag=data.diagnostics||{};
    O('watchdogStats').innerHTML=stat('State',data.state||'UNKNOWN')+stat('Adapter',data.interface||'NONE')+stat('Capture',cap.state||'UNKNOWN')+stat('TShark PID',cap.process_pid||'NONE')+stat('Packets',Number(cap.packets||0).toLocaleString());
    const problems=diag.problems||[];O('watchdogProblems').innerHTML=problems.length?problems.map(p=>`<div class="watch-problem attention"><div class="watch-title">${esc(p.problem||'Problem')} · ${esc(p.severity||'INFO')}</div><div class="watch-meta"><b>Evidence:</b> ${esc(p.evidence||'—')}<br><b>Cause:</b> ${esc(p.cause||'—')}<br><b>Fix:</b> ${esc(p.fix||'—')}<br><b>Verify:</b> ${esc(p.verify||'—')}</div></div>`).join(''):'<div class="watch-ok"><b>Runtime healthy.</b><br>Windows adapter, session and managed TShark process satisfy the watchdog checks.</div>';
    const anomalies=data.anomalies?.top||[];O('watchdogAnomalies').innerHTML=anomalies.length?anomalies.map(a=>`<div class="operator-row"><span class="operator-badge">${esc(a.severity||'INFO')}</span>${esc(a.kind||'EVENT')} · ${esc(a.title||'Observed anomaly')}</div>`).join(''):'<div class="watch-ok">No current packet-derived security anomaly.</div>';
  }catch(error){O('watchdogProblems').innerHTML=`<div class="watch-problem attention"><div class="watch-title">Watchdog API unavailable</div><div class="watch-meta">${esc(error.message)}</div></div>`;}
}
setInterval(()=>{const view=document.querySelector('.tab.active')?.dataset?.view;if(view==='investigation'&&Date.now()-lastTargetsAt>5000)loadTargets();if(view==='watchdog'&&Date.now()-lastWatchAt>3500)loadWatchdog();},4000);
inject();
})();
</script>
"""
