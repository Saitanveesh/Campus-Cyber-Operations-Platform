from __future__ import annotations


STABLE_OPERATOR_EXTENSION = r"""
<style>
#operatorGate{position:fixed;inset:0;background:rgba(255,255,255,.96);z-index:220;display:none;place-items:center}
#operatorGate.show{display:grid}.operator-login{width:min(430px,92vw);border:2px solid #111;background:#fff;padding:22px}.operator-login h2{font-size:16px;margin-bottom:14px}.operator-login input{width:100%;height:38px;border:1px solid #999;margin:5px 0 10px;padding:0 10px}.operator-login .warning{font-size:10px;line-height:1.45;border-left:3px solid #111;padding:8px 10px;margin:12px 0}
.operator-shell{max-width:1500px;margin:0 auto}.operator-targetbar{display:grid;grid-template-columns:minmax(240px,430px) auto auto;gap:8px;margin:12px 0}.operator-targetbar input{height:35px;border:1px solid #999;padding:0 10px;font:12px Consolas,monospace}.operator-hero{display:grid;grid-template-columns:repeat(6,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:14px 0}.operator-hero>div{padding:11px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:68px}.operator-hero strong{display:block;font-size:17px;margin-top:5px}.operator-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.operator-panel{border:1px solid #c7c7c7;padding:13px;min-width:0}.operator-row{padding:8px 0;border-bottom:1px solid #ddd;font-size:10px;line-height:1.5}.operator-row:last-child{border-bottom:0}.operator-output{border:1px solid #c7c7c7;min-height:180px;max-height:460px;overflow:auto;padding:12px;white-space:pre-wrap;font:10px/1.5 Consolas,monospace;background:#fff}.operator-table{max-height:470px}.operator-badge{display:inline-block;border:1px solid #111;padding:3px 6px;font-size:9px;font-weight:700;margin-right:5px}.operator-empty{font-size:10px;color:#666;padding:10px 0}.operator-list{max-height:340px;overflow:auto}.operator-muted{color:#666}.operator-reason{border-left:2px solid #111;padding:5px 8px;margin:5px 0;font-size:10px}.operator-auth-state{font-size:9px;letter-spacing:.08em;color:#555;margin-left:8px}
@media(max-width:1050px){.operator-grid{grid-template-columns:1fr}.operator-hero{grid-template-columns:repeat(3,1fr)}.operator-targetbar{grid-template-columns:1fr}}
@media(max-width:650px){.operator-hero{grid-template-columns:1fr 1fr}}
</style>
<div id="operatorGate">
  <div class="operator-login">
    <h2>Operator Access</h2>
    <div class="label">Operator ID</div><input id="operatorUser" autocomplete="username" value="admin">
    <div class="label">Password</div><input id="operatorPass" type="password" autocomplete="current-password">
    <div class="warning">Investigation and Forensics are protected local-console workspaces. Stable MON does not expose active probing, remote access or containment controls here.</div>
    <div class="toolbar"><button class="btn" id="operatorLoginBtn">Sign In</button><button class="btn" id="operatorCancelBtn">Cancel</button></div>
    <div class="message" id="operatorLoginMessage"></div>
  </div>
</div>
<script>
(()=>{
const O=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let token=sessionStorage.getItem('campusOpsOperatorToken')||'',pending='',lastReport=null;
function headers(){return token?{'X-Campus-Admin':token}:{}}
async function api(path,options={}){
  options.headers={...(options.headers||{}),...headers()};
  const response=await fetch(path,{cache:'no-store',...options});
  const data=await response.json().catch(()=>({}));
  if(response.status===401){clearSession();showLogin();throw new Error('Operator session expired. Sign in again.')}
  if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||data));
  return data;
}
function clearSession(){token='';sessionStorage.removeItem('campusOpsOperatorToken');updateAuthState()}
function showLogin(){O('operatorGate')?.classList.add('show');setTimeout(()=>O('operatorPass')?.focus(),30)}
function closeLogin(){O('operatorGate')?.classList.remove('show');if(O('operatorPass'))O('operatorPass').value=''}
function updateAuthState(){document.querySelectorAll('[data-operator-auth]').forEach(x=>x.textContent=token?'PROTECTED SESSION ACTIVE':'SIGN-IN REQUIRED')}
function openProtected(view){
  if(token){pending='';setView(view);return}
  pending=view;showLogin();
}
async function login(){
  const message=O('operatorLoginMessage');message.textContent='Signing in…';
  try{
    const response=await fetch('/api/v1/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:O('operatorUser').value,password:O('operatorPass').value})});
    const data=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(data.detail||'Login failed');
    token=String(data.token||'');
    sessionStorage.setItem('campusOpsOperatorToken',token);
    message.textContent='';closeLogin();updateAuthState();
    await loadTargets();
    if(pending){const view=pending;pending='';setView(view)}
  }catch(error){message.textContent=error.message}
}
async function logout(){
  if(token){try{await api('/api/v1/admin/logout',{method:'POST'})}catch{}}
  clearSession();lastReport=null;setView('overview');
}
function inject(){
  if(O('view-investigation'))return;
  const nav=document.querySelector('nav'),main=document.querySelector('main'),system=nav?.querySelector('button.tab[data-view="system"]'),foot=main?.querySelector('.foot');
  if(!nav||!main)return;
  try{
    pages.investigation=['Investigation','Protected passive pivots across current-session evidence.'];
    pages.forensics=['Forensics','Evidence-centered report for an observed target.'];
  }catch{}
  for(const [view,label] of [['investigation','Investigation'],['forensics','Forensics']]){
    const button=document.createElement('button');button.className='tab';button.dataset.view=view;button.textContent=label;button.onclick=()=>openProtected(view);nav.insertBefore(button,system||null);
  }
  const holder=document.createElement('div');
  holder.innerHTML=`
  <div class="view" id="view-investigation"><section class="operator-shell"><div class="sectionhead"><div><h2>Investigation Workspace</h2><div class="small">Select an observed IP and pivot through current-session evidence without generating network traffic.<span class="operator-auth-state" data-operator-auth></span></div></div><button class="btn" data-operator-logout>Logout</button></div><div class="operator-targetbar"><input id="investigationTarget" placeholder="Observed target IP"><button class="btn" id="investigationRun">Investigate</button><button class="btn" id="investigationRefresh">Refresh Targets</button></div><div class="operator-hero" id="investigationStats"></div><div class="operator-grid"><div class="operator-panel"><div class="label">Assessment</div><div id="investigationAssessment" class="operator-empty">Choose an observed target.</div></div><div class="operator-panel"><div class="label">Evidence Pivots</div><div id="investigationPivots" class="operator-empty">No target selected.</div></div></div><div class="operator-panel" style="margin-top:14px"><div class="label">Observed Targets</div><div class="tablewrap operator-table"><table><thead><tr><th>IP</th><th>Name</th><th>Class</th><th>Packets</th><th>Managed</th><th>Action</th></tr></thead><tbody id="investigationTargets"><tr><td colspan="6" class="muted">Sign in to load targets.</td></tr></tbody></table></div></div></section></div>
  <div class="view" id="view-forensics"><section class="operator-shell"><div class="sectionhead"><div><h2>Forensics Workbench</h2><div class="small">Passive evidence correlation for one target. No active probe is available in stable mode.<span class="operator-auth-state" data-operator-auth></span></div></div><button class="btn" data-operator-logout>Logout</button></div><div class="operator-targetbar"><input id="forensicsTarget" placeholder="Observed target IP"><button class="btn" id="forensicsRun">Build Report</button><button class="btn" id="forensicsUseInvestigation">Use Investigation Target</button></div><div class="operator-grid"><div class="operator-panel"><div class="label">Identity / Asset Evidence</div><div id="forensicsIdentity" class="operator-empty">Choose an observed target.</div><div class="label" style="margin-top:14px">Alerts / Incidents</div><div id="forensicsSecurity" class="operator-empty">No report loaded.</div></div><div class="operator-panel"><div class="label">Flows / Relationships</div><div id="forensicsRelationships" class="operator-list"><div class="operator-empty">No report loaded.</div></div></div></div><div class="operator-panel" style="margin-top:14px"><div class="label">Evidence Record</div><pre id="forensicsOutput" class="operator-output">No passive report has been built.</pre></div></section></div>`;
  while(holder.firstChild)main.insertBefore(holder.firstChild,foot||null);
  O('investigationRun').onclick=()=>runInvestigation(O('investigationTarget').value);
  O('investigationRefresh').onclick=loadTargets;
  O('forensicsRun').onclick=()=>runForensics(O('forensicsTarget').value);
  O('forensicsUseInvestigation').onclick=()=>{const value=O('investigationTarget').value.trim();O('forensicsTarget').value=value;if(value)runForensics(value)};
  document.querySelectorAll('[data-operator-logout]').forEach(button=>button.onclick=logout);
  updateAuthState();
}
function stat(label,value){return`<div><div class="label">${esc(label)}</div><strong>${esc(value)}</strong></div>`}
function rows(values,empty='None observed'){
  if(!values||!values.length)return`<div class="operator-empty">${esc(empty)}</div>`;
  return values.map(value=>`<div class="operator-row">${esc(Array.isArray(value)?`${value[0]} · ${value[1]}`:value)}</div>`).join('');
}
async function loadTargets(){
  if(!token){updateAuthState();return}
  const body=O('investigationTargets');if(body)body.innerHTML='<tr><td colspan="6" class="muted">Loading…</td></tr>';
  try{
    const data=await api('/api/v1/admin/targets');const targets=data.targets||[];
    if(body)body.innerHTML=targets.map(item=>`<tr><td class="mono">${esc(item.ip)}</td><td>${esc(item.name||'—')}</td><td>${esc(item.classification||'—')}</td><td>${Number(item.packets||0).toLocaleString()}</td><td>${item.managed?'YES':'NO'}</td><td><button class="btn" data-investigate-target="${esc(item.ip)}">Investigate</button></td></tr>`).join('')||'<tr><td colspan="6" class="muted">No observed targets in the current session.</td></tr>';
    body?.querySelectorAll('[data-investigate-target]').forEach(button=>button.onclick=()=>{const target=button.dataset.investigateTarget||'';O('investigationTarget').value=target;runInvestigation(target)});
  }catch(error){if(body)body.innerHTML=`<tr><td colspan="6" class="muted">${esc(error.message)}</td></tr>`}
}
async function fetchReport(target){
  target=String(target||'').trim();if(!target)throw new Error('Enter a target IP.');
  const report=await api(`/api/v1/admin/forensics/${encodeURIComponent(target)}`);lastReport=report;return report;
}
async function runInvestigation(target){
  if(!token){pending='investigation';showLogin();return}
  const assessment=O('investigationAssessment');if(assessment)assessment.textContent='Building passive investigation…';
  try{
    const report=await fetchReport(target);O('investigationTarget').value=report.target||target;O('forensicsTarget').value=report.target||target;
    const summary=report.summary||{},risk=report.risk||{};
    O('investigationStats').innerHTML=stat('Target',report.target||'—')+stat('Assessment',risk.assessment||'—')+stat('Risk',`${Number(risk.score||0)}/100`)+stat('Flows',summary.flow_count||0)+stat('Peers',summary.peer_count||0)+stat('Alerts',summary.alert_count||0);
    const reasons=risk.reasons||[];
    O('investigationAssessment').innerHTML=`<div class="operator-row"><span class="operator-badge">${esc(risk.assessment||'OBSERVED')}</span> Evidence-based priority, not a maliciousness verdict.</div>`+(reasons.length?reasons.map(reason=>`<div class="operator-reason">${esc(reason)}</div>`).join(''):'<div class="operator-empty">No strong current indicators were derived from the active-session evidence.</div>');
    O('investigationPivots').innerHTML='<div class="label">Top Peers</div>'+rows(summary.top_peers)+ '<div class="label" style="margin-top:10px">Top Services</div>'+rows(summary.top_services)+'<div class="label" style="margin-top:10px">Top Applications</div>'+rows(summary.top_applications);
  }catch(error){if(assessment)assessment.textContent=error.message}
}
function compact(value){return JSON.stringify(value??null,null,2)}
async function runForensics(target){
  if(!token){pending='forensics';showLogin();return}
  O('forensicsOutput').textContent='Building passive forensic report…';
  try{
    const report=await fetchReport(target);O('forensicsTarget').value=report.target||target;O('investigationTarget').value=report.target||target;
    const asset=report.asset||{},summary=report.summary||{};
    O('forensicsIdentity').innerHTML=`<div class="operator-row"><b>${esc(report.target||'—')}</b> · ${esc(report.scope||'—')}</div><div class="operator-row">Name: ${esc(asset.hostname||asset.dhcp_hostname||'not observed')}</div><div class="operator-row">Role: ${esc(asset.classification||asset.role||'not classified')}</div><div class="operator-row">MAC: ${esc(asset.mac||asset.mac_address||'not observed')}</div><div class="operator-row">Current-session packets: ${Number(summary.packets||0).toLocaleString()}</div>`;
    const alerts=report.alerts||[],incidents=report.incidents||[];
    O('forensicsSecurity').innerHTML=`<div class="operator-row">Alerts: <b>${alerts.length}</b></div><div class="operator-row">Incidents: <b>${incidents.length}</b></div>`+incidents.slice(0,8).map(item=>`<div class="operator-row"><span class="operator-badge">${esc(item.severity||'INFO')}</span>${esc(item.title||item.summary||item.type||'Incident evidence')}</div>`).join('');
    const flows=report.flows||[],edges=report.topology_edges||[];
    O('forensicsRelationships').innerHTML=(flows.slice(0,18).map(flow=>`<div class="operator-row"><b>${esc(flow.src||'?')}</b> → <b>${esc(flow.dst||'?')}</b> · ${esc(flow.protocol||flow.transport||'')} · ${Number(flow.packets||0).toLocaleString()} packets</div>`).join('')||'<div class="operator-empty">No packet-observed flows for this target.</div>')+(edges.length?`<div class="label" style="margin-top:12px">Observed Relationships</div>${edges.slice(0,12).map(edge=>`<div class="operator-row">${esc(edge.source||'?')} ↔ ${esc(edge.target||'?')} · ${Number(edge.packets||0).toLocaleString()} packets</div>`).join('')}`:'');
    O('forensicsOutput').textContent=compact(report);
  }catch(error){O('forensicsOutput').textContent=error.message}
}
O('operatorLoginBtn').onclick=login;O('operatorCancelBtn').onclick=()=>{pending='';closeLogin()};O('operatorPass').addEventListener('keydown',event=>{if(event.key==='Enter')login()});
inject();
setInterval(()=>{if(token&&document.querySelector('.tab.active')?.dataset?.view==='investigation')loadTargets()},10000);
})();
</script>
"""
