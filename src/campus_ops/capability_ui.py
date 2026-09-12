CAPABILITY_EXTENSION = r"""
<style>
.capability-shell{max-width:1500px;margin-left:auto;margin-right:auto}
.capability-score{display:grid;grid-template-columns:170px 1fr 1fr 1fr;border:1px solid #c7c7c7;margin-bottom:14px}
.capability-score>div{padding:13px;border-right:1px solid #c7c7c7}.capability-score>div:last-child{border-right:0}
.capability-score strong{display:block;font-size:22px;margin-top:5px}
.capability-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.capability-card{border:1px solid #c7c7c7;padding:12px;min-height:118px}
.capability-card.core{border-left:4px solid #111}
.capability-head{display:flex;justify-content:space-between;gap:10px;align-items:start}
.capability-head strong{font-size:12px}.capability-state{font:700 9px Arial,Helvetica,sans-serif;letter-spacing:.08em;border:1px solid #111;padding:3px 6px}
.capability-meta{font-size:9px;letter-spacing:.11em;color:#666;margin-top:4px}.capability-purpose{font-size:10px;line-height:1.45;margin-top:8px}
.capability-missing{font-size:9px;color:#555;margin-top:7px;line-height:1.45}
.capability-gap{padding:8px 0;border-bottom:1px solid #ddd;font-size:10px}.capability-gap:last-child{border-bottom:0}
.diagnostic-grid{display:flex;gap:7px;flex-wrap:wrap;margin:9px 0 12px}
.diagnostic-output{border:1px solid #c7c7c7;background:#fff;min-height:150px;max-height:350px;overflow:auto;padding:12px;white-space:pre-wrap;font:10px/1.45 Consolas,Monaco,monospace}
.host-security-grid{display:grid;grid-template-columns:repeat(4,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin-bottom:12px}
.host-security-cell{padding:11px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:70px}.host-security-cell strong{display:block;font-size:16px;margin-top:6px}
.host-security-detail{border:1px solid #c7c7c7;padding:12px;font-size:10px;line-height:1.55;min-height:92px}
@media(max-width:950px){.capability-score{grid-template-columns:1fr 1fr}.capability-score>div:nth-child(2){border-right:0}.capability-grid{grid-template-columns:1fr}.host-security-grid{grid-template-columns:1fr 1fr}}
</style>
<script>
(()=>{
const K=id=>document.getElementById(id);
const he=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let capabilityData=null;

function injectCapabilityCenter(){
  const system=K('view-system');if(!system||K('capabilityCenter'))return;
  const section=document.createElement('section');section.id='capabilityCenter';section.className='capability-shell';
  section.innerHTML='<div class="sectionhead"><div><h2>Capability Center</h2><div class="small">Readiness across visibility, intelligence, endpoint, response and evidence planes.</div></div><button class="btn" id="capabilityRefresh">Refresh</button></div><div class="capability-score" id="capabilityScore"></div><div class="sectionhead"><h2>Monitoring Host Security</h2><div class="note">Read-only Windows Defender, Firewall and Sysmon posture.</div></div><div class="host-security-grid" id="hostSecurityGrid"></div><div class="host-security-detail" id="hostSecurityDetail">Waiting for Windows security telemetry.</div><div class="split" style="margin-top:16px"><div><div class="label" style="margin-bottom:8px">Operational Capabilities</div><div class="capability-grid" id="capabilityGrid"></div></div><div><div class="panel"><div class="label">Highest-value Gaps</div><div id="capabilityGaps" style="margin-top:8px"></div></div><div class="panel" style="margin-top:12px"><div class="label">Read-only Diagnostics</div><div class="diagnostic-grid" id="diagnosticButtons"></div><div id="diagnosticStatus" class="small">Select a diagnostic check.</div><pre class="diagnostic-output" id="diagnosticOutput">No diagnostic has been run.</pre></div></div></div>';
  const anchor=K('watchdogSystem');
  if(anchor&&anchor.parentElement===system)anchor.insertAdjacentElement('afterend',section);else system.insertBefore(section,system.firstChild);
  const refresh=K('capabilityRefresh');if(refresh)refresh.onclick=()=>{loadCapabilities();renderHostSecurity();};
}

function currentSnapshot(){try{return typeof snapshot==='object'&&snapshot?snapshot:{}}catch{return {}};}
function yn(v){return v===true?'ON':v===false?'OFF':'UNKNOWN';}
function renderHostSecurity(){
  injectCapabilityCenter();const live=currentSnapshot().live||{},metrics=live.metrics||{},s=metrics.windows_security||{};
  const grid=K('hostSecurityGrid'),detail=K('hostSecurityDetail');
  if(!s.available){if(grid)grid.innerHTML=[['Defender','UNKNOWN'],['Real-time','UNKNOWN'],['Firewall','UNKNOWN'],['Sysmon','UNKNOWN']].map(x=>`<div class="host-security-cell"><div class="label">${he(x[0])}</div><strong>${he(x[1])}</strong></div>`).join('');if(detail)detail.textContent=s.error||'Windows security telemetry is not available yet.';return;}
  const d=s.defender||{},fw=s.firewall||{},sysmon=s.sysmon||[],enabled=Object.values(fw).filter(v=>v===true).length,total=Object.keys(fw).length,sysmonRunning=sysmon.some(x=>String(x.status||'').toLowerCase()==='running');
  if(grid)grid.innerHTML=[['Defender',yn(d.antivirus_enabled)],['Real-time',yn(d.realtime_enabled)],['Firewall',total?`${enabled} / ${total} ON`:'UNKNOWN'],['Sysmon',sysmon.length?(sysmonRunning?'RUNNING':'STOPPED'):'NOT INSTALLED']].map(x=>`<div class="host-security-cell"><div class="label">${he(x[0])}</div><strong>${he(x[1])}</strong></div>`).join('');
  if(detail){const profiles=Object.entries(fw).map(([name,value])=>`${name}: ${yn(value)}`).join(' · ')||'No firewall profile data';const services=sysmon.map(x=>`${x.name}: ${x.status}`).join(' · ')||'Sysmon not detected';detail.innerHTML=`<b>Behavior monitoring:</b> ${he(yn(d.behavior_monitor_enabled))} &nbsp; <b>IOAV:</b> ${he(yn(d.ioav_enabled))} &nbsp; <b>NIS:</b> ${he(yn(d.nis_enabled))}<br><b>Firewall:</b> ${he(profiles)}<br><b>Sysmon:</b> ${he(services)}<br><b>Defender signature update:</b> ${he(d.signature_updated||'unknown')}`;}
}

function renderCapabilities(d){
  capabilityData=d;injectCapabilityCenter();renderHostSecurity();
  const score=K('capabilityScore');if(score)score.innerHTML=[['Readiness',`${Number(d.score||0)}%`],['Core Ready',`${d.core_ready||0} / ${d.core_total||0}`],['All Ready',`${d.ready||0} / ${d.total||0}`],['Next Priority',d.next_gaps?.[0]?.label||'None']].map(x=>`<div><div class="label">${he(x[0])}</div><strong>${he(x[1])}</strong></div>`).join('');
  const grid=K('capabilityGrid');if(grid)grid.innerHTML=(d.capabilities||[]).map(c=>{const missing=[...(c.missing_tools||[]).map(x=>'tool: '+x),...(c.missing_workers||[]).map(x=>'worker: '+x)];return `<div class="capability-card ${c.priority==='CORE'?'core':''}"><div class="capability-head"><div><strong>${he(c.label)}</strong><div class="capability-meta">${he(c.plane)} · ${he(c.priority)}</div></div><span class="capability-state">${he(c.state)}</span></div><div class="capability-purpose">${he(c.purpose)}</div>${missing.length?`<div class="capability-missing">Missing: ${missing.map(he).join(' · ')}</div>`:'<div class="capability-missing">All current checks are ready.</div>'}</div>`}).join('')||'<div class="muted">No capability data</div>';
  const gaps=K('capabilityGaps');if(gaps)gaps.innerHTML=(d.next_gaps||[]).map((g,i)=>`<div class="capability-gap"><b>${i+1}. ${he(g.label)}</b><div>${he(g.state)} · ${he(g.plane)}</div><div>${he([...(g.missing_tools||[]),...(g.missing_workers||[])].join(' · ')||'Needs validation')}</div></div>`).join('')||'<div class="muted">No capability gaps detected.</div>';
  const buttons=K('diagnosticButtons');if(buttons)buttons.innerHTML=(d.diagnostics||[]).map(x=>`<button class="btn" data-diagnostic="${he(x.key)}" title="${he(x.description)}">${he(x.key.replaceAll('-',' '))}</button>`).join('');
  document.querySelectorAll('[data-diagnostic]').forEach(btn=>btn.onclick=()=>runDiagnostic(btn.dataset.diagnostic));
}

async function loadCapabilities(){
  injectCapabilityCenter();const status=K('diagnosticStatus');if(status)status.textContent='Refreshing capability state...';
  try{const r=await fetch('/api/v1/system/capabilities',{cache:'no-store'}),d=await r.json();if(!r.ok)throw new Error(d.detail||'Capability request failed');renderCapabilities(d);if(status)status.textContent='Capability state refreshed.';}catch(e){if(status)status.textContent=e.message;}
}

async function runDiagnostic(key){
  const status=K('diagnosticStatus'),out=K('diagnosticOutput');if(status)status.textContent=`Running ${key}...`;if(out)out.textContent='Running read-only diagnostic...';
  try{const r=await fetch(`/api/v1/system/diagnostics/${encodeURIComponent(key)}`,{method:'POST'}),d=await r.json();if(!r.ok)throw new Error(d.detail||'Diagnostic failed');if(status)status.textContent=`${d.status} · ${d.tool} · ${d.description}`;if(out)out.textContent=d.output||'No output returned.';}catch(e){if(status)status.textContent='ERROR';if(out)out.textContent=e.message;}
}

injectCapabilityCenter();loadCapabilities();setInterval(()=>{renderHostSecurity();if(document.querySelector('.tab.active')?.dataset?.view==='system')loadCapabilities();},15000);setInterval(renderHostSecurity,2000);
})();
</script>
"""
