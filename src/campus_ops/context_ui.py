CONTEXT_EXTENSION = r"""
<style>
.context-incident-grid{display:grid;grid-template-columns:220px 1fr;gap:16px}
.context-incident-summary{border:1px solid #c7c7c7;padding:14px;min-height:150px}
.context-incident-evidence{border:1px solid #c7c7c7;padding:14px;min-height:150px}
.context-incident-title{font-size:18px;font-weight:800;line-height:1.2;margin:7px 0 10px}
.context-incident-line{font-size:10px;line-height:1.55;margin-top:4px}
.context-incident-timeline{margin-top:10px;border-top:1px solid #ddd}
.context-incident-timeline>div{padding:7px 0;border-bottom:1px solid #ddd;font-size:10px}
@media(max-width:900px){.context-incident-grid{grid-template-columns:1fr}}
</style>
<script>
(()=>{
const C=id=>document.getElementById(id);
const ce=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let lastView='overview',contextTimer=null,lastRequestedAt=0,lastContextText='';

function activeView(){return document.querySelector('.tab.active')?.dataset?.view||'overview';}
function browserVoice(text){
  if(!text||!('speechSynthesis' in window)||!('SpeechSynthesisUtterance' in window))return;
  try{window.speechSynthesis.cancel();const u=new SpeechSynthesisUtterance(text);u.rate=1;u.volume=1;window.speechSynthesis.speak(u);}catch{}
}
async function contextualBrief(view,force=false){
  const now=Date.now();if(!force&&now-lastRequestedAt<900)return;lastRequestedAt=now;
  try{
    const r=await fetch(`/api/v1/system/assistant/context/${encodeURIComponent(view)}`,{method:'POST'});
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Context briefing failed');
    lastContextText=d.text||'';
    const transcript=C('assistantTranscript');if(transcript)transcript.textContent=lastContextText;
    const msg=C('assistantMessage');if(msg)msg.textContent=`${view.toUpperCase()} briefing`;
    const systemMsg=C('assistantSystemMessage');if(systemMsg)systemMsg.textContent=lastContextText;
    if(!d.queued&&!d.muted)browserVoice(lastContextText);
  }catch(e){const msg=C('assistantMessage');if(msg)msg.textContent=e.message;}
}
function scheduleContext(view){
  clearTimeout(contextTimer);
  contextTimer=setTimeout(()=>contextualBrief(view),260);
}
function observeNavigation(){
  const tabs=[...document.querySelectorAll('.tab')];if(!tabs.length)return;
  lastView=activeView();
  const observer=new MutationObserver(()=>{const view=activeView();if(view!==lastView){lastView=view;scheduleContext(view);}});
  tabs.forEach(tab=>observer.observe(tab,{attributes:true,attributeFilter:['class']}));
}
function wireBriefButtons(){
  for(const id of ['assistantBrief','assistantBrief2']){const button=C(id);if(button)button.onclick=()=>contextualBrief(activeView(),true);}
}
function currentData(){try{return typeof snapshot==='object'&&snapshot?snapshot:{}}catch{return {}};}
function severityRank(v){return {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0}[String(v||'INFO').toUpperCase()]||0;}
function topIncident(){
  const d=currentData(),items=((d.live||{}).incidents||[]).filter(i=>String(i.status||'OPEN').toUpperCase()!=='CLOSED');
  return items.sort((a,b)=>severityRank(b.severity)-severityRank(a.severity)||Number(b.confidence||0)-Number(a.confidence||0)||String(b.last_seen||'').localeCompare(String(a.last_seen||'')))[0]||null;
}
function evidenceText(e){
  if(!e||typeof e!=='object')return 'No structured evidence attached.';
  const skip=new Set(['raw','payload','voice']);
  const rows=Object.entries(e).filter(([k,v])=>!skip.has(k)&&v!==null&&v!==''&&typeof v!=='object').slice(0,14);
  return rows.map(([k,v])=>`<div class="context-incident-line"><b>${ce(k.replaceAll('_',' '))}</b>: ${ce(v)}</div>`).join('')||'No structured evidence attached.';
}
function injectIncidentPanel(){
  const security=C('view-security');if(!security||C('contextIncidentPanel'))return;
  const section=document.createElement('section');section.id='contextIncidentPanel';
  section.innerHTML='<div class="sectionhead"><h2>Active Incident Detail</h2><div class="toolbar"><button class="btn" id="speakIncident">Speak Current Incident</button></div></div><div class="context-incident-grid"><div class="context-incident-summary" id="contextIncidentSummary"></div><div class="context-incident-evidence" id="contextIncidentEvidence"></div></div>';
  security.insertBefore(section,security.firstChild);
  C('speakIncident').onclick=()=>contextualBrief('security',true);
}
function renderIncidentPanel(){
  injectIncidentPanel();const summary=C('contextIncidentSummary'),evidence=C('contextIncidentEvidence');if(!summary||!evidence)return;
  const incident=topIncident();
  if(!incident){summary.innerHTML='<div class="label">Current Status</div><div class="context-incident-title">No open incidents</div><div class="context-incident-line">The correlation engine has no active incident requiring operator action.</div>';evidence.innerHTML='<div class="label">Evidence</div><div class="context-incident-line">No incident evidence to display.</div>';return;}
  summary.innerHTML=`<div class="label">Highest Priority</div><div class="context-incident-title">${ce(incident.title||'Incident')}</div><div class="context-incident-line"><b>Severity:</b> ${ce(incident.severity||'—')}</div><div class="context-incident-line"><b>Status:</b> ${ce(incident.status||'OPEN')}</div><div class="context-incident-line"><b>Source:</b> ${ce(incident.source||'—')}</div><div class="context-incident-line"><b>Confidence:</b> ${ce(incident.confidence||0)}%</div><div class="context-incident-line"><b>Correlated alerts:</b> ${ce(incident.alert_count||0)}</div>`;
  const timeline=(incident.timeline||[]).slice(-5).reverse();
  evidence.innerHTML=`<div class="label">Latest Evidence</div>${evidenceText(incident.latest_evidence)}<div class="context-incident-timeline">${timeline.map(t=>`<div><b>${ce(t.severity||'')} · ${ce(t.title||'')}</b><br>${ce(t.timestamp?new Date(t.timestamp).toLocaleTimeString():'')}</div>`).join('')}</div>`;
}
function preserveContextTranscript(){
  if(!lastContextText)return;
  const transcript=C('assistantTranscript');if(transcript&&activeView()!=='overview')transcript.textContent=lastContextText;
}
setTimeout(()=>{observeNavigation();wireBriefButtons();injectIncidentPanel();renderIncidentPanel();},80);
setInterval(()=>{wireBriefButtons();renderIncidentPanel();preserveContextTranscript();},1000);
window.contextualOperationsBrief=contextualBrief;
})();
</script>
"""
