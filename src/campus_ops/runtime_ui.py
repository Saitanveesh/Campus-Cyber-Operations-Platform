from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from campus_ops.admin import install_admin_routes
from campus_ops.admin_ui import ADMIN_EXTENSION
from campus_ops.capabilities import install_capability_routes
from campus_ops.capability_ui import CAPABILITY_EXTENSION
from campus_ops.context_assistant import install_context_assistant, page_briefing
from campus_ops.context_ui import CONTEXT_EXTENSION
from campus_ops.investigation import install_investigation_routes
from campus_ops.investigation_ui import INVESTIGATION_EXTENSION
from campus_ops.topology_ui import TOPOLOGY_EXTENSION
from campus_ops.traffic_ui import TRAFFIC_EXTENSION


UI_EXTENSION = r"""
<style>
#opsWatchBadge{position:fixed;right:18px;bottom:16px;z-index:80;border:1px solid #111;background:#fff;color:#111;padding:9px 12px;font:700 10px Arial,Helvetica,sans-serif;letter-spacing:.08em;text-transform:uppercase;box-shadow:0 2px 12px rgba(0,0,0,.12);cursor:pointer}
#opsWatchBadge.attention{border-width:3px}.watch-grid{display:grid;grid-template-columns:repeat(4,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7}.watch-cell{padding:12px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7}.watch-cell strong{display:block;font-size:18px;margin-top:6px}.watch-condition{border-bottom:1px solid #d7d7d7;padding:8px 0}.watch-condition:last-child{border-bottom:0}.watch-condition b{font-size:11px}.watch-condition div{font-size:10px;color:#555;margin-top:3px}.assistant-controls{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.assistant-msg{font-size:11px;color:#333;margin-top:9px;line-height:1.4}.assistant-transcript{border-left:2px solid #111;padding:8px 10px;margin-top:10px;font-size:11px;line-height:1.45;min-height:34px}
@media(max-width:900px){.watch-grid{grid-template-columns:1fr 1fr}#opsWatchBadge{right:8px;bottom:8px}}
</style>
<div id="opsWatchBadge">WATCHDOG · STARTING</div>
<script>
(()=>{
const byId=id=>document.getElementById(id);
let assistantData=null,eventsInitialized=false,seenEvents=new Set(),lastBrowserText='',lastBrowserAt=0;
function esc2(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function cleanCopy(){const pattern=/(evidence-first|black\s*\/\s*white\s*\/\s*grey|authorized cyber-range|current_session_only|live contract)/i;document.querySelectorAll('.product,.subtitle,.note,.foot span').forEach(el=>{if(pattern.test(el.textContent||''))el.textContent='';});}
function injectPanels(){
  const overview=byId('view-overview'),system=byId('view-system');
  if(overview&&!byId('watchdogOverview')){const s=document.createElement('section');s.id='watchdogOverview';s.innerHTML='<div class="sectionhead"><h2>Operations Watch</h2><div class="note">Capture, workers, incidents and response jobs.</div></div><div class="watch-grid" id="watchGrid"></div><div class="equal" style="margin-top:14px"><div class="panel"><div class="label">Active Conditions</div><div id="watchConditions" style="margin-top:8px"></div></div><div class="panel"><div class="label">Operations Assistant</div><div class="assistant-transcript" id="assistantTranscript">Waiting for platform state.</div><div class="assistant-controls"><button class="btn" id="assistantBrief">Brief Current Page</button><button class="btn" id="assistantStop">Stop Voice</button></div><div class="assistant-msg" id="assistantMessage"></div></div></div>';overview.insertBefore(s,overview.firstChild);}
  if(system&&!byId('watchdogSystem')){const s=document.createElement('section');s.id='watchdogSystem';s.innerHTML='<div class="sectionhead"><h2>Watchdog & Assistant</h2><div class="note">Supervisor state. Voice is intentionally minimal.</div></div><div class="equal"><div class="panel"><div class="kv" id="watchdogSystemKv"></div><div id="watchdogSystemConditions" style="margin-top:10px"></div></div><div class="panel"><div class="kv" id="assistantSystemKv"></div><div class="assistant-controls"><button class="btn" id="assistantBrief2">Brief Current Page</button><button class="btn" id="assistantStop2">Stop Voice</button><button class="btn" id="assistantBackendTest">Test Backend Audio</button></div><div class="assistant-msg" id="assistantSystemMessage"></div></div></div>';system.insertBefore(s,system.firstChild);}
  for(const id of ['assistantBrief','assistantBrief2']){const el=byId(id);if(el)el.onclick=briefMe;}for(const id of ['assistantStop','assistantStop2']){const el=byId(id);if(el)el.onclick=stopVoice;}const backend=byId('assistantBackendTest');if(backend)backend.onclick=testBackend;const badge=byId('opsWatchBadge');if(badge)badge.onclick=()=>{if(typeof setView==='function')setView('system');};cleanCopy();
}
function browserAvailable(){return 'speechSynthesis' in window&&'SpeechSynthesisUtterance' in window;}
function stopBrowser(){try{if(browserAvailable())window.speechSynthesis.cancel();}catch{}}
function browserSpeak(text,force=false){if(!browserAvailable()||!text)return false;const now=Date.now();if(!force&&text===lastBrowserText&&now-lastBrowserAt<1800000)return false;lastBrowserText=text;lastBrowserAt=now;try{stopBrowser();const u=new SpeechSynthesisUtterance(text);u.rate=1;u.volume=1;window.speechSynthesis.speak(u);return true}catch{return false;}}
function conditionHtml(watch){const items=Object.entries(watch.active_conditions||{});if(!items.length)return '<div class="muted">No active watchdog conditions.</div>';return items.map(([key,c])=>`<div class="watch-condition"><b>${esc2(c.severity||'')} · ${esc2(c.title||key)}</b><div>${esc2(c.detail||'')}</div></div>`).join('');}
function renderAssistant(d){
  assistantData=d;injectPanels();cleanCopy();const w=d.watchdog||{},v=d.voice||{},live=d.live||{},capture=live.capture||{};const badge=byId('opsWatchBadge');if(badge){badge.textContent=`WATCHDOG · ${w.state||'UNKNOWN'} · ${Number(w.active_count||0)} ACTIVE`;badge.classList.toggle('attention',Number(w.active_count||0)>0);}const grid=byId('watchGrid');if(grid)grid.innerHTML=[['State',w.state||'—'],['Checks',Number(w.checks||0).toLocaleString()],['Active',Number(w.active_count||0)],['Highest',w.highest_severity||'INFO']].map(x=>`<div class="watch-cell"><div class="label">${esc2(x[0])}</div><strong>${esc2(x[1])}</strong></div>`).join('');const c=conditionHtml(w);if(byId('watchConditions'))byId('watchConditions').innerHTML=c;if(byId('watchdogSystemConditions'))byId('watchdogSystemConditions').innerHTML=c;
  if(byId('watchdogSystemKv'))byId('watchdogSystemKv').innerHTML=[['State',w.state||'—'],['Last Check',w.last_check||'—'],['Checks',w.checks||0],['Interval',(w.interval_seconds||0)+' s'],['Active Conditions',w.active_count||0]].flatMap(x=>[`<div>${esc2(x[0])}</div>`,`<div>${esc2(x[1])}</div>`]).join('');
  const backendState=v.available?'READY':(v.backend_present?'BROWSER FALLBACK':'UNAVAILABLE');if(byId('assistantSystemKv'))byId('assistantSystemKv').innerHTML=[['Voice Mode','MINIMAL'],['Backend',backendState],['Engine',v.engine||'—'],['Speaking',v.speaking?'YES':'NO'],['Queue',v.queue_depth||0],['Muted',v.muted?'YES':'NO'],['Browser Fallback',browserAvailable()?'READY':'UNAVAILABLE'],['Last Spoken',v.last_spoken||'—']].flatMap(x=>[`<div>${esc2(x[0])}</div>`,`<div>${esc2(x[1])}</div>`]).join('');
  const openItems=(live.incidents||[]).filter(i=>String(i.status||'OPEN').toUpperCase()!=='CLOSED');openItems.sort((a,b)=>String(b.last_seen||'').localeCompare(String(a.last_seen||'')));const incident=openItems[0],incidentText=incident?` · incident ${esc2(incident.title||'unnamed')} (${esc2(incident.severity||'')})`:'';const transcript=`Watching ${esc2((d.network||{}).interface||'network')} · capture ${esc2(capture.state||'unknown')} · ${Number((live.assets||[]).length)} assets · ${Number((live.flows||[]).length)} flows · ${openItems.length} open incidents${incidentText} · ${Number(w.active_count||0)} watch conditions.`;if(byId('assistantTranscript'))byId('assistantTranscript').innerHTML=transcript;handleBrowserFallback(d);
}
async function getStatus(){try{const r=await fetch('/api/v1/live/status',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);renderAssistant(await r.json());}catch{const b=byId('opsWatchBadge');if(b)b.textContent='WATCHDOG · CONSOLE OFFLINE';}}
function shouldFallbackSpeak(e){const p=e.payload||{},sev=String(e.severity||'').toUpperCase(),kind=String(e.kind||'').toUpperCase();if(kind==='INCIDENT'&&['INCIDENT_OPENED','INCIDENT_REOPENED','INCIDENT_ESCALATED'].includes(String(p.type||''))&&['HIGH','CRITICAL'].includes(sev))return true;if(kind==='HEALTH'&&String(p.state||'').toUpperCase()==='ACTIVE'&&['HIGH','CRITICAL'].includes(sev))return true;if(kind==='ACTION'&&String(p.action||'')==='RESPONSE_JOB_RESULT'&&['FAILED','REJECTED'].includes(String(p.status||'').toUpperCase()))return true;return false;}
function handleBrowserFallback(d){const v=d.voice||{},events=((d.live||{}).events||[]);if(!eventsInitialized){events.forEach(e=>e.event_id&&seenEvents.add(e.event_id));eventsInitialized=true;return;}const backendFailed=!v.available;if(!backendFailed||v.muted){events.forEach(e=>e.event_id&&seenEvents.add(e.event_id));return;}for(const e of [...events].reverse()){if(!e.event_id||seenEvents.has(e.event_id))continue;seenEvents.add(e.event_id);if(!shouldFallbackSpeak(e))continue;const text=(e.payload||{}).voice;if(text)browserSpeak(String(text));}if(seenEvents.size>2000)seenEvents=new Set(events.slice(0,500).map(e=>e.event_id).filter(Boolean));}
async function briefMe(){if(typeof window.contextualOperationsBrief==='function'){window.contextualOperationsBrief(document.querySelector('.tab.active')?.dataset?.view||'overview',true);return;}const targets=[byId('assistantMessage'),byId('assistantSystemMessage')].filter(Boolean);targets.forEach(x=>x.textContent='Preparing briefing...');try{const r=await fetch('/api/v1/system/assistant/brief',{method:'POST'}),d=await r.json();if(!r.ok)throw new Error(d.detail||'Briefing failed');targets.forEach(x=>x.textContent=d.text||'Briefing queued');if(!d.queued&&!d.muted)browserSpeak(d.text,true);}catch(e){targets.forEach(x=>x.textContent=e.message);}}
async function stopVoice(){stopBrowser();if(typeof window.stopOperationsVoice==='function')window.stopOperationsVoice();try{await fetch('/api/v1/system/voice/stop',{method:'POST'});}catch{}const m=byId('assistantSystemMessage');if(m)m.textContent='Voice stopped.';}
async function testBackend(){const m=byId('assistantSystemMessage');if(m)m.textContent='Testing backend audio...';try{const r=await fetch('/api/v1/system/voice/test',{method:'POST'}),d=await r.json();if(m)m.textContent=d.test_success?'Backend audio passed':'Backend audio unavailable; browser fallback remains available.';if(!d.test_success)browserSpeak('Browser voice fallback is working.',true);}catch(e){if(m)m.textContent=e.message;}}
injectPanels();getStatus();setInterval(getStatus,2000);
})();
</script>
"""


def _clean_console_copy(html: str) -> str:
    replacements = {
        "Evidence-first network defence console": "",
        "EVIDENCE-FIRST NETWORK DEFENCE CONSOLE": "",
        "Black / white / grey operator interface · authorized cyber-range and campus-lab environments only · live contract: CURRENT_SESSION_ONLY": "",
        "BLACK / WHITE / GREY OPERATOR INTERFACE · AUTHORIZED CYBER-RANGE AND CAMPUS-LAB ENVIRONMENTS ONLY · LIVE CONTRACT: CURRENT_SESSION_ONLY": "",
        "Current-session packet relationships only": "",
    }
    for old, new in replacements.items():
        html = html.replace(old, new)
    return html


def install_runtime_extensions(app: FastAPI) -> FastAPI:
    """Install supervision, investigation, admin and visualization runtime extensions."""
    if getattr(app.state, "runtime_extensions_installed", False):
        return app
    app.state.runtime_extensions_installed = True
    install_context_assistant(app)
    install_capability_routes(app)
    install_investigation_routes(app)
    install_admin_routes(app)

    @app.get("/api/v1/system/watchdog")
    async def watchdog_status() -> dict[str, object]:
        return app.state.orchestrator.watchdog.status()

    @app.post("/api/v1/system/assistant/brief")
    async def assistant_brief() -> dict[str, object]:
        orch = app.state.orchestrator
        text = page_briefing(orch.snapshot(), "overview")
        status = orch.voice.status()
        muted = bool(status.get("muted"))
        queued = await orch.voice.replace_speech(text, priority=20) if status.get("available") and not muted else False
        if not status.get("available"):
            await orch.voice.cancel_speech(clear_queue=True)
        return {"text": text, "queued": bool(queued), "muted": muted, "voice": orch.voice.status(), "watchdog": orch.watchdog.status()}

    @app.post("/api/v1/system/voice/stop")
    async def assistant_stop() -> dict[str, object]:
        orch = app.state.orchestrator
        await orch.voice.cancel_speech(clear_queue=True)
        return orch.voice.status()

    @app.middleware("http")
    async def console_extension(request: Request, call_next):
        if request.method == "GET" and request.url.path == "/":
            ui_path = Path(__file__).parent / "ui" / "index.html"
            try:
                html = ui_path.read_text(encoding="utf-8")
            except OSError:
                return await call_next(request)
            html = _clean_console_copy(html)
            extended = html.replace(
                "</body>",
                f"{UI_EXTENSION}\n{CONTEXT_EXTENSION}\n{CAPABILITY_EXTENSION}\n{INVESTIGATION_EXTENSION}\n{TOPOLOGY_EXTENSION}\n{TRAFFIC_EXTENSION}\n{ADMIN_EXTENSION}\n</body>",
            )
            return HTMLResponse(extended, headers={"Cache-Control": "no-store, no-cache, must-revalidate"})
        return await call_next(request)

    return app
