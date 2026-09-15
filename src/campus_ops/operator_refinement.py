from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse


OPERATOR_REFINEMENT_EXTENSION = r"""
<style>
/* Keep the primary operator navigation compact; admin workspaces live on their own row. */
nav{overflow-x:hidden!important;white-space:normal!important;display:flex!important;flex-wrap:wrap!important}
#adminWorkspaceNav{display:none;align-items:center;gap:0;border-bottom:1px solid #c7c7c7;background:#fafafa;padding:0 24px;min-height:42px;flex-wrap:wrap}
#adminWorkspaceNav.show{display:flex}
#adminWorkspaceNav .admin-nav-label{font:700 9px/42px Arial,Helvetica,sans-serif;letter-spacing:.16em;text-transform:uppercase;margin-right:14px;color:#555}
#adminWorkspaceNav button.tab{display:block!important;position:relative!important;float:none!important;border-top:0!important;border-bottom:0!important;min-height:41px;padding:0 14px;white-space:nowrap}
#adminWorkspaceNav button.tab.active{background:#111!important;color:#fff!important}
#adminWorkspaceNav .admin-nav-sep{width:1px;height:22px;background:#ccc;margin:0 5px}

/* Radial live network view */
#radialTopologyCanvas{display:none;height:660px;min-height:660px;background:#fff;border:1px solid #c7c7c7;position:relative;overflow:hidden}
#radialTopologyCanvas.active{display:block}
#radialTopologyCanvas svg{width:100%;height:100%;display:block}
.radial-ring{fill:none;stroke:#d3d3d3;stroke-width:1;stroke-dasharray:5 7}
.radial-ring-label{fill:#777;font:700 9px Arial,Helvetica,sans-serif;letter-spacing:.12em}
.radial-link{stroke:#c3c3c3;stroke-width:1;opacity:.6}
.radial-link.hot{stroke:#111;stroke-width:1.8;opacity:.9}
.radial-node{cursor:pointer}
.radial-node circle{fill:#fff;stroke:#111;stroke-width:1.2}
.radial-node.sensor circle{fill:#111;stroke:#111;stroke-width:2}
.radial-node.sensor text{fill:#fff}
.radial-node.selected circle{stroke-width:4}
.radial-node text{font:9px Consolas,Monaco,monospace;fill:#111;pointer-events:none}
.radial-node .radial-sub{font:7.5px Arial,Helvetica,sans-serif;fill:#666}
.radial-node.sensor .radial-sub{fill:#fff}
#radialTopologyMeta{position:absolute;left:14px;right:14px;bottom:12px;border:1px solid #bbb;background:rgba(255,255,255,.95);padding:9px 11px;display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center;font:10px/1.45 Arial,Helvetica,sans-serif}
#radialTopologyMeta b{font-size:11px}
#radialInvestigate{height:31px}
#radialModeButton{border-right:1px solid #111}
@media(max-width:900px){#adminWorkspaceNav{padding:0 8px}#adminWorkspaceNav button.tab{padding:0 9px}#radialTopologyCanvas{height:560px;min-height:560px}}
</style>
<script>
(()=>{
const O=id=>document.getElementById(id);
const safe=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let radialSelected='',radialLast=null;
/* Keep the same canonical names as admin_layout_ui. This extension must never fight it. */
const ADMIN_ORDER=['admin-command','admin-forensics','admin-red','admin-infra','admin-soc','admin-hunt','admin-deep','admin-ioc','admin-remote','admin-contain'];
const ADMIN_NAMES={
 'admin-command':'Operations',
 'admin-forensics':'Investigation',
 'admin-red':'Validation',
 'admin-infra':'Infrastructure',
 'admin-soc':'SOC Desk',
 'admin-hunt':'Investigation Detail',
 'admin-deep':'Endpoint Analysis',
 'admin-ioc':'IOC Watch',
 'admin-remote':'Remote Access',
 'admin-contain':'Containment'
};
function adminToken(){return sessionStorage.getItem('campusOpsAdminToken')||''}
function ensureAdminSubnav(){
 const nav=document.querySelector('nav');if(!nav)return null;
 let sub=O('adminWorkspaceNav');
 if(!sub){sub=document.createElement('div');sub.id='adminWorkspaceNav';const label=document.createElement('span');label.className='admin-nav-label';label.textContent='Admin';sub.appendChild(label);nav.insertAdjacentElement('afterend',sub)}
 return sub;
}
function organizeAdminNavigation(){
 const nav=document.querySelector('nav'),sub=ensureAdminSubnav();if(!nav||!sub)return;
 const buttons=[...document.querySelectorAll('button.tab')].filter(b=>String(b.dataset.view||'').startsWith('admin-'));
 buttons.sort((a,b)=>{const ai=ADMIN_ORDER.indexOf(a.dataset.view),bi=ADMIN_ORDER.indexOf(b.dataset.view);return (ai<0?99:ai)-(bi<0?99:bi)});
 for(const b of buttons){const view=b.dataset.view;const name=ADMIN_NAMES[view];if(name&&b.textContent!==name)b.textContent=name;if(b.parentElement!==sub)sub.appendChild(b)}
 const active=!!adminToken();sub.classList.toggle('show',active);
 if(typeof pages!=='undefined'){
   if(pages['admin-deep'])pages['admin-deep']=['Endpoint Analysis','Managed endpoint processes, connections, services and response controls.'];
   if(pages['admin-hunt'])pages['admin-hunt']=['Investigation Detail','Current-session target investigation workspace.'];
   if(pages['admin-command'])pages['admin-command']=['Operations','Unified investigation, evidence and response workspace.'];
   if(pages['admin-forensics'])pages['admin-forensics']=['Investigation','Forensic evidence and target analysis.'];
   if(pages['admin-red'])pages['admin-red']=['Validation','Controlled defensive validation workspace.'];
   if(pages['admin-infra'])pages['admin-infra']=['Infrastructure','Network and platform infrastructure telemetry.'];
 }
 const deep=O('view-admin-deep');if(deep){const h=deep.querySelector('h2');if(h&&/Endpoint Deep/i.test(h.textContent||''))h.textContent='Endpoint Analysis';const s=deep.querySelector('.small');if(s&&/Correlates authenticated endpoint telemetry/i.test(s.textContent||''))s.textContent='Process, connection, service and network correlation for managed endpoints.'}
}
function typeOf(id,assets){
 const a=assets.get(id)||{},r=String(a.role||a.classification||'').toUpperCase();
 if(r.includes('SENSOR'))return 'sensor';
 if(r.includes('GATEWAY')||r.includes('INFRASTRUCTURE')||r.includes('SWITCH')||r.includes('ROUTER'))return 'infra';
 if(r.includes('PUBLIC')||r.includes('OFF_SUBNET')||r.includes('EXTERNAL'))return 'external';
 return 'local';
}
function pickCenter(assets,edges){
 for(const [id,a] of assets)if(String(a.role||a.classification||'').toUpperCase().includes('SENSOR'))return id;
 const degree={};for(const e of edges){degree[e.source]=(degree[e.source]||0)+1;degree[e.target]=(degree[e.target]||0)+1}
 return Object.entries(degree).sort((a,b)=>b[1]-a[1])[0]?.[0]||[...assets.keys()][0]||'MONITOR';
}
function scoreNodes(edges){const s={};for(const e of edges){const w=Number(e.bps_ewma||0)+Number(e.packets||0)*100;s[e.source]=(s[e.source]||0)+w;s[e.target]=(s[e.target]||0)+w}return s}
function polar(cx,cy,r,index,count){const angle=(-Math.PI/2)+(Math.PI*2*(index/Math.max(1,count)));return{x:cx+Math.cos(angle)*r,y:cy+Math.sin(angle)*r}}
function radialNode(id,pos,type,asset,selected){const label=String(asset?.hostname||asset?.dhcp_hostname||id);const short=label.length>18?label.slice(0,17)+'…':label;const sub=type==='sensor'?'MONITOR':type.toUpperCase();return `<g class="radial-node ${type} ${selected?'selected':''}" data-radial-node="${safe(id)}" transform="translate(${pos.x.toFixed(1)},${pos.y.toFixed(1)})"><circle r="${type==='sensor'?34:20}"></circle><text text-anchor="middle" y="-2">${safe(short)}</text><text class="radial-sub" text-anchor="middle" y="11">${safe(sub)}</text></g>`}
function ensureRadial(){
 const topo=O('topologyCanvas');if(!topo||O('radialTopologyCanvas'))return;
 const holder=topo.parentElement;const radial=document.createElement('div');radial.id='radialTopologyCanvas';radial.innerHTML='<svg id="radialTopologySvg" viewBox="0 0 1000 760" preserveAspectRatio="xMidYMid meet"></svg><div id="radialTopologyMeta"><div><b>RADIAL LIVE MAP</b><br><span id="radialTopologyStatus">Waiting for live topology.</span></div><button class="btn" id="radialInvestigate" disabled>Investigate Node</button></div>';holder.appendChild(radial);
 const group=O('topoModes');if(group&&!O('radialModeButton')){const b=document.createElement('button');b.id='radialModeButton';b.className='topo-mode';b.textContent='Radial';group.appendChild(b);b.onclick=()=>{group.querySelectorAll('.topo-mode').forEach(x=>x.classList.toggle('active',x===b));topo.style.display='none';radial.classList.add('active');refreshRadial()};group.querySelectorAll('[data-topo-mode]').forEach(x=>x.addEventListener('click',()=>{topo.style.display='';radial.classList.remove('active')},true))}
 O('radialInvestigate').onclick=()=>{if(radialSelected&&typeof window.openInvestigation==='function')window.openInvestigation(radialSelected)};
}
async function refreshRadial(){
 const box=O('radialTopologyCanvas');if(!box?.classList.contains('active'))return;
 try{
   const [topoRes,depthRes]=await Promise.all([fetch('/api/v1/live/topology',{cache:'no-store'}),fetch('/api/v1/system/network-depth',{cache:'no-store'}).catch(()=>null)]);
   if(!topoRes.ok)throw new Error(`topology HTTP ${topoRes.status}`);const d=await topoRes.json();const depth=depthRes&&depthRes.ok?await depthRes.json():{};radialLast=d;renderRadial(d,depth);
 }catch(e){const s=O('radialTopologyStatus');if(s)s.textContent=`Radial map unavailable · ${e.message}`}
}
function renderRadial(d,depth){
 const assets=new Map((d.assets||[]).filter(a=>a.ip).map(a=>[String(a.ip),a])),edges=(d.edges||[]).filter(e=>e.source&&e.target),center=pickCenter(assets,edges),score=scoreNodes(edges),groups={infra:[],local:[],external:[]};
 const ids=[...new Set([...assets.keys(),...edges.flatMap(e=>[String(e.source),String(e.target)])])].filter(id=>id!==center);
 for(const id of ids){const type=typeOf(id,assets);if(groups[type])groups[type].push(id)}for(const g of Object.values(groups))g.sort((a,b)=>(score[b]||0)-(score[a]||0));
 groups.infra=groups.infra.slice(0,8);groups.local=groups.local.slice(0,18);groups.external=groups.external.slice(0,14);const visible=new Set([center,...groups.infra,...groups.local,...groups.external]);
 const cx=500,cy=355,pos={[center]:{x:cx,y:cy}},rings={infra:125,local:235,external:340};for(const type of ['infra','local','external'])groups[type].forEach((id,i)=>pos[id]=polar(cx,cy,rings[type],i,groups[type].length));
 const ringSvg=`<circle class="radial-ring" cx="${cx}" cy="${cy}" r="125"></circle><circle class="radial-ring" cx="${cx}" cy="${cy}" r="235"></circle><circle class="radial-ring" cx="${cx}" cy="${cy}" r="340"></circle><text class="radial-ring-label" x="${cx+8}" y="${cy-130}">INFRASTRUCTURE</text><text class="radial-ring-label" x="${cx+8}" y="${cy-240}">LOCAL / VLAN</text><text class="radial-ring-label" x="${cx+8}" y="${cy-345}">EXTERNAL / OFF-SUBNET</text>`;
 const links=edges.filter(e=>visible.has(String(e.source))&&visible.has(String(e.target))).slice().sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0)).slice(0,80).map((e,i)=>{const a=pos[String(e.source)],b=pos[String(e.target)];if(!a||!b)return'';return `<line class="radial-link ${i<12?'hot':''}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"></line>`}).join('');
 const nodes=[radialNode(center,pos[center],'sensor',assets.get(center),radialSelected===center),...['infra','local','external'].flatMap(type=>groups[type].map(id=>radialNode(id,pos[id],type,assets.get(id),radialSelected===id)))].join('');
 const svg=O('radialTopologySvg');if(svg){svg.innerHTML=ringSvg+links+nodes;svg.querySelectorAll('[data-radial-node]').forEach(g=>g.onclick=()=>{radialSelected=g.dataset.radialNode||'';renderRadial(d,depth);const a=assets.get(radialSelected)||{};const status=O('radialTopologyStatus');if(status)status.textContent=`Selected ${radialSelected}${a.hostname?' · '+a.hostname:''} · ${typeOf(radialSelected,assets).toUpperCase()} · double-click or Investigate for details.`;O('radialInvestigate').disabled=false;g.ondblclick=()=>{if(typeof window.openInvestigation==='function')window.openInvestigation(radialSelected)}})}
 const physical=depth?.physical_topology||{},linkCount=(physical.links||[]).length,hidden=Math.max(0,ids.length-(groups.infra.length+groups.local.length+groups.external.length));const status=O('radialTopologyStatus');if(status&&!radialSelected)status.textContent=`${visible.size} nodes visible · ${edges.length} observed communication links · ${hidden} grouped · ${linkCount?`${linkCount} LLDP/SNMP physical links available`:'communication view only; no physical topology evidence'}.`;
}
function tick(){organizeAdminNavigation();ensureRadial();if(O('radialTopologyCanvas')?.classList.contains('active'))refreshRadial()}
setTimeout(tick,300);setInterval(tick,2000);
})();
</script>
"""


def install_operator_refinement(app: FastAPI) -> FastAPI:
    if getattr(app.state, "operator_refinement_installed", False):
        return app
    app.state.operator_refinement_installed = True

    @app.middleware("http")
    async def operator_refinement(request: Request, call_next):
        response = await call_next(request)
        if request.method != "GET" or request.url.path != "/":
            return response
        media_type = (response.headers.get("content-type") or "").lower()
        if "text/html" not in media_type:
            return response
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        text = body.decode("utf-8", errors="replace")
        if OPERATOR_REFINEMENT_EXTENSION not in text:
            text = text.replace("</body>", OPERATOR_REFINEMENT_EXTENSION + "\n</body>")
        headers = {k: v for k, v in response.headers.items() if k.lower() not in {"content-length", "content-type"}}
        headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return HTMLResponse(text, status_code=response.status_code, headers=headers)

    return app
