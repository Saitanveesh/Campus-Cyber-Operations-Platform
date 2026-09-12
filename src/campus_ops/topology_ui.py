from __future__ import annotations


TOPOLOGY_EXTENSION = r"""
<style>
#topologyCanvas{background:#fff;min-height:560px}
#topologyCanvas svg{display:block;width:100%;height:100%;user-select:none}
.topo-layer{fill:#777;font:700 10px Arial,Helvetica,sans-serif;letter-spacing:.12em}
.topo-guide{stroke:#dedede;stroke-width:1;stroke-dasharray:4 6}
.topo-edge{stroke:#a9a9a9;fill:none;stroke-linecap:round;transition:stroke-width .2s,opacity .2s}
.topo-edge.recent{stroke:#111;stroke-dasharray:7 5;animation:topoDash 1.2s linear infinite}
.topo-edge.selected{stroke:#111;opacity:1!important}
.topo-node rect{fill:#fff;stroke:#111;stroke-width:1.2;rx:3;ry:3}
.topo-node{cursor:pointer}
.topo-node:hover rect{stroke-width:2}
.topo-node.selected rect{fill:#111;stroke-width:2}
.topo-node text{fill:#111;font:10px Consolas,Monaco,monospace;pointer-events:none}
.topo-node .node-sub{fill:#666;font:9px Arial,Helvetica,sans-serif}
.topo-node.selected text,.topo-node.selected .node-sub{fill:#fff}
.topo-node.risk-high rect{stroke-width:3}
.topo-edge-label{fill:#444;font:9px Consolas,Monaco,monospace;paint-order:stroke;stroke:#fff;stroke-width:3px;stroke-linejoin:round}
.topo-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:10px;color:#555;margin-top:8px}
.topo-legend span:before{content:'';display:inline-block;width:18px;border-top:1px solid #777;margin-right:5px;vertical-align:middle}
.topo-legend .recent:before{border-top:2px dashed #111}
.topo-mode{border:1px solid #111;background:#fff;padding:7px 9px;font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;cursor:pointer}
.topo-mode.active{background:#111;color:#fff}
.topo-statbar{display:grid;grid-template-columns:repeat(5,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:12px 0}
.topo-stat{padding:10px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7}
.topo-stat b{display:block;font-size:17px;margin-top:4px}
@keyframes topoDash{to{stroke-dashoffset:-24}}
@media(max-width:900px){.topo-statbar{grid-template-columns:1fr 1fr}.topology{height:480px}}
</style>
<script>
(()=>{
let topoMode='hierarchy';
let topoSelected=null;
let topoLastLive=null;

const T=id=>document.getElementById(id);
const h=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const n=v=>Number(v||0).toLocaleString();
const shortBytes=v=>{v=Number(v||0);return v>=1e9?(v/1e9).toFixed(1)+' GB':v>=1e6?(v/1e6).toFixed(1)+' MB':v>=1e3?(v/1e3).toFixed(1)+' KB':v+' B'};
const ageSeconds=v=>{if(!v)return 1e9;const t=new Date(v).getTime();return Number.isFinite(t)?Math.max(0,(Date.now()-t)/1000):1e9};

function injectTopologyControls(){
  const view=T('view-topology');
  const canvas=T('topologyCanvas');
  if(!view||!canvas)return;
  const heading=view.querySelector('h2');if(heading)heading.textContent='Live Network Topology';
  const small=view.querySelector('.sectionhead .small');if(small)small.textContent='';
  const toolbar=view.querySelector('.toolbar');
  if(toolbar&&!T('topoModeHierarchy')){
    const wrap=document.createElement('span');
    wrap.innerHTML='<button class="topo-mode active" id="topoModeHierarchy">Hierarchy</button><button class="topo-mode" id="topoModeFlows">Flows</button><button class="topo-mode" id="topoModeRisk">Risk</button>';
    toolbar.insertBefore(wrap,toolbar.firstChild);
    T('topoModeHierarchy').onclick=()=>setMode('hierarchy');
    T('topoModeFlows').onclick=()=>setMode('flows');
    T('topoModeRisk').onclick=()=>setMode('risk');
  }
  if(!T('topologyStats')){
    const stats=document.createElement('div');stats.id='topologyStats';stats.className='topo-statbar';
    canvas.parentElement.insertBefore(stats,canvas);
  }
  if(!T('topologyLegend')){
    const legend=document.createElement('div');legend.id='topologyLegend';legend.className='topo-legend';
    legend.innerHTML='<span>Observed relationship</span><span class="recent">Recent traffic</span><span>Arrow shows direction</span>';
    canvas.parentElement.appendChild(legend);
  }
  if(!T('topologyFlowLens')){
    const section=document.createElement('section');section.id='topologyFlowLens';
    section.innerHTML='<div class="sectionhead"><h2>Live Flow Lens</h2><div class="note" id="flowLensNote"></div></div><div class="tablewrap"><table><thead><tr><th>Source</th><th>Destination</th><th>Transport</th><th>Protocol</th><th>Application</th><th>Packets</th><th>Bytes</th><th>Last Seen</th></tr></thead><tbody id="topologyFlowRows"></tbody></table></div>';
    view.appendChild(section);
  }
  const find=T('topologyFind');if(find)find.onclick=()=>{const q=(T('topologySearch')?.value||'').trim().toLowerCase();if(!q||!topoLastLive)return;const assets=topoLastLive.assets||[];const ids=[...new Set([...(assets.map(a=>a.ip)),...((topoLastLive.topology_edges||[]).flatMap(e=>[e.source,e.target]))].filter(Boolean))];const asset=assets.find(a=>String(a.hostname||a.dhcp_hostname||'').toLowerCase().includes(q));const found=ids.find(id=>String(id).toLowerCase().includes(q))||asset?.ip;if(found)advancedSelectNode(found);};
  const reset=T('topologyReset');if(reset)reset.onclick=()=>{topoSelected=null;try{selectedNode=null}catch{};advancedRender(topoLastLive||{});};
}

function setMode(mode){topoMode=mode;for(const [id,name] of [['topoModeHierarchy','hierarchy'],['topoModeFlows','flows'],['topoModeRisk','risk']]){const el=T(id);if(el)el.classList.toggle('active',name===mode);}advancedRender(topoLastLive||{});}
function roleOfAsset(asset){return String(asset?.role||asset?.classification||'OBSERVED_PEER').toUpperCase();}
function categoryFor(id,assets,edges){
  const asset=assets.get(id);const role=roleOfAsset(asset);
  if(role.includes('SENSOR'))return 'sensor';
  if(role.includes('GATEWAY')||role.includes('INFRASTRUCTURE'))return 'infra';
  if(role.includes('PUBLIC')||role.includes('OFF_SUBNET')||role.includes('MULTICAST')||role.includes('BROADCAST')||role.includes('SPECIAL'))return 'external';
  const edge=edges.find(e=>e.source===id||e.target===id);const erole=String(edge?.source===id?edge?.source_role:edge?.target_role||'').toUpperCase();
  if(erole.includes('SENSOR'))return 'sensor';if(erole.includes('GATEWAY')||erole.includes('INFRASTRUCTURE'))return 'infra';if(erole.includes('PUBLIC')||erole.includes('OFF_SUBNET'))return 'external';
  return 'local';
}
function nodeLabel(id,asset){const host=asset?.hostname||asset?.dhcp_hostname||asset?.name||'';return {main:id,sub:host&&host!==id?host:String(asset?.classification||asset?.role||'')};}
function riskMap(live){const graph=(live.metrics||{}).risk_graph||{};const m={};for(const node of graph.nodes||[])m[String(node.id)]=Number(node.risk||0);return m;}
function layout(ids,assets,edges){
  const groups={external:[],infra:[],local:[],sensor:[]};for(const id of ids)groups[categoryFor(id,assets,edges)].push(id);
  for(const key of Object.keys(groups))groups[key].sort((a,b)=>{const av=String(assets.get(a)?.vlan_id||'');const bv=String(assets.get(b)?.vlan_id||'');return av.localeCompare(bv)||a.localeCompare(b);});
  const pos={};const W=1200;const layers=[['external',75],['infra',190],['local',340],['sensor',485]];
  for(const [key,y] of layers){const arr=groups[key];arr.forEach((id,i)=>{const x=arr.length===1?W/2:70+i*(W-140)/Math.max(1,arr.length-1);pos[id]={x,y,group:key};});}
  return {pos,groups,W,H:560};
}
function edgeInfo(edge){const protocols=Object.entries(edge.protocols||{}).sort((a,b)=>Number(b[1])-Number(a[1])).slice(0,2).map(x=>x[0]);return protocols.join('/')||edge.last_protocol||edge.last_transport||'';}
function renderStats(live,edges,ids){const recent=edges.filter(e=>ageSeconds(e.last_seen)<10).length;const external=ids.filter(id=>{const a=(live.assets||[]).find(x=>x.ip===id);return roleOfAsset(a).includes('PUBLIC')||roleOfAsset(a).includes('OFF_SUBNET')}).length;const stats=T('topologyStats');if(stats)stats.innerHTML=[['Nodes',ids.length],['Relationships',edges.length],['Recent',recent],['External Peers',external],['Active Flows',(live.flows||[]).length]].map(x=>`<div class="topo-stat"><div class="label">${h(x[0])}</div><b>${h(x[1])}</b></div>`).join('');}
function renderFlowLens(live){const rows=(live.flows||[]).slice().sort((a,b)=>Number(b.packets||0)-Number(a.packets||0)).slice(0,30);const body=T('topologyFlowRows');if(body)body.innerHTML=rows.map(f=>`<tr><td class="mono">${h(f.src)}:${h(f.src_port||'')}</td><td class="mono">${h(f.dst)}:${h(f.dst_port||'')}</td><td>${h(f.transport||'—')}</td><td>${h(f.protocol||'—')}</td><td>${h(f.dns_query||f.tls_sni||f.http_host||'—')}</td><td>${n(f.packets)}</td><td>${shortBytes(f.bytes)}</td><td>${h(f.last_seen?new Date(f.last_seen).toLocaleTimeString():'—')}</td></tr>`).join('')||'<tr><td colspan="8" class="muted">No active flows</td></tr>';const note=T('flowLensNote');if(note)note.textContent=rows.length?`${rows.length} busiest current flows`:'Waiting for live flow data';}

function advancedSelectNode(id){
  topoSelected=id;try{selectedNode=id}catch{};advancedRender(topoLastLive||{});
  const live=topoLastLive||{},asset=(live.assets||[]).find(a=>a.ip===id)||{},edges=(live.topology_edges||[]).filter(e=>e.source===id||e.target===id).sort((a,b)=>Number(b.packets||0)-Number(a.packets||0));
  if(T('selectedNode'))T('selectedNode').textContent=id||'None';
  if(T('selectedNodeKv'))T('selectedNodeKv').innerHTML=[['Role',asset.role||asset.classification||'Observed peer'],['Name',asset.hostname||asset.dhcp_hostname||'—'],['MAC',asset.mac||'—'],['Vendor',asset.vendor||'—'],['OS Hint',asset.os_guess||'—'],['VLAN',asset.vlan_id||'—'],['Last Seen',asset.last_seen?new Date(asset.last_seen).toLocaleTimeString():'—']].flatMap(x=>[`<div>${h(x[0])}</div>`,`<div>${h(x[1])}</div>`]).join('');
  if(T('selectedConnections'))T('selectedConnections').innerHTML=edges.slice(0,20).map(e=>{const peer=e.source===id?e.target:e.source;const dir=e.source===id?'→':'←';const app=e.last_application||e.last_tls_sni||e.last_dns_query||e.last_http_host||'';return `<div style="padding:7px 0;border-bottom:1px solid #ddd"><b class="mono">${dir} ${h(peer)}</b><div>${h(edgeInfo(e)||'traffic')} · ${n(e.packets)} packets · ${shortBytes(e.bytes)}</div>${app?`<div class="muted">${h(app)}</div>`:''}</div>`}).join('')||'No live relationships for this node';
}

function advancedRender(live){
  topoLastLive=live;injectTopologyControls();const canvas=T('topologyCanvas');if(!canvas)return;
  const assetsList=live.assets||[],edgesAll=live.topology_edges||[],assets=new Map(assetsList.filter(a=>a.ip).map(a=>[a.ip,a]));
  let edges=edgesAll.slice().sort((a,b)=>Number(b.packets||0)-Number(a.packets||0));
  const risk=riskMap(live);if(topoMode==='risk')edges=edges.filter(e=>(risk[e.source]||0)>0||(risk[e.target]||0)>0);else if(topoMode==='flows')edges=edges.slice(0,350);else edges=edges.slice(0,250);
  let ids=[...new Set([...assets.keys(),...edges.flatMap(e=>[e.source,e.target])].filter(Boolean))];
  if(topoMode==='risk'){const risky=ids.filter(id=>(risk[id]||0)>0);if(risky.length)ids=risky;}
  if(!ids.length){canvas.innerHTML='<div class="empty">No live topology data</div>';renderStats(live,[],[]);renderFlowLens(live);return;}
  ids=ids.slice(0,120);const idSet=new Set(ids);edges=edges.filter(e=>idSet.has(e.source)&&idSet.has(e.target));const {pos,groups,W,H}=layout(ids,assets,edges);
  const marker='<defs><marker id="topoArrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#777"/></marker><marker id="topoArrowHot" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#111"/></marker></defs>';
  const guides=[['EXTERNAL / OFF-SUBNET',75],['GATEWAY / INFRASTRUCTURE',190],['LOCAL / VLAN',340],['SENSOR',485]].map(([label,y])=>`<text class="topo-layer" x="20" y="${y-34}">${label}</text><line class="topo-guide" x1="20" y1="${y-24}" x2="1180" y2="${y-24}"/>`).join('');
  const maxPackets=Math.max(1,...edges.map(e=>Number(e.packets||0)));
  const edgeSvg=edges.map(e=>{const a=pos[e.source],b=pos[e.target];if(!a||!b)return '';const recent=ageSeconds(e.last_seen)<8;const selected=topoSelected&&(e.source===topoSelected||e.target===topoSelected);const width=1+Math.min(4,Math.log10(1+Number(e.packets||0))/Math.max(1,Math.log10(1+maxPackets))*4);const opacity=selected?1:(topoMode==='flows' ? 0.82 : 0.48);const cls=`topo-edge ${recent?'recent':''} ${selected?'selected':''}`;const markerId=recent||selected?'topoArrowHot':'topoArrow';let label='';if(selected){const mx=(a.x+b.x)/2,my=(a.y+b.y)/2-4;label=`<text class="topo-edge-label" x="${mx}" y="${my}" text-anchor="middle">${h(edgeInfo(e))} · ${n(e.packets)}</text>`;}return `<line class="${cls}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" style="stroke-width:${width};opacity:${opacity}" marker-end="url(#${markerId})"><title>${h(e.source)} → ${h(e.target)} | ${h(edgeInfo(e))} | ${n(e.packets)} packets | ${shortBytes(e.bytes)}</title></line>${label}`;}).join('');
  const nodeSvg=ids.map(id=>{const p=pos[id];if(!p)return '';const asset=assets.get(id)||{},label=nodeLabel(id,asset),score=risk[id]||0,selected=id===topoSelected,w=Math.max(104,Math.min(180,64+Math.max(label.main.length,label.sub.length)*6));const cls=`topo-node ${selected?'selected':''} ${score>=70?'risk-high':''}`;const sub=label.sub?`<text class="node-sub" x="0" y="13" text-anchor="middle">${h(label.sub.slice(0,24))}</text>`:'';return `<g class="${cls}" data-topo-node="${h(id)}" transform="translate(${p.x},${p.y})"><rect x="${-w/2}" y="-20" width="${w}" height="40"></rect><text x="0" y="-3" text-anchor="middle">${h(label.main)}</text>${sub}<title>${h(label.main)} | ${h(label.sub)}${score?` | risk ${score}`:''}</title></g>`;}).join('');
  const groupCounts=`<text class="topo-layer" x="1180" y="41" text-anchor="end">${groups.external.length} EXT · ${groups.infra.length} INFRA · ${groups.local.length} LOCAL · ${groups.sensor.length} SENSOR</text>`;
  canvas.innerHTML=`<svg viewBox="0 0 ${W} ${H}">${marker}${guides}${groupCounts}${edgeSvg}${nodeSvg}</svg>`;
  canvas.querySelectorAll('[data-topo-node]').forEach(el=>el.onclick=()=>advancedSelectNode(el.getAttribute('data-topo-node')));
  renderStats(live,edges,ids);renderFlowLens(live);
}

injectTopologyControls();
try{renderTopology=advancedRender;selectNode=advancedSelectNode}catch{}
setInterval(()=>{if(topoLastLive&&T('view-topology')?.classList.contains('active'))advancedRender(topoLastLive);},1500);
})();
</script>
"""
