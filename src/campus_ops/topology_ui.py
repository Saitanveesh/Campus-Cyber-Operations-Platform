TOPOLOGY_EXTENSION = r"""
<style>
#view-topology>section{max-width:1500px;margin-left:auto;margin-right:auto}
#view-topology .split{grid-template-columns:minmax(0,1fr) 330px;gap:14px}
#topologyCanvas{background:#fff;height:660px;min-height:660px;padding:8px;overflow:hidden}
#topologyCanvas svg{display:block;width:100%;height:100%;user-select:none}
.topo-band-label{fill:#666;font:700 9px Arial,Helvetica,sans-serif;letter-spacing:.13em}
.topo-band-line{stroke:#e1e1e1;stroke-width:1;stroke-dasharray:4 7}
.topo-edge{fill:none;stroke:#aaa;stroke-linecap:round;transition:opacity .15s,stroke-width .15s}
.topo-edge.recent{stroke:#111;stroke-dasharray:8 6;animation:topoDash 1.25s linear infinite}
.topo-edge.selected{stroke:#111!important;opacity:1!important;stroke-width:2.4!important}
.topo-node{cursor:pointer;transition:opacity .15s}
.topo-node rect{fill:#fff;stroke:#222;stroke-width:1;rx:5;ry:5}
.topo-node:hover rect{stroke-width:2}
.topo-node.selected rect{fill:#111;stroke:#111;stroke-width:2}
.topo-node.risk rect{stroke-width:2.5}
.topo-node text{fill:#111;font:10px Consolas,Monaco,monospace;pointer-events:none}
.topo-node .node-sub{fill:#666;font:8.5px Arial,Helvetica,sans-serif}
.topo-node.selected text,.topo-node.selected .node-sub{fill:#fff}
.topo-hidden{cursor:pointer}.topo-hidden rect{fill:#f5f5f5;stroke:#aaa;stroke-dasharray:4 3}
.topo-hidden:hover rect{stroke:#111;stroke-width:2}.topo-hidden text{fill:#555;font:700 9px Arial,Helvetica,sans-serif;letter-spacing:.05em}
.topo-edge-label{fill:#222;font:9px Consolas,Monaco,monospace;paint-order:stroke;stroke:#fff;stroke-width:5px;stroke-linejoin:round}
.topo-statbar{display:grid;grid-template-columns:repeat(6,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:12px 0 14px}
.topo-stat{padding:10px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:62px}
.topo-stat b{display:block;font-size:17px;margin-top:4px}
.topo-toolbar-group{display:inline-flex;margin-right:7px}
.topo-mode{border:1px solid #111;border-right:0;background:#fff;padding:7px 9px;font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;cursor:pointer}
.topo-mode:last-child{border-right:1px solid #111}.topo-mode.active{background:#111;color:#fff}
.topo-note{font-size:10px;color:#555;margin:8px 0 0;line-height:1.45}
.topo-legend{display:flex;gap:16px;flex-wrap:wrap;font-size:10px;color:#555;margin:8px 0 0}
.topo-legend span:before{content:'';display:inline-block;width:18px;border-top:1px solid #aaa;margin-right:5px;vertical-align:middle}
.topo-legend .recent:before{border-top:2px dashed #111}
.topo-flow-table{max-height:330px}
@keyframes topoDash{to{stroke-dashoffset:-28}}
@media(max-width:1100px){#view-topology .split{grid-template-columns:1fr}#topologyCanvas{height:620px}.topo-statbar{grid-template-columns:repeat(3,1fr)}}
@media(max-width:720px){#topologyCanvas{height:560px}.topo-statbar{grid-template-columns:1fr 1fr}.topo-mode{padding:7px 6px}}
</style>
<script>
(()=>{
let topoMode='hierarchy',topoDensity='focus',topoSelected=null,topoLive={};
const T=id=>document.getElementById(id);
const h=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const n=v=>Number(v||0).toLocaleString();
const age=v=>{if(!v)return 1e9;const t=new Date(v).getTime();return Number.isFinite(t)?Math.max(0,(Date.now()-t)/1000):1e9};
const bits=v=>{v=Number(v||0);return v>=1e9?(v/1e9).toFixed(1)+' Gbps':v>=1e6?(v/1e6).toFixed(1)+' Mbps':v>=1e3?(v/1e3).toFixed(1)+' Kbps':v.toFixed(0)+' bps'};
const bytes=v=>{v=Number(v||0);return v>=1e9?(v/1e9).toFixed(1)+' GB':v>=1e6?(v/1e6).toFixed(1)+' MB':v>=1e3?(v/1e3).toFixed(1)+' KB':v+' B'};
function role(asset){return String(asset?.role||asset?.classification||'OBSERVED_PEER').toUpperCase();}
function riskMap(live){const out={};for(const item of ((live.metrics||{}).risk_graph||{}).nodes||[])out[String(item.id)]=Number(item.risk||0);return out;}
function category(id,assets,edges){const r=role(assets.get(id));if(r.includes('SENSOR'))return 'sensor';if(r.includes('INFRASTRUCTURE')||r.includes('GATEWAY'))return 'infra';if(r.includes('PUBLIC')||r.includes('OFF_SUBNET')||r.includes('MULTICAST')||r.includes('BROADCAST')||r.includes('SPECIAL'))return 'external';const e=edges.find(x=>x.source===id||x.target===id),er=String(e?.source===id?e?.source_role:e?.target_role||'').toUpperCase();if(er.includes('SENSOR'))return 'sensor';if(er.includes('INFRASTRUCTURE')||er.includes('GATEWAY'))return 'infra';if(er.includes('PUBLIC')||er.includes('OFF_SUBNET'))return 'external';return 'local';}
function appOf(x){return x?.last_application||x?.last_tls_sni||x?.last_dns_query||x?.last_http_host||x?.dns_query||x?.tls_sni||x?.http_host||x?.last_protocol||x?.protocol||x?.transport||'';}
function setDensity(value){topoDensity=value;document.querySelectorAll('[data-topo-density]').forEach(x=>x.classList.toggle('active',x.dataset.topoDensity===value));renderAdvanced(topoLive);}
function inject(){
  const view=T('view-topology'),canvas=T('topologyCanvas');if(!view||!canvas)return;
  const head=view.querySelector('h2');if(head)head.textContent='Live Network Topology';
  const toolbar=view.querySelector('.toolbar');if(toolbar&&!T('topoModes')){
    const modes=document.createElement('span');modes.id='topoModes';modes.className='topo-toolbar-group';modes.innerHTML='<button class="topo-mode active" data-topo-mode="hierarchy">Map</button><button class="topo-mode" data-topo-mode="flows">Flows</button><button class="topo-mode" data-topo-mode="risk">Risk</button>';
    const density=document.createElement('span');density.id='topoDensity';density.className='topo-toolbar-group';density.innerHTML='<button class="topo-mode active" data-topo-density="focus">Focus</button><button class="topo-mode" data-topo-density="expanded">Expand</button>';
    toolbar.insertBefore(density,toolbar.firstChild);toolbar.insertBefore(modes,toolbar.firstChild);
    modes.querySelectorAll('button').forEach(b=>b.onclick=()=>{topoMode=b.dataset.topoMode;modes.querySelectorAll('button').forEach(x=>x.classList.toggle('active',x===b));renderAdvanced(topoLive);});
    density.querySelectorAll('button').forEach(b=>b.onclick=()=>setDensity(b.dataset.topoDensity));
  }
  const split=canvas.closest('.split');if(split&&!T('topologyStats')){const stats=document.createElement('div');stats.id='topologyStats';stats.className='topo-statbar';split.parentElement.insertBefore(stats,split);}
  if(split&&!T('topologyLegend')){const legend=document.createElement('div');legend.id='topologyLegend';legend.className='topo-legend';legend.innerHTML='<span>Observed relationship</span><span class="recent">Recent traffic</span><span>Focus mode groups low-priority nodes</span>';split.parentElement.appendChild(legend);const note=document.createElement('div');note.id='topologyFocusNote';note.className='topo-note';split.parentElement.appendChild(note);}
  if(!T('topologyInvestigate')){const selected=T('selectedNode');if(selected){const wrap=document.createElement('div');wrap.className='invest-controls';wrap.style.marginTop='10px';wrap.innerHTML='<button class="btn" id="topologyInvestigate" disabled>Investigate IP</button>';selected.insertAdjacentElement('afterend',wrap);T('topologyInvestigate').onclick=()=>{if(topoSelected&&typeof window.openInvestigation==='function')window.openInvestigation(topoSelected);};}}
  if(!T('topologyFlowLens')){const section=document.createElement('section');section.id='topologyFlowLens';section.innerHTML='<div class="sectionhead"><h2>Live Flow Lens</h2><div class="note" id="topologyFlowNote"></div></div><div class="tablewrap topo-flow-table"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Application</th><th>PPS</th><th>Rate</th><th>Packets</th><th>Bytes</th></tr></thead><tbody id="topologyFlowRows"></tbody></table></div>';view.appendChild(section);}
  const find=T('topologyFind');if(find)find.onclick=()=>{const q=(T('topologySearch')?.value||'').trim().toLowerCase();if(!q)return;const assets=topoLive.assets||[],edges=topoLive.topology_edges||[],ids=[...new Set([...assets.map(a=>a.ip),...edges.flatMap(e=>[e.source,e.target])].filter(Boolean))];const byName=assets.find(a=>String(a.hostname||a.dhcp_hostname||'').toLowerCase().includes(q));const found=ids.find(id=>String(id).toLowerCase().includes(q))||byName?.ip;if(found)selectAdvanced(found);};
  const reset=T('topologyReset');if(reset)reset.onclick=()=>{topoSelected=null;setDensity('focus');try{selectedNode=null}catch{};renderSelected(null);};
}
function nodeScores(ids,edges,risk){const s={};ids.forEach(id=>s[id]=(risk[id]||0)*1e8);for(const e of edges){const w=Number(e.bps_ewma||0)*25+Number(e.packets||0);s[e.source]=(s[e.source]||0)+w;s[e.target]=(s[e.target]||0)+w;}return s;}
function chooseIds(live,assets,edges,risk){
  const all=[...new Set([...assets.keys(),...edges.flatMap(e=>[e.source,e.target])].filter(Boolean))],scores=nodeScores(all,edges,risk),groups={external:[],infra:[],local:[],sensor:[]};
  for(const id of all)groups[category(id,assets,edges)].push(id);for(const arr of Object.values(groups))arr.sort((a,b)=>(scores[b]||0)-(scores[a]||0));
  const caps=topoDensity==='expanded'?{external:10,infra:5,local:16,sensor:3}:{external:4,infra:2,local:6,sensor:1};const keep=new Set();
  if(topoMode==='flows'){const flowIds=[];for(const f of (live.flows||[]).slice().sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0)).slice(0,topoDensity==='expanded'?12:7)){if(f.src)flowIds.push(f.src);if(f.dst)flowIds.push(f.dst);}for(const id of flowIds)keep.add(id);}else if(topoMode==='risk'){for(const id of all.slice().sort((a,b)=>(risk[b]||0)-(risk[a]||0))){if((risk[id]||0)>0)keep.add(id);if(keep.size>=(topoDensity==='expanded'?22:10))break;}}
  for(const [cat,arr] of Object.entries(groups)){for(const id of arr.slice(0,caps[cat]))keep.add(id);}
  if(topoSelected){keep.add(topoSelected);const neighbors=edges.filter(e=>e.source===topoSelected||e.target===topoSelected).sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0));for(const e of neighbors.slice(0,topoDensity==='expanded'?14:6))keep.add(e.source===topoSelected?e.target:e.source);}
  return {all,visible:[...keep],scores,groups,caps};
}
function placeBand(ids,yStart,yEnd,pos,W,cols){if(!ids.length)return;const rows=Math.ceil(ids.length/cols),gapY=rows<=1?0:(yEnd-yStart)/(rows-1);ids.forEach((id,i)=>{const row=Math.floor(i/cols),count=Math.min(cols,ids.length-row*cols),col=i%cols,x=count===1?W/2:150+col*(W-300)/(count-1),y=yStart+row*gapY;pos[id]={x,y};});}
function layout(ids,assets,edges,scores){const groups={external:[],infra:[],local:[],sensor:[]};ids.forEach(id=>groups[category(id,assets,edges)].push(id));for(const arr of Object.values(groups))arr.sort((a,b)=>(scores[b]||0)-(scores[a]||0));const W=1400,H=740,pos={};placeBand(groups.external,110,160,pos,W,5);placeBand(groups.infra,285,320,pos,W,4);placeBand(groups.local,455,520,pos,W,5);placeBand(groups.sensor,650,680,pos,W,3);return {groups,pos,W,H};}
function curve(a,b){const dy=b.y-a.y,midY=a.y+dy*.5;if(Math.abs(dy)<25){const lift=Math.max(35,Math.min(90,Math.abs(a.x-b.x)*.18));return `M${a.x},${a.y} Q${(a.x+b.x)/2},${a.y-lift} ${b.x},${b.y}`;}return `M${a.x},${a.y} C${a.x},${midY} ${b.x},${midY} ${b.x},${b.y}`;}
function label(id,a){const host=a?.hostname||a?.dhcp_hostname||'',vlan=a?.vlan_id?`VLAN ${a.vlan_id}`:'',sub=[host||a?.classification||a?.role||'',vlan].filter(Boolean).join(' · ');return {main:id,sub};}
function hiddenSvg(picked,visibleSet){const bands={external:{y:205,label:'EXTERNAL'},infra:{y:365,label:'INFRA'},local:{y:570,label:'LOCAL'},sensor:{y:710,label:'SENSOR'}},rows=[];for(const [cat,arr] of Object.entries(picked.groups)){const hidden=arr.filter(id=>!visibleSet.has(id)).length;if(!hidden)continue;const b=bands[cat];rows.push(`<g class="topo-hidden" data-topo-expand="1" transform="translate(1230,${b.y})"><rect x="-82" y="-16" width="164" height="32" rx="5"></rect><text x="0" y="4" text-anchor="middle">+${hidden} MORE ${b.label} · EXPAND</text></g>`);}return rows.join('');}
function renderStats(live,total,visible,edges){const totalRate=edges.reduce((s,e)=>s+Number(e.bps_ewma||0),0),recent=edges.filter(e=>age(e.last_seen)<8).length,hidden=Math.max(0,total-visible.length),stats=T('topologyStats');if(stats)stats.innerHTML=[['Visible Nodes',`${visible.length} / ${total}`],['Visible Links',edges.length],['Active Flows',(live.flows||[]).length],['Recent Links',recent],['Visible Rate',bits(totalRate)],['Grouped Hidden',hidden]].map(x=>`<div class="topo-stat"><div class="label">${h(x[0])}</div><b>${h(x[1])}</b></div>`).join('');const note=T('topologyFocusNote');if(note)note.textContent=hidden?`${hidden} lower-priority nodes are collapsed. The map keeps only the most active, risky and selected relationships visible. Click a +MORE badge or Expand for detail.`:'All selected nodes are visible.';}
function renderFlows(live){const rows=(live.flows||[]).slice().sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0)).slice(0,24),body=T('topologyFlowRows');if(body)body.innerHTML=rows.map(f=>`<tr><td class="mono">${h(f.src)}:${h(f.src_port||'')}</td><td class="mono">${h(f.dst)}:${h(f.dst_port||'')}</td><td>${h(f.protocol||f.transport||'—')}</td><td>${h(appOf(f)||'—')}</td><td>${Number(f.pps_ewma||0).toFixed(1)}</td><td>${bits(f.bps_ewma||0)}</td><td>${n(f.packets)}</td><td>${bytes(f.bytes)}</td></tr>`).join('')||'<tr><td colspan="8" class="muted">No active flows</td></tr>';if(T('topologyFlowNote'))T('topologyFlowNote').textContent=rows.length?`${rows.length} busiest current flows`:'Waiting for current flow evidence';}
function renderSelected(id){const live=topoLive||{},asset=(live.assets||[]).find(a=>a.ip===id)||{},edges=(live.topology_edges||[]).filter(e=>e.source===id||e.target===id).sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0));if(T('selectedNode'))T('selectedNode').textContent=id||'None';const inv=T('topologyInvestigate');if(inv)inv.disabled=!id;if(T('selectedNodeKv'))T('selectedNodeKv').innerHTML=id?[['Role',asset.role||asset.classification||'Observed peer'],['Name',asset.hostname||asset.dhcp_hostname||'—'],['MAC',asset.mac||'—'],['Vendor',asset.vendor||'—'],['OS Hint',asset.os_guess||'—'],['VLAN',asset.vlan_id||'—'],['Connections',edges.length],['Last Seen',asset.last_seen?new Date(asset.last_seen).toLocaleTimeString():'—']].flatMap(x=>[`<div>${h(x[0])}</div>`,`<div>${h(x[1])}</div>`]).join(''):'';if(T('selectedConnections'))T('selectedConnections').innerHTML=id?(edges.slice(0,10).map(e=>{const peer=e.source===id?e.target:e.source,dir=e.source===id?'→':'←';return `<div style="padding:7px 0;border-bottom:1px solid #ddd"><b class="mono">${dir} ${h(peer)}</b><div>${h(appOf(e)||e.last_protocol||'traffic')} · ${Number(e.pps_ewma||0).toFixed(1)} pps · ${bits(e.bps_ewma||0)}</div></div>`}).join('')||'No current relationships'):'Select a node';}
function selectAdvanced(id){topoSelected=id;try{selectedNode=id}catch{};renderAdvanced(topoLive);renderSelected(id);}
function renderAdvanced(live){
  topoLive=live||{};inject();try{if(selectedNode&&selectedNode!==topoSelected)topoSelected=selectedNode}catch{}
  const canvas=T('topologyCanvas');if(!canvas)return;const assetsList=topoLive.assets||[],edgesAll=topoLive.topology_edges||[],assets=new Map(assetsList.filter(a=>a.ip).map(a=>[a.ip,a])),risk=riskMap(topoLive),picked=chooseIds(topoLive,assets,edgesAll,risk),visibleSet=new Set(picked.visible);
  if(!picked.visible.length){canvas.innerHTML='<div class="empty">No live topology data</div>';renderStats(topoLive,0,[],[]);renderFlows(topoLive);return;}
  let edges=edgesAll.filter(e=>visibleSet.has(e.source)&&visibleSet.has(e.target)).sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0));if(topoSelected){const selectedEdges=edges.filter(e=>e.source===topoSelected||e.target===topoSelected),other=edges.filter(e=>e.source!==topoSelected&&e.target!==topoSelected);edges=[...selectedEdges.slice(0,12),...other.slice(0,8)];}else edges=edges.slice(0,topoDensity==='expanded'?70:20);
  const {groups,pos,W,H}=layout(picked.visible,assets,edges,picked.scores),maxTraffic=Math.max(1,...edges.map(e=>Number(e.bps_ewma||0)||Number(e.packets||0))),defs='<defs><marker id="tArrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#888"/></marker><marker id="tArrowHot" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#111"/></marker></defs>';
  const guides=[['EXTERNAL / OFF-SUBNET',55],['GATEWAY / INFRASTRUCTURE',245],['LOCAL / VLAN',415],['SENSOR',625]].map(([name,y])=>`<text class="topo-band-label" x="35" y="${y}">${name}</text><line class="topo-band-line" x1="35" y1="${Number(y)+12}" x2="1365" y2="${Number(y)+12}"/>`).join('');
  const edgeSvg=edges.map(e=>{const a=pos[e.source],b=pos[e.target];if(!a||!b)return '';const selected=topoSelected&&(e.source===topoSelected||e.target===topoSelected),unrelated=topoSelected&&!selected,recent=age(e.last_seen)<8,value=Number(e.bps_ewma||0)||Number(e.packets||0),width=1+Math.min(3,Math.log10(1+value)/Math.max(1,Math.log10(1+maxTraffic))*3),opacity=unrelated?.025:selected?1:recent?.58:.11,label=selected?`<text class="topo-edge-label" x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-5}" text-anchor="middle">${h(appOf(e)||e.last_protocol||'traffic')} · ${bits(e.bps_ewma||0)}</text>`:'';return `<path class="topo-edge ${recent?'recent':''} ${selected?'selected':''}" d="${curve(a,b)}" style="stroke-width:${width.toFixed(2)};opacity:${opacity}" marker-end="url(#${recent||selected?'tArrowHot':'tArrow'})"><title>${h(e.source)} → ${h(e.target)} · ${h(appOf(e)||'traffic')} · ${bits(e.bps_ewma||0)}</title></path>${label}`;}).join('');
  const nodeSvg=picked.visible.map(id=>{const p=pos[id];if(!p)return '';const a=assets.get(id)||{},lab=label(id,a),selected=id===topoSelected,connected=!topoSelected||edges.some(e=>(e.source===topoSelected&&e.target===id)||(e.target===topoSelected&&e.source===id))||selected,opacity=connected?1:.18,rv=risk[id]||0;return `<g class="topo-node ${selected?'selected':''} ${rv>0?'risk':''}" data-adv-node="${h(id)}" transform="translate(${p.x},${p.y})" style="opacity:${opacity}"><rect x="-72" y="-23" width="144" height="46"></rect><text x="0" y="-4" text-anchor="middle">${h(lab.main)}</text><text class="node-sub" x="0" y="12" text-anchor="middle">${h(lab.sub.slice(0,31))}</text><title>${h(role(a))}${rv?` · risk ${rv}/100`:''}</title></g>`;}).join('');
  const counts=`<text class="topo-band-label" x="1360" y="24" text-anchor="end">FOCUS ${picked.visible.length}/${picked.all.length} · ${groups.external.length} EXT · ${groups.infra.length} INFRA · ${groups.local.length} LOCAL · ${groups.sensor.length} SENSOR</text>`;
  canvas.innerHTML=`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">${defs}${guides}${counts}${edgeSvg}${nodeSvg}${hiddenSvg(picked,visibleSet)}</svg>`;canvas.querySelectorAll('[data-adv-node]').forEach(g=>g.onclick=()=>selectAdvanced(g.dataset.advNode));canvas.querySelectorAll('[data-topo-expand]').forEach(g=>g.onclick=()=>setDensity('expanded'));renderStats(topoLive,picked.all.length,picked.visible,edges);renderFlows(topoLive);renderSelected(topoSelected);
}
inject();try{renderTopology=renderAdvanced}catch{};try{renderAdvanced(snapshot?.live||{})}catch{};setInterval(()=>{try{renderAdvanced(snapshot?.live||topoLive||{})}catch{}},1600);
})();
</script>
"""
