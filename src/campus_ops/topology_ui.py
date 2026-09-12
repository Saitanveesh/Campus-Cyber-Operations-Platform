TOPOLOGY_EXTENSION = r"""
<style>
#view-topology>section{max-width:1500px;margin-left:auto;margin-right:auto}
#view-topology .sectionhead{align-items:center}
#view-topology .split{grid-template-columns:minmax(0,1fr) 320px;gap:14px}
#topologyCanvas{background:#fff;height:680px;min-height:680px;padding:8px;overflow:hidden}
#topologyCanvas svg{display:block;width:100%;height:100%;user-select:none}
.topo-layer{fill:#666;font:700 10px Arial,Helvetica,sans-serif;letter-spacing:.12em}
.topo-guide{stroke:#e2e2e2;stroke-width:1;stroke-dasharray:4 7}
.topo-vlan{fill:#555;font:700 9px Arial,Helvetica,sans-serif;letter-spacing:.08em}
.topo-edge{fill:none;stroke:#999;stroke-linecap:round;transition:opacity .15s,stroke-width .15s}
.topo-edge.recent{stroke:#111;stroke-dasharray:8 5;animation:topoDash 1.15s linear infinite}
.topo-edge.selected{stroke:#111!important;opacity:1!important}
.topo-node{cursor:pointer;transition:opacity .15s}
.topo-node rect{fill:#fff;stroke:#222;stroke-width:1;rx:3;ry:3}
.topo-node:hover rect{stroke-width:2}
.topo-node.selected rect{fill:#111;stroke:#111;stroke-width:2}
.topo-node.risk rect{stroke-width:2.5}
.topo-node text{fill:#111;font:10px Consolas,Monaco,monospace;pointer-events:none}
.topo-node .node-sub{fill:#666;font:9px Arial,Helvetica,sans-serif}
.topo-node.selected text,.topo-node.selected .node-sub{fill:#fff}
.topo-edge-label{fill:#333;font:9px Consolas,Monaco,monospace;paint-order:stroke;stroke:#fff;stroke-width:4px;stroke-linejoin:round}
.topo-statbar{display:grid;grid-template-columns:repeat(6,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:12px 0 14px}
.topo-stat{padding:10px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:64px}
.topo-stat b{display:block;font-size:17px;margin-top:4px}
.topo-toolbar-group{display:inline-flex;margin-right:8px}
.topo-mode{border:1px solid #111;border-right:0;background:#fff;padding:7px 9px;font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;cursor:pointer}
.topo-mode:last-child{border-right:1px solid #111}.topo-mode.active{background:#111;color:#fff}
.topo-legend{display:flex;gap:16px;flex-wrap:wrap;font-size:10px;color:#555;margin:8px 0 0}
.topo-legend span:before{content:'';display:inline-block;width:18px;border-top:1px solid #999;margin-right:5px;vertical-align:middle}
.topo-legend .recent:before{border-top:2px dashed #111}
.topo-focus-note{font-size:10px;color:#555;margin:6px 0 0}
.topo-flow-table{max-height:360px}
@keyframes topoDash{to{stroke-dashoffset:-26}}
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
function category(id,assets,edges){
  const r=role(assets.get(id));if(r.includes('SENSOR'))return 'sensor';if(r.includes('INFRASTRUCTURE')||r.includes('GATEWAY'))return 'infra';if(r.includes('PUBLIC')||r.includes('OFF_SUBNET')||r.includes('MULTICAST')||r.includes('BROADCAST')||r.includes('SPECIAL'))return 'external';
  const e=edges.find(x=>x.source===id||x.target===id),er=String(e?.source===id?e?.source_role:e?.target_role||'').toUpperCase();if(er.includes('SENSOR'))return 'sensor';if(er.includes('INFRASTRUCTURE')||er.includes('GATEWAY'))return 'infra';if(er.includes('PUBLIC')||er.includes('OFF_SUBNET'))return 'external';return 'local';
}
function appOf(x){return x?.last_application||x?.last_tls_sni||x?.last_dns_query||x?.last_http_host||x?.dns_query||x?.tls_sni||x?.http_host||x?.last_protocol||x?.protocol||x?.transport||'';}
function inject(){
  const view=T('view-topology'),canvas=T('topologyCanvas');if(!view||!canvas)return;
  const head=view.querySelector('h2');if(head)head.textContent='Live Network Topology';
  const toolbar=view.querySelector('.toolbar');if(toolbar&&!T('topoModes')){
    const group=document.createElement('span');group.id='topoModes';group.className='topo-toolbar-group';group.innerHTML='<button class="topo-mode active" data-topo-mode="hierarchy">Hierarchy</button><button class="topo-mode" data-topo-mode="flows">Flows</button><button class="topo-mode" data-topo-mode="risk">Risk</button>';
    const density=document.createElement('span');density.id='topoDensity';density.className='topo-toolbar-group';density.innerHTML='<button class="topo-mode active" data-topo-density="focus">Focus</button><button class="topo-mode" data-topo-density="expanded">Expand</button>';
    toolbar.insertBefore(density,toolbar.firstChild);toolbar.insertBefore(group,toolbar.firstChild);
    group.querySelectorAll('button').forEach(b=>b.onclick=()=>{topoMode=b.dataset.topoMode;group.querySelectorAll('button').forEach(x=>x.classList.toggle('active',x===b));renderAdvanced(topoLive);});
    density.querySelectorAll('button').forEach(b=>b.onclick=()=>{topoDensity=b.dataset.topoDensity;density.querySelectorAll('button').forEach(x=>x.classList.toggle('active',x===b));renderAdvanced(topoLive);});
  }
  const split=canvas.closest('.split');if(split&&!T('topologyStats')){const stats=document.createElement('div');stats.id='topologyStats';stats.className='topo-statbar';split.parentElement.insertBefore(stats,split);}
  if(split&&!T('topologyLegend')){const legend=document.createElement('div');legend.id='topologyLegend';legend.className='topo-legend';legend.innerHTML='<span>Observed relationship</span><span class="recent">Recent traffic</span><span>Direction follows source to destination</span>';split.parentElement.appendChild(legend);const note=document.createElement('div');note.id='topologyFocusNote';note.className='topo-focus-note';split.parentElement.appendChild(note);}
  if(!T('topologyFlowLens')){const section=document.createElement('section');section.id='topologyFlowLens';section.innerHTML='<div class="sectionhead"><h2>Live Flow Lens</h2><div class="note" id="topologyFlowNote"></div></div><div class="tablewrap topo-flow-table"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Application</th><th>PPS</th><th>Rate</th><th>Packets</th><th>Bytes</th><th>Last Seen</th></tr></thead><tbody id="topologyFlowRows"></tbody></table></div>';view.appendChild(section);}
  const find=T('topologyFind');if(find)find.onclick=()=>{const q=(T('topologySearch')?.value||'').trim().toLowerCase();if(!q)return;const assets=topoLive.assets||[],edges=topoLive.topology_edges||[],ids=[...new Set([...assets.map(a=>a.ip),...edges.flatMap(e=>[e.source,e.target])].filter(Boolean))];const byName=assets.find(a=>String(a.hostname||a.dhcp_hostname||'').toLowerCase().includes(q));const found=ids.find(id=>String(id).toLowerCase().includes(q))||byName?.ip;if(found)selectAdvanced(found);};
  const reset=T('topologyReset');if(reset)reset.onclick=()=>{topoSelected=null;try{selectedNode=null}catch{};renderAdvanced(topoLive);renderSelected(null);};
}
function nodeScores(ids,edges,risk){const s={};ids.forEach(id=>s[id]=(risk[id]||0)*1e8);for(const e of edges){const weight=Number(e.bps_ewma||0)*40+Number(e.packets||0);s[e.source]=(s[e.source]||0)+weight;s[e.target]=(s[e.target]||0)+weight;}return s;}
function chooseIds(live,assets,edges,risk){
  const all=[...new Set([...assets.keys(),...edges.flatMap(e=>[e.source,e.target])].filter(Boolean))],scores=nodeScores(all,edges,risk),sorted=all.slice().sort((a,b)=>(scores[b]||0)-(scores[a]||0));
  const max=topoDensity==='expanded'?96:44,keep=new Set();
  for(const id of all){const c=category(id,assets,edges);if(c==='sensor'||c==='infra')keep.add(id);}
  if(topoMode==='flows'){const flows=(live.flows||[]).slice().sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0));for(const f of flows){if(f.src)keep.add(f.src);if(f.dst)keep.add(f.dst);if(keep.size>=max)break;}}
  else if(topoMode==='risk'){for(const id of sorted){if((risk[id]||0)>0)keep.add(id);if(keep.size>=max)break;}}
  else{for(const id of sorted){keep.add(id);if(keep.size>=max)break;}}
  if(topoSelected){keep.add(topoSelected);const neighbors=edges.filter(e=>e.source===topoSelected||e.target===topoSelected).sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0));for(const e of neighbors.slice(0,20))keep.add(e.source===topoSelected?e.target:e.source);}
  return {all,visible:[...keep].slice(0,Math.max(max,keep.size)),scores};
}
function placeGroup(ids,top,bottom,pos,W,cols){if(!ids.length)return;const rows=Math.ceil(ids.length/cols),gap=rows<=1?0:(bottom-top)/(rows-1);ids.forEach((id,i)=>{const row=Math.floor(i/cols),rowItems=Math.min(cols,ids.length-row*cols),col=i%cols,x=rowItems===1?W/2:105+col*(W-210)/(rowItems-1),y=top+row*gap;pos[id]={x,y};});}
function layout(ids,assets,edges,scores){const groups={external:[],infra:[],local:[],sensor:[]};ids.forEach(id=>groups[category(id,assets,edges)].push(id));for(const arr of Object.values(groups))arr.sort((a,b)=>(scores[b]||0)-(scores[a]||0));const W=1400,H=760,pos={};placeGroup(groups.external,95,205,pos,W,10);placeGroup(groups.infra,300,340,pos,W,8);placeGroup(groups.local,445,575,pos,W,10);placeGroup(groups.sensor,690,710,pos,W,7);return {groups,pos,W,H};}
function curve(a,b){if(Math.abs(a.y-b.y)<20){const lift=Math.max(45,Math.min(110,Math.abs(a.x-b.x)*.22));return `M${a.x},${a.y} Q${(a.x+b.x)/2},${a.y-lift} ${b.x},${b.y}`;}const mid=(a.y+b.y)/2;return `M${a.x},${a.y} C${a.x},${mid} ${b.x},${mid} ${b.x},${b.y}`;}
function nodeLabel(id,a){const host=a?.hostname||a?.dhcp_hostname||'',vlan=a?.vlan_id?`VLAN ${a.vlan_id}`:'',sub=[host||a?.classification||a?.role||'',vlan].filter(Boolean).join(' · ');return {main:id,sub};}
function renderStats(live,total,visible,visibleEdges){const totalRate=visibleEdges.reduce((s,e)=>s+Number(e.bps_ewma||0),0),recent=visibleEdges.filter(e=>age(e.last_seen)<8).length,hidden=Math.max(0,total-visible.length),stats=T('topologyStats');if(stats)stats.innerHTML=[['Visible Nodes',`${visible.length} / ${total}`],['Relationships',visibleEdges.length],['Active Flows',(live.flows||[]).length],['Recent Links',recent],['Observed Rate',bits(totalRate)],['Hidden',hidden]].map(x=>`<div class="topo-stat"><div class="label">${h(x[0])}</div><b>${h(x[1])}</b></div>`).join('');const note=T('topologyFocusNote');if(note)note.textContent=hidden?`${hidden} lower-activity nodes are hidden in Focus view. Use Expand or Find to inspect them.`:'All selected topology nodes are visible.';}
function renderFlows(live){const rows=(live.flows||[]).slice().sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0)).slice(0,30),body=T('topologyFlowRows');if(body)body.innerHTML=rows.map(f=>`<tr><td class="mono">${h(f.src)}:${h(f.src_port||'')}</td><td class="mono">${h(f.dst)}:${h(f.dst_port||'')}</td><td>${h(f.protocol||f.transport||'—')}</td><td>${h(appOf(f)||'—')}</td><td>${Number(f.pps_ewma||0).toFixed(1)}</td><td>${bits(f.bps_ewma||0)}</td><td>${n(f.packets)}</td><td>${bytes(f.bytes)}</td><td>${h(f.last_seen?new Date(f.last_seen).toLocaleTimeString():'—')}</td></tr>`).join('')||'<tr><td colspan="9" class="muted">No active flows</td></tr>';const note=T('topologyFlowNote');if(note)note.textContent=rows.length?`${rows.length} busiest current flows`:'Waiting for live flow data';}
function renderSelected(id){const live=topoLive||{},asset=(live.assets||[]).find(a=>a.ip===id)||{},edges=(live.topology_edges||[]).filter(e=>e.source===id||e.target===id).sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0));if(T('selectedNode'))T('selectedNode').textContent=id||'None';if(T('selectedNodeKv'))T('selectedNodeKv').innerHTML=id?[['Role',asset.role||asset.classification||'Observed peer'],['Name',asset.hostname||asset.dhcp_hostname||'—'],['MAC',asset.mac||'—'],['Vendor',asset.vendor||'—'],['OS Hint',asset.os_guess||'—'],['VLAN',asset.vlan_id||'—'],['Connections',edges.length],['Last Seen',asset.last_seen?new Date(asset.last_seen).toLocaleTimeString():'—']].flatMap(x=>[`<div>${h(x[0])}</div>`,`<div>${h(x[1])}</div>`]).join(''):'';if(T('selectedConnections'))T('selectedConnections').innerHTML=id?(edges.slice(0,18).map(e=>{const peer=e.source===id?e.target:e.source,dir=e.source===id?'→':'←';return `<div style="padding:7px 0;border-bottom:1px solid #ddd"><b class="mono">${dir} ${h(peer)}</b><div>${h(appOf(e)||e.last_protocol||'traffic')} · ${Number(e.pps_ewma||0).toFixed(1)} pps · ${bits(e.bps_ewma||0)}</div><div>${n(e.packets)} packets · ${bytes(e.bytes)}</div></div>`}).join('')||'No live relationships'):'Select a node';}
function selectAdvanced(id){topoSelected=id;try{selectedNode=id}catch{};renderAdvanced(topoLive);renderSelected(id);}
function renderAdvanced(live){
  topoLive=live||{};inject();try{if(selectedNode&&selectedNode!==topoSelected)topoSelected=selectedNode}catch{}
  const canvas=T('topologyCanvas');if(!canvas)return;const assetsList=topoLive.assets||[],edgesAll=topoLive.topology_edges||[],assets=new Map(assetsList.filter(a=>a.ip).map(a=>[a.ip,a])),risk=riskMap(topoLive),picked=chooseIds(topoLive,assets,edgesAll,risk),visibleSet=new Set(picked.visible),edges=edgesAll.filter(e=>visibleSet.has(e.source)&&visibleSet.has(e.target)).sort((a,b)=>Number(b.bps_ewma||b.packets||0)-Number(a.bps_ewma||a.packets||0)).slice(0,topoDensity==='expanded'?500:260);
  if(!picked.visible.length){canvas.innerHTML='<div class="empty">No live topology data</div>';renderStats(topoLive,0,[],[]);renderFlows(topoLive);return;}
  const {groups,pos,W,H}=layout(picked.visible,assets,edges,picked.scores),maxTraffic=Math.max(1,...edges.map(e=>Number(e.bps_ewma||0)||Number(e.packets||0))),defs='<defs><marker id="tArrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#777"/></marker><marker id="tArrowHot" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 z" fill="#111"/></marker></defs>';
  const guides=[['EXTERNAL / OFF-SUBNET',65],['GATEWAY / INFRASTRUCTURE',260],['LOCAL / VLAN',400],['SENSOR',645]].map(([label,y])=>`<text class="topo-layer" x="30" y="${y}">${label}</text><line class="topo-guide" x1="30" y1="${Number(y)+12}" x2="1370" y2="${Number(y)+12}"/>`).join('');
  const edgeSvg=edges.map(e=>{const a=pos[e.source],b=pos[e.target];if(!a||!b)return '';const selected=topoSelected&&(e.source===topoSelected||e.target===topoSelected),unrelated=topoSelected&&!selected,recent=age(e.last_seen)<8,value=Number(e.bps_ewma||0)||Number(e.packets||0),width=1+Math.min(4,Math.log10(1+value)/Math.max(1,Math.log10(1+maxTraffic))*4),opacity=unrelated?.045:selected?1:recent?.72:.22,label=selected?`<text class="topo-edge-label" x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-5}" text-anchor="middle">${h(appOf(e)||e.last_protocol||'traffic')} · ${bits(e.bps_ewma||0)}</text>`:'';return `<path class="topo-edge ${recent?'recent':''} ${selected?'selected':''}" d="${curve(a,b)}" style="stroke-width:${width.toFixed(2)};opacity:${opacity}" marker-end="url(#${recent||selected?'tArrowHot':'tArrow'})"><title>${h(e.source)} → ${h(e.target)} · ${h(appOf(e)||'traffic')} · ${bits(e.bps_ewma||0)} · ${n(e.packets)} packets</title></path>${label}`;}).join('');
  const nodeSvg=picked.visible.map(id=>{const p=pos[id];if(!p)return '';const a=assets.get(id)||{},label=nodeLabel(id,a),selected=id===topoSelected,connected=!topoSelected||edges.some(e=>(e.source===topoSelected&&e.target===id)||(e.target===topoSelected&&e.source===id))||selected,opacity=connected?1:.2,rv=risk[id]||0;return `<g class="topo-node ${selected?'selected':''} ${rv>0?'risk':''}" data-adv-node="${h(id)}" transform="translate(${p.x},${p.y})" style="opacity:${opacity}"><rect x="-61" y="-19" width="122" height="38"></rect><text x="0" y="-3" text-anchor="middle">${h(label.main)}</text><text class="node-sub" x="0" y="11" text-anchor="middle">${h(label.sub.slice(0,28))}</text><title>${h(role(a))}${rv?` · risk ${rv}/100`:''}</title></g>`;}).join('');
  const counts=`<text class="topo-layer" x="1370" y="24" text-anchor="end">${groups.external.length} EXT · ${groups.infra.length} INFRA · ${groups.local.length} LOCAL · ${groups.sensor.length} SENSOR</text>`;
  canvas.innerHTML=`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">${defs}${guides}${counts}${edgeSvg}${nodeSvg}</svg>`;canvas.querySelectorAll('[data-adv-node]').forEach(g=>g.onclick=()=>selectAdvanced(g.dataset.advNode));renderStats(topoLive,picked.all.length,picked.visible,edges);renderFlows(topoLive);if(topoSelected)renderSelected(topoSelected);
}
inject();try{renderTopology=renderAdvanced}catch{};try{renderAdvanced(snapshot?.live||{})}catch{};setInterval(()=>{try{renderAdvanced(snapshot?.live||topoLive||{})}catch{}},1400);
})();
</script>
"""
