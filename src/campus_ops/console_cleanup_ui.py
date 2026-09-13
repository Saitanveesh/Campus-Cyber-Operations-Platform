CONSOLE_CLEANUP_EXTENSION = r"""
<style>
/* Preserve the established black/white V0.3 identity while reducing navigation noise. */
nav{overflow-x:hidden!important;flex-wrap:nowrap!important}
.tab.console-secondary{display:none!important}
#consoleQuickNav{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:10px 0 0}
#consoleQuickNav .btn{min-width:96px}
.console-shortcuts{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:8px 0 0}
.console-shortcuts .btn{padding:6px 9px}
#engineReadinessCompact{margin-top:16px}
.engine-grid{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7}
.engine-cell{padding:11px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:76px}
.engine-cell strong{display:block;font-size:16px;margin-top:5px}.engine-cell .small{margin-top:3px}
@media(max-width:1000px){.engine-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:650px){.engine-grid{grid-template-columns:1fr}}
</style>
<script>
(()=>{
const CORE=['overview','network','topology','pathspace','assets','security','system'];
const SECONDARY=['traffic','endpoints','response','evidence','history'];
const LABELS={overview:'Overview',network:'Network',topology:'Topology',pathspace:'Path Space',assets:'Assets',security:'Security',system:'System'};
const $=id=>document.getElementById(id);
function go(view){if(typeof window.setView==='function')window.setView(view);else{const b=document.querySelector(`button.tab[data-view="${view}"]`);if(b)b.click()}}
function compactPrimaryNav(){
 const nav=document.querySelector('nav');if(!nav)return;
 for(const view of SECONDARY){const b=nav.querySelector(`button.tab[data-view="${view}"]`);if(b)b.classList.add('console-secondary')}
 for(const view of CORE){const b=nav.querySelector(`button.tab[data-view="${view}"]`);if(b&&LABELS[view])b.textContent=LABELS[view]}
}
function shortcuts(container,items){
 if(!container||container.querySelector('.console-shortcuts'))return;
 const row=document.createElement('div');row.className='console-shortcuts';
 for(const [label,view] of items){const b=document.createElement('button');b.className='btn';b.textContent=label;b.onclick=()=>go(view);row.appendChild(b)}
 container.insertBefore(row,container.firstChild);
}
function installShortcuts(){
 const network=$('view-network');if(network)shortcuts(network,[['Live Traffic','traffic']]);
 const assets=$('view-assets');if(assets)shortcuts(assets,[['Endpoint Telemetry','endpoints']]);
 const security=$('view-security');if(security)shortcuts(security,[['Response','response'],['Evidence','evidence']]);
 const system=$('view-system');if(system)shortcuts(system,[['History','history']]);
}
async function renderEngineReadiness(){
 const system=$('view-system');if(!system||$('engineReadinessCompact'))return;
 const section=document.createElement('section');section.id='engineReadinessCompact';section.innerHTML='<div class="sectionhead"><h2>Analytics Engines</h2><div class="note">Current-session defensive analytics and correlation readiness.</div></div><div class="engine-grid" id="engineGrid"><div class="engine-cell"><div class="label">Status</div><strong>LOADING</strong></div></div>';system.appendChild(section);
 try{
  const urls=['/api/v1/system/depth-engines','/api/v1/system/depth-engines-v2','/api/v1/system/depth-engines-v3','/api/v1/system/depth-engines-v4'];
  const results=await Promise.all(urls.map(u=>fetch(u,{cache:'no-store'}).then(r=>r.ok?r.json():null).catch(()=>null)));
  const engines=[];for(const d of results){for(const e of (d?.engines||[]))if(e?.engine)engines.push(e)}
  const dedup=new Map();for(const e of engines)dedup.set(String(e.engine),e);
  const cells=[...dedup.values()].map(e=>`<div class="engine-cell"><div class="label">${String(e.engine||'ENGINE').replaceAll('_',' ')}</div><strong>${String(e.state||'ACTIVE')}</strong><div class="small">${Array.isArray(e.findings)?`${e.findings.length} findings`:e.score!==undefined?`score ${e.score}`:'current session'}</div></div>`).join('');
  const grid=$('engineGrid');if(grid)grid.innerHTML=cells||'<div class="engine-cell"><div class="label">Analytics</div><strong>AVAILABLE</strong><div class="small">No current findings.</div></div>';
 }catch{const grid=$('engineGrid');if(grid)grid.innerHTML='<div class="engine-cell"><div class="label">Analytics</div><strong>UNAVAILABLE</strong><div class="small">Engine status endpoint unavailable.</div></div>'}
}
function cleanDuplicateHeadings(){
 document.querySelectorAll('.sectionhead h2').forEach(h=>{const t=(h.textContent||'').trim();if(t==='Capability Center'||t==='Platform Capabilities')h.closest('section')?.classList.add('capability-section')});
}
function tick(){compactPrimaryNav();installShortcuts();cleanDuplicateHeadings();renderEngineReadiness()}
setTimeout(tick,350);setInterval(tick,2500);
})();
</script>
"""
