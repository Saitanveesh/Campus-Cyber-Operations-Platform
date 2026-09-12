LINK_STATE_EXTENSION = r"""
<style>
.linkstate-grid{display:grid;grid-template-columns:repeat(6,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7;margin:12px 0}.linkstate-grid>div{padding:10px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7;min-height:66px}.linkstate-grid strong{display:block;font-size:16px;margin-top:4px}.linkstate-table{max-height:260px}@media(max-width:1000px){.linkstate-grid{grid-template-columns:repeat(3,1fr)}}
</style>
<script>
(()=>{
const L=id=>document.getElementById(id),esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let last=0;
function inject(){const view=L('view-network');if(!view||L('linkStatePanel'))return;const s=document.createElement('section');s.id='linkStatePanel';s.innerHTML='<div class="sectionhead"><div><h2>Connection / Channel State</h2><div class="small">Automatically adapts to Wi-Fi or Ethernet/LAN.</div></div><button class="btn" id="linkStateRefresh">Refresh</button></div><div class="linkstate-grid" id="linkStateGrid"></div><div class="tablewrap linkstate-table"><table><thead><tr><th>Interface</th><th>Medium</th><th>State</th><th>Speed</th><th>Channel</th><th>Signal</th><th>SSID / Link</th></tr></thead><tbody id="linkStateRows"></tbody></table></div><div class="small" id="linkStateTruth" style="margin-top:8px"></div>';view.appendChild(s);L('linkStateRefresh').onclick=load}
async function load(){inject();try{const r=await fetch('/api/v1/system/link-state',{cache:'no-store'}),d=await r.json();if(!r.ok)throw new Error(`HTTP ${r.status}`);render(d);last=Date.now()}catch(e){if(L('linkStateGrid'))L('linkStateGrid').innerHTML=`<div><div class="label">State</div><strong>UNAVAILABLE</strong></div>`}}
function render(d){const a=d.active||{},wifi=String(a.medium||'').toUpperCase()==='WIFI';const rate=wifi?(a.rx_rate_mbps||a.tx_rate_mbps||0):(a.speed_mbps||0);L('linkStateGrid').innerHTML=[['Interface',a.name||d.selected_interface||'—'],['Medium',a.medium||'UNKNOWN'],['State',a.state||'UNKNOWN'],['Rate',rate?rate+' Mbps':'—'],['Channel',wifi?(a.channel??'—'):'N/A'],['Signal',wifi&&a.signal_percent!=null?a.signal_percent+'%':'N/A']].map(x=>`<div><div class="label">${esc(x[0])}</div><strong>${esc(x[1])}</strong></div>`).join('');L('linkStateRows').innerHTML=(d.interfaces||[]).map(x=>`<tr><td>${x.selected?'<b>':''}${esc(x.name)}${x.selected?'</b>':''}</td><td>${esc(x.medium)}</td><td>${esc(x.state)}</td><td>${esc(x.speed_mbps||x.rx_rate_mbps||x.tx_rate_mbps||'—')} Mbps</td><td>${x.medium==='WIFI'?esc(x.channel??'—'):'N/A'}</td><td>${x.medium==='WIFI'&&x.signal_percent!=null?esc(x.signal_percent)+'%':'N/A'}</td><td>${esc(x.ssid||x.duplex||'—')}</td></tr>`).join('');L('linkStateTruth').textContent=d.truth_note||''}
function tick(){inject();if(document.querySelector('.tab.active')?.dataset?.view==='network'&&Date.now()-last>4500)load()}setTimeout(tick,400);setInterval(tick,2500);
})();
</script>
"""
