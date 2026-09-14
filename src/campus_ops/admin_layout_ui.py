ADMIN_LAYOUT_EXTENSION = r"""
<style>
#adminWorkspaceNav{gap:0!important}
#adminWorkspaceNav .admin-secondary{display:none!important}
#adminWorkspaceNav .admin-core{font-weight:700}
#adminWorkspaceNav .admin-validation{background:#111!important;color:#fff!important}
#adminWorkspaceNav .admin-validation.active{box-shadow:inset 0 -3px 0 #fff}
#adminAutonomy{margin-top:16px}.admin-autonomy-grid{display:grid;grid-template-columns:repeat(4,1fr);border-left:1px solid #c7c7c7;border-top:1px solid #c7c7c7}.admin-autonomy-grid>div{padding:11px;border-right:1px solid #c7c7c7;border-bottom:1px solid #c7c7c7}.admin-autonomy-grid strong{display:block;font-size:17px;margin-top:5px}.admin-auto-row{display:grid;grid-template-columns:minmax(130px,1fr) 70px 130px 130px;gap:8px;padding:8px 0;border-bottom:1px solid #ddd;font-size:10px}
@media(max-width:900px){.admin-autonomy-grid{grid-template-columns:1fr 1fr}.admin-auto-row{grid-template-columns:1fr 70px 1fr}}
</style>
<script>
(()=>{
/* Four role-oriented workspaces replace overlapping feature consoles. */
const CORE=['admin-command','admin-forensics','admin-red','admin-infra'];
const SECONDARY=['admin-soc','admin-hunt','admin-deep','admin-ioc','admin-remote','admin-contain'];
const NAMES={
 'admin-command':'Operations',
 'admin-forensics':'Investigation',
 'admin-red':'Validation',
 'admin-infra':'Infrastructure'
};
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function clean(){
 const sub=$('adminWorkspaceNav');if(!sub)return;
 for(const view of CORE){
   const b=sub.querySelector(`button.tab[data-view="${view}"]`)||document.querySelector(`button.tab[data-view="${view}"]`);
   if(!b)continue;b.classList.add('admin-core');b.classList.remove('admin-secondary');if(NAMES[view])b.textContent=NAMES[view];if(view==='admin-red')b.classList.add('admin-validation');if(b.parentElement!==sub)sub.appendChild(b);
 }
 for(const view of SECONDARY){const b=document.querySelector(`button.tab[data-view="${view}"]`);if(b)b.classList.add('admin-secondary')}
 const label=sub.querySelector('.admin-nav-label');if(label)label.textContent='Admin';
}
function installAutonomy(){
 const host=$('view-admin-command');if(!host||$('adminAutonomy'))return;
 const s=document.createElement('section');s.id='adminAutonomy';s.innerHTML=`<div class="sectionhead"><div><h2>Governed Autonomy</h2><div class="small">Closed-loop response recommendations with evidence and control gates.</div></div><button class="btn" id="adminAutoRefresh">Refresh</button></div><div class="admin-autonomy-grid" id="adminAutoSummary"></div><div class="panel" style="margin-top:12px"><div class="label">Response Candidates</div><div id="adminAutoRows" style="margin-top:8px"></div></div>`;host.appendChild(s);$('adminAutoRefresh').onclick=loadAutonomy;loadAutonomy();
}
async function loadAutonomy(){
 if(!$('adminAutonomy'))return;
 try{const r=await fetch('/api/v1/system/autonomy',{cache:'no-store'}),d=await r.json();if(!r.ok)throw new Error('HTTP '+r.status);const rows=d.decisions||[],eligible=rows.filter(x=>x.automation_gate==='ELIGIBLE').length;$('adminAutoSummary').innerHTML=[['Mode',d.mode||'—'],['Candidates',d.decision_count||0],['Isolation eligible',eligible],['Auto containment',d.automatic_containment_enabled?'ENABLED':'OFF']].map(x=>`<div><div class="label">${esc(x[0])}</div><strong>${esc(x[1])}</strong></div>`).join('');$('adminAutoRows').innerHTML=rows.slice(0,12).map(x=>`<div class="admin-auto-row"><b class="mono">${esc(x.target)}</b><span>${esc(x.risk_score)}</span><span>${esc(x.recommendation)}</span><span>${esc(x.automation_gate)}</span></div>`).join('')||'<div class="muted">No current response candidates.</div>'}catch(e){$('adminAutoRows').textContent='Autonomy engine unavailable: '+e.message}
}
function tick(){clean();installAutonomy()}
setTimeout(tick,450);setInterval(tick,1800);setInterval(loadAutonomy,5000);
})();
</script>
"""
