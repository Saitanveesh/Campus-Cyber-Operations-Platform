ADMIN_LAYOUT_EXTENSION = r"""
<style>
#adminWorkspaceNav{gap:0!important}
#adminWorkspaceNav .admin-secondary{display:none!important}
#adminWorkspaceNav .admin-core{font-weight:700}
#adminWorkspaceNav .admin-redteam{background:#111!important;color:#fff!important}
#adminWorkspaceNav .admin-redteam.active{box-shadow:inset 0 -3px 0 #fff}
</style>
<script>
(()=>{
const CORE=['admin-command','admin-soc','admin-red','admin-forensics','admin-infra'];
const SECONDARY=['admin-hunt','admin-deep','admin-ioc','admin-remote','admin-contain'];
const NAMES={
 'admin-command':'Command Center',
 'admin-soc':'SOC Desk',
 'admin-red':'Red Team',
 'admin-forensics':'Forensics',
 'admin-infra':'Infrastructure'
};
function clean(){
 const sub=document.getElementById('adminWorkspaceNav');if(!sub)return;
 for(const view of CORE){const b=sub.querySelector(`button.tab[data-view="${view}"]`)||document.querySelector(`button.tab[data-view="${view}"]`);if(!b)continue;b.classList.add('admin-core');b.classList.remove('admin-secondary');if(NAMES[view])b.textContent=NAMES[view];if(view==='admin-red')b.classList.add('admin-redteam');if(b.parentElement!==sub)sub.appendChild(b)}
 for(const view of SECONDARY){const b=document.querySelector(`button.tab[data-view="${view}"]`);if(b)b.classList.add('admin-secondary')}
 const label=sub.querySelector('.admin-nav-label');if(label)label.textContent='Admin';
}
setTimeout(clean,450);setInterval(clean,1800);
})();
</script>
"""
