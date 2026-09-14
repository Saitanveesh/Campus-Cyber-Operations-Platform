ADMIN_LAYOUT_EXTENSION = r"""
<style>
#adminWorkspaceNav{gap:0!important}
#adminWorkspaceNav .admin-secondary{display:none!important}
#adminWorkspaceNav .admin-core{font-weight:700}
#adminWorkspaceNav .admin-validation{background:#111!important;color:#fff!important}
#adminWorkspaceNav .admin-validation.active{box-shadow:inset 0 -3px 0 #fff}
</style>
<script>
(()=>{
/*
Enterprise admin navigation is deliberately role-oriented instead of feature-oriented.
Dozens of backend engines still exist, but operators should not be forced to choose
between overlapping consoles. Hidden legacy views remain addressable internally and
are surfaced from their parent workspace when needed.
*/
const CORE=['admin-command','admin-forensics','admin-red','admin-infra'];
const SECONDARY=['admin-soc','admin-hunt','admin-deep','admin-ioc','admin-remote','admin-contain'];
const NAMES={
 'admin-command':'Operations',
 'admin-forensics':'Investigation',
 'admin-red':'Validation',
 'admin-infra':'Infrastructure'
};
function clean(){
 const sub=document.getElementById('adminWorkspaceNav');if(!sub)return;
 for(const view of CORE){
   const b=sub.querySelector(`button.tab[data-view="${view}"]`)||document.querySelector(`button.tab[data-view="${view}"]`);
   if(!b)continue;
   b.classList.add('admin-core');b.classList.remove('admin-secondary');
   if(NAMES[view])b.textContent=NAMES[view];
   if(view==='admin-red')b.classList.add('admin-validation');
   if(b.parentElement!==sub)sub.appendChild(b);
 }
 for(const view of SECONDARY){
   const b=document.querySelector(`button.tab[data-view="${view}"]`);
   if(b)b.classList.add('admin-secondary');
 }
 const label=sub.querySelector('.admin-nav-label');if(label)label.textContent='Admin';
}
setTimeout(clean,450);setInterval(clean,1800);
})();
</script>
"""
