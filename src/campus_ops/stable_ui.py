from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from campus_ops.admin_ui import ADMIN_EXTENSION
from campus_ops.pathspace_ui import PATHSPACE_EXTENSION
from campus_ops.stable_operator import install_stable_operator_routes
from campus_ops.topology_ui import TOPOLOGY_EXTENSION


_STABLE_UI = r"""
<style>
/* Stable mode removes consoles that need separate agents/control/evidence pipelines,
   but keeps the packet-derived operational views operators actually use. */
button.tab[data-view="endpoints"],
button.tab[data-view="response"],
button.tab[data-view="evidence"],
button.tab[data-view="history"] { display:none !important; }

/* There is no separate Admin panel in stable mode. Protected passive workspaces are
   first-class navigation items; authentication is requested only when one is opened. */
#adminButton{display:none!important}
button.tab[data-view="admin-hunt"],
button.tab[data-view="admin-forensics"]{display:block!important}

/* Stable mode is passive/forensic. Control surfaces whose workers are not running
   remain unavailable even after operator authentication. */
button.tab[data-view="admin-remote"],
button.tab[data-view="admin-contain"],
#view-admin-remote,
#view-admin-contain,
#adminForensicProbe { display:none !important; }
#view-security section.equal{display:none!important}
#view-system section.equal{display:none!important}
.stable-truth-note{margin:12px 0;padding:10px 12px;border:1px solid #c7c7c7;font-size:10px;line-height:1.45;color:#444}
</style>
<script>
(()=>{
  const allowed=new Set(['overview','network','topology','assets','traffic','security','system']);
  document.querySelectorAll('button.tab[data-view]').forEach(b=>{
    if(!allowed.has(b.dataset.view) && !b.dataset.view.startsWith('admin-')) b.style.display='none';
  });

  const product=document.querySelector('.product');
  if(product) product.textContent='Campus Cyber Operations Platform · Stable 0.4.2';
  const state=document.querySelector('.headstate span');
  if(state) state.textContent='MONITOR / V0.4.2 STABLE';

  // Show the exact capture interface. The selected interface is authoritative; the
  // physical upstream medium can differ in virtualised or bridged environments.
  const iface=document.getElementById('iface');
  if(iface&&iface.previousElementSibling){
    iface.previousElementSibling.textContent='Capture Interface';
  }
  document.querySelectorAll('#view-network h2').forEach(h=>{
    const title=(h.textContent||'').trim();
    if(title==='Network Interface') h.textContent='Capture Interface';
    if(title==='Wi-Fi Link'){
      const panel=h.closest('section.equal');
      const column=h.closest('div');
      if(column) column.style.display='none';
      if(panel) panel.style.gridTemplateColumns='1fr';
    }
  });

  // System should show the workers that actually run, not unused audio/adapters/tool hubs.
  document.querySelectorAll('#view-system section').forEach(section=>{
    const title=(section.querySelector('h2')?.textContent||'').trim();
    if(title==='Tools') section.style.display='none';
  });

  const overview=document.getElementById('view-overview');
  if(overview&&!document.getElementById('stableTruthNote')){
    const n=document.createElement('div');
    n.id='stableTruthNote';
    n.className='stable-truth-note';
    n.textContent='Stable 0.4.2: TShark is the only live packet source. Topology and Path Space are derived from that same packet stream, not extra capture tools. Capture stays ACTIVE while TShark is healthy; quiet traffic is not a failure. Assets require repeated local source-frame evidence with a unicast MAC.';
    overview.insertBefore(n, overview.firstChild);
  }

  function protectedToken(){
    return sessionStorage.getItem('campusOpsAdminToken')||'';
  }

  function openProtected(view){
    if(protectedToken()&&document.getElementById(`view-${view}`)){
      sessionStorage.removeItem('campusOpsPendingView');
      setView(view);
      return;
    }
    sessionStorage.setItem('campusOpsPendingView',view);
    const gateButton=document.getElementById('adminButton');
    if(gateButton){
      gateButton.click();
      return;
    }
    const gate=document.getElementById('adminGate');
    if(gate) gate.classList.add('show');
  }

  function ensureProtectedButton(nav,system,view,label){
    let primary=nav.querySelector(`button.protected-operator-tab[data-view="${view}"]`);
    if(!primary){
      primary=document.createElement('button');
      primary.className='tab protected-operator-tab';
      primary.dataset.view=view;
      primary.textContent=label;
      primary.onclick=()=>openProtected(view);
      nav.insertBefore(primary,system||null);
    }else{
      primary.classList.remove('admin-tab');
      if(primary.textContent!==label) primary.textContent=label;
      if(primary.dataset.promotedView!==view){
        primary.dataset.promotedView=view;
        primary.onclick=()=>openProtected(view);
      }
    }

    // The legacy admin extension may inject its own hidden copy after authentication.
    // Keep exactly one visible primary-nav button and discard those duplicate shells.
    nav.querySelectorAll(`button.admin-tab[data-view="${view}"]`).forEach(button=>{
      if(button!==primary) button.remove();
    });
    return primary;
  }

  function promoteProtectedViews(){
    const nav=document.querySelector('nav');
    if(!nav) return;
    const system=nav.querySelector('button.tab[data-view="system"]');
    const investigation=ensureProtectedButton(nav,system,'admin-hunt','Investigation');
    const forensics=ensureProtectedButton(nav,system,'admin-forensics','Forensics');

    if(system){
      if(investigation.nextElementSibling!==forensics||forensics.nextElementSibling!==system){
        nav.insertBefore(investigation,system);
        nav.insertBefore(forensics,system);
      }
    }

    try{
      pages['admin-hunt']=['Investigation','Passive target investigation across current-session evidence.'];
      pages['admin-forensics']=['Forensics','Evidence-centered target analysis for the active monitoring session.'];
    }catch{}

    const adminButton=document.getElementById('adminButton');
    if(adminButton) adminButton.style.display='none';

    const gate=document.getElementById('adminGate');
    if(gate){
      const title=gate.querySelector('.admin-login h2');
      if(title&&title.textContent!=='Operator Access') title.textContent='Operator Access';
      const warning=gate.querySelector('.admin-login .warning');
      const copy='Protected investigation workspaces are local-console only. Sign in to open passive investigation and forensic evidence views.';
      if(warning&&warning.textContent!==copy) warning.textContent=copy;
    }

    const hunt=document.getElementById('view-admin-hunt');
    if(hunt){
      const title=hunt.querySelector('h2');
      if(title&&title.textContent!=='Investigation Workspace') title.textContent='Investigation Workspace';
      const small=hunt.querySelector('.small');
      const copy='Select a target and pivot through current-session evidence without generating traffic.';
      if(small&&small.textContent!==copy) small.textContent=copy;
    }
    const forensic=document.getElementById('view-admin-forensics');
    if(forensic){
      const title=forensic.querySelector('h2');
      if(title&&title.textContent!=='Forensics Workbench') title.textContent='Forensics Workbench';
      const small=forensic.querySelector('.small');
      const copy='Passive evidence correlation for the selected target. Active probing is disabled in stable mode.';
      if(small&&small.textContent!==copy) small.textContent=copy;
    }

    const pending=sessionStorage.getItem('campusOpsPendingView');
    if(
      pending&&protectedToken()&&
      (pending==='admin-hunt'||pending==='admin-forensics')&&
      document.getElementById(`view-${pending}`)
    ){
      sessionStorage.removeItem('campusOpsPendingView');
      setView(pending);
    }
  }

  promoteProtectedViews();
  setInterval(promoteProtectedViews,700);
})();
</script>
"""


def install_stable_ui(app: FastAPI) -> FastAPI:
    if getattr(app.state, "stable_ui_installed", False):
        return app
    app.state.stable_ui_installed = True

    # Stable mode mounts authentication plus passive target/forensic routes only.
    # Active probe, remote-console and containment endpoints are intentionally absent.
    install_stable_operator_routes(app)

    @app.middleware("http")
    async def stable_console(request: Request, call_next):
        if request.method == "GET" and request.url.path == "/":
            ui_path = Path(__file__).parent / "ui" / "index.html"
            try:
                html = ui_path.read_text(encoding="utf-8")
            except OSError:
                return await call_next(request)
            html = html.replace(
                "</body>",
                f"{TOPOLOGY_EXTENSION}\n{PATHSPACE_EXTENSION}\n{ADMIN_EXTENSION}\n{_STABLE_UI}\n</body>",
            )
            return HTMLResponse(
                html,
                headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
            )
        return await call_next(request)

    return app
