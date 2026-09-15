from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from campus_ops.admin import install_admin_routes
from campus_ops.admin_ui import ADMIN_EXTENSION
from campus_ops.pathspace_ui import PATHSPACE_EXTENSION
from campus_ops.topology_ui import TOPOLOGY_EXTENSION


_STABLE_UI = r"""
<style>
/* Stable mode removes consoles that need separate agents/control/evidence pipelines,
   but keeps the packet-derived operational views operators actually use. */
button.tab[data-view="endpoints"],
button.tab[data-view="response"],
button.tab[data-view="evidence"],
button.tab[data-view="history"] { display:none !important; }
/* Stable Admin is passive/forensic. Do not expose controls whose workers are not running. */
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

  // Show the exact Linux capture interface. On WSL, eth0 may sit behind a Windows
  // Wi-Fi connection; guessing the physical medium from the Linux device name is wrong.
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
})();
</script>
"""


def install_stable_ui(app: FastAPI) -> FastAPI:
    if getattr(app.state, "stable_ui_installed", False):
        return app
    app.state.stable_ui_installed = True

    # Admin login/targets/forensics are local-only and operate on the same stable
    # snapshot. Response/containment workers are deliberately not started in stable mode.
    install_admin_routes(app)

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
