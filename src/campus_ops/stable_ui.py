from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from campus_ops.pathspace_ui import PATHSPACE_EXTENSION
from campus_ops.stable_operator import install_stable_operator_routes
from campus_ops.stable_operator_ui import STABLE_OPERATOR_EXTENSION
from campus_ops.topology_ui import TOPOLOGY_EXTENSION


_STABLE_UI = r"""
<style>
/* Stable mode exposes only views backed by the active single-source runtime. */
button.tab[data-view="endpoints"],
button.tab[data-view="response"],
button.tab[data-view="evidence"],
button.tab[data-view="history"] { display:none !important; }
#view-security section.equal{display:none!important}
#view-system section.equal{display:none!important}
.stable-truth-note{margin:12px 0;padding:10px 12px;border:1px solid #c7c7c7;font-size:10px;line-height:1.45;color:#444}
</style>
<script>
(()=>{
  const allowed=new Set(['overview','network','topology','pathspace','assets','traffic','security','investigation','forensics','system']);
  document.querySelectorAll('button.tab[data-view]').forEach(button=>{
    if(!allowed.has(button.dataset.view)) button.style.display='none';
  });

  const product=document.querySelector('.product');
  if(product) product.textContent='Campus Cyber Operations Platform · Stable 0.4.2';
  const state=document.querySelector('.headstate span');
  if(state) state.textContent='MONITOR / V0.4.2 STABLE';

  // The capture interface is the interface MON actually bound to. It must not be
  // inferred from a different UP adapter.
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

  // System shows the active stable runtime rather than unused tool-hub surfaces.
  document.querySelectorAll('#view-system section').forEach(section=>{
    const title=(section.querySelector('h2')?.textContent||'').trim();
    if(title==='Tools') section.style.display='none';
  });

  const overview=document.getElementById('view-overview');
  if(overview&&!document.getElementById('stableTruthNote')){
    const note=document.createElement('div');
    note.id='stableTruthNote';
    note.className='stable-truth-note';
    note.textContent='Stable 0.4.2: TShark is the only live packet source. Topology and Path Space are derived from that same packet stream. Capture remains ACTIVE while the TShark process is healthy; a quiet wire is not a link failure. Investigation and Forensics are passive protected workspaces.';
    overview.insertBefore(note,overview.firstChild);
  }
})();
</script>
"""


def install_stable_ui(app: FastAPI) -> FastAPI:
    if getattr(app.state, "stable_ui_installed", False):
        return app
    app.state.stable_ui_installed = True

    # Only authentication, target listing and passive forensic correlation are mounted
    # for the protected operator workspaces. The legacy Admin console is not injected.
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
                (
                    f"{TOPOLOGY_EXTENSION}\n"
                    f"{PATHSPACE_EXTENSION}\n"
                    f"{STABLE_OPERATOR_EXTENSION}\n"
                    f"{_STABLE_UI}\n"
                    "</body>"
                ),
            )
            return HTMLResponse(
                html,
                headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
            )
        return await call_next(request)

    return app
