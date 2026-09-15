from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse


_STABLE_UI = r"""
<style>
/* Stable mode deliberately exposes only views backed by the single packet pipeline. */
button.tab[data-view="topology"],
button.tab[data-view="endpoints"],
button.tab[data-view="response"],
button.tab[data-view="evidence"],
button.tab[data-view="history"] { display:none !important; }
#view-security section.equal{display:none!important}
#view-system section.equal{display:none!important}
tr[data-asset]{cursor:default!important}
.stable-truth-note{margin:12px 0;padding:10px 12px;border:1px solid #c7c7c7;font-size:10px;line-height:1.45;color:#444}
</style>
<script>
(()=>{
  const allowed=new Set(['overview','network','assets','traffic','security','system']);
  document.querySelectorAll('button.tab[data-view]').forEach(b=>{
    if(!allowed.has(b.dataset.view)) b.style.display='none';
  });

  const product=document.querySelector('.product');
  if(product) product.textContent='Campus Cyber Operations Platform · Stable 0.4';
  const state=document.querySelector('.headstate span');
  if(state) state.textContent='MONITOR / V0.4 STABLE';

  // The base UI used asset-row clicks to open the now-hidden Topology console.
  // Stable mode keeps Assets as a truth-scoped inventory table and blocks that stale path.
  document.addEventListener('click',e=>{
    if(e.target.closest&&e.target.closest('tr[data-asset]')){
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  },true);

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
    n.textContent='Stable mode: TShark is the single live packet source. Assets require repeated local source-frame evidence with a unicast MAC. Remote Internet addresses are shown only as traffic peers, not as local assets.';
    overview.insertBefore(n, overview.firstChild);
  }
})();
</script>
"""


def install_stable_ui(app: FastAPI) -> FastAPI:
    if getattr(app.state, "stable_ui_installed", False):
        return app
    app.state.stable_ui_installed = True

    @app.middleware("http")
    async def stable_console(request: Request, call_next):
        if request.method == "GET" and request.url.path == "/":
            ui_path = Path(__file__).parent / "ui" / "index.html"
            try:
                html = ui_path.read_text(encoding="utf-8")
            except OSError:
                return await call_next(request)
            html = html.replace("</body>", f"{_STABLE_UI}\n</body>")
            return HTMLResponse(
                html,
                headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
            )
        return await call_next(request)

    return app
