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
.stable-truth-note{margin:12px 0;padding:10px 12px;border:1px solid #c7c7c7;font-size:10px;line-height:1.45;color:#444}
</style>
<script>
(()=>{
  const allowed=new Set(['overview','network','assets','traffic','security','system']);
  document.querySelectorAll('button.tab[data-view]').forEach(b=>{
    if(!allowed.has(b.dataset.view)) b.style.display='none';
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
