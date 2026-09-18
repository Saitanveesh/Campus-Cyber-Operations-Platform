from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from campus_ops.diagnostic_ui import DIAGNOSTIC_EXTENSION
from campus_ops.pathspace_ui import PATHSPACE_EXTENSION
from campus_ops.stable_operator import install_stable_operator_routes
from campus_ops.stable_operator_ui import STABLE_OPERATOR_EXTENSION
from campus_ops.topology_ui import TOPOLOGY_EXTENSION
from campus_ops.voice_ui import VOICE_EXTENSION


_WINDOWS_CONSOLE = r"""
<script>
(()=>{
  const product=document.querySelector('.product');
  if(product)product.textContent='MON Windows · Native 1.0.0';
  const state=document.querySelector('.headstate span');
  if(state)state.textContent='WINDOWS / TSHARK + NPCAP / REAL PACKET EVIDENCE';

  // The Windows product deliberately exposes only operator-useful workspaces. Assets
  // and raw Traffic remain internal data models used by Topology, Path Space and
  // Investigation; they are not separate consoles.
  for(const view of ['assets','traffic']){
    // Remove only the navigation entry. Keep the backing DOM view mounted because
    // the shared live renderer updates these nodes every second even though Windows
    // does not expose Assets/Traffic as standalone operator workspaces.
    document.querySelector(`button.tab[data-view="${view}"]`)?.remove();
    const backingView=document.getElementById(`view-${view}`);
    if(backingView)backingView.setAttribute('aria-hidden','true');
    try{delete pages[view]}catch{}
  }

  const nav=document.querySelector('nav');
  const order=['overview','network','topology','pathspace','security','investigation','system','watchdog'];
  if(nav){for(const name of order){const button=nav.querySelector(`button.tab[data-view="${name}"]`);if(button)nav.appendChild(button);}}

  const truth=document.querySelector('.truth');
  if(truth)truth.textContent='Native Windows MON uses one live packet source: TShark through Npcap on the elected Windows Wi-Fi/Ethernet adapter. IPs shown as targets or relationships must exist in current-session packet evidence. Unseen IPs are rejected; physical switch/router hops are never invented.';
})();
</script>
"""


def install_stable_ui(app: FastAPI) -> FastAPI:
    """Serve the native Windows MON console. There is no Admin panel."""
    if getattr(app.state, "stable_ui_installed", False):
        return app
    app.state.stable_ui_installed = True
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
                    f"{DIAGNOSTIC_EXTENSION}\n"
                    f"{VOICE_EXTENSION}\n"
                    f"{_WINDOWS_CONSOLE}\n"
                    "</body>"
                ),
            )
            return HTMLResponse(
                html,
                headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
            )
        return await call_next(request)

    return app
