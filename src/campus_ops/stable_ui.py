from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from campus_ops.diagnostic_ui import DIAGNOSTIC_EXTENSION
from campus_ops.pathspace_ui import PATHSPACE_EXTENSION
from campus_ops.stable_operator import install_stable_operator_routes
from campus_ops.stable_operator_ui import STABLE_OPERATOR_EXTENSION
from campus_ops.topology_ui import TOPOLOGY_EXTENSION


_STABLE_LABEL = r"""
<script>
(()=>{
  const product=document.querySelector('.product');
  if(product)product.textContent='Campus Cyber Operations Platform · Stable 0.5.0';
  const state=document.querySelector('.headstate span');
  if(state)state.textContent='PASSIVE / SINGLE SOURCE / V0.5.0';
})();
</script>
"""


def install_stable_ui(app: FastAPI) -> FastAPI:
    """Serve the stable-only console and local operator workspaces."""
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
                    f"{_STABLE_LABEL}\n"
                    "</body>"
                ),
            )
            return HTMLResponse(
                html,
                headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
            )
        return await call_next(request)

    return app
