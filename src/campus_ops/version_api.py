from __future__ import annotations

from fastapi import FastAPI

from campus_ops.version import build_info, package_version


def install_version_api(app: FastAPI) -> FastAPI:
    if getattr(app.state, "version_api_installed", False):
        return app
    app.state.version_api_installed = True
    app.version = package_version()

    @app.get("/api/v1/system/version")
    async def system_version() -> dict[str, object]:
        return build_info()

    return app
