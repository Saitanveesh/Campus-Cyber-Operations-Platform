from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import uvicorn

from campus_ops.config import DEFAULT_SETTINGS
from campus_ops.main import build_app
from campus_ops.platform_paths import data_root

SERVICE_NAME = "MONWindows"
SERVICE_DISPLAY_NAME = "MON Windows Network Monitor"
SERVICE_DESCRIPTION = (
    "Native Windows passive network monitor using one TShark/Npcap packet source."
)


def _configure_service_logging() -> Path:
    log_path = data_root() / "mon-service.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(
        isinstance(handler, RotatingFileHandler)
        and Path(getattr(handler, "baseFilename", "")) == log_path
        for handler in root.handlers
    ):
        handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        root.addHandler(handler)
    return log_path


def _load_pywin32() -> tuple[Any, Any, Any, Any]:
    if os.name != "nt":
        raise RuntimeError("MON Windows Service can run only on native Windows")
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
    except ImportError as exc:
        raise RuntimeError("pywin32 is required for the native MON Windows Service") from exc
    return servicemanager, win32event, win32service, win32serviceutil


def service_class() -> type[Any]:
    servicemanager, win32event, win32service, win32serviceutil = _load_pywin32()

    class MONWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.server: uvicorn.Server | None = None
            self.log_path = _configure_service_logging()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            logging.getLogger(__name__).info("Windows Service stop requested")
            server = self.server
            if server is not None:
                server.should_exit = True
            win32event.SetEvent(self.stop_event)

        def SvcShutdown(self) -> None:
            self.SvcStop()

        def SvcDoRun(self) -> None:
            logger = logging.getLogger(__name__)
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} starting")
            logger.info("%s starting; log=%s", SERVICE_NAME, self.log_path)
            try:
                config = uvicorn.Config(
                    build_app(),
                    host=DEFAULT_SETTINGS.host,
                    port=DEFAULT_SETTINGS.port,
                    log_level="info",
                    access_log=False,
                    log_config=None,
                )
                self.server = uvicorn.Server(config)
                self.server.run()
                logger.info("%s stopped", SERVICE_NAME)
                servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")
            except BaseException as exc:
                logger.exception("%s crashed", SERVICE_NAME)
                try:
                    servicemanager.LogErrorMsg(f"{SERVICE_NAME} crashed: {exc}")
                finally:
                    raise
            finally:
                self.server = None

    return MONWindowsService


def run_service_dispatcher() -> None:
    """Enter the Windows Service Control Manager dispatcher from the frozen EXE."""
    servicemanager, _, _, _ = _load_pywin32()
    service = service_class()
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(service)
    servicemanager.StartServiceCtrlDispatcher()


def service_mode_requested(argv: list[str] | None = None) -> bool:
    values = sys.argv[1:] if argv is None else argv
    return any(value.casefold() == "--service" for value in values)
