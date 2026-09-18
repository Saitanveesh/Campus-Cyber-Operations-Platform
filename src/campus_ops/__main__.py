from __future__ import annotations

from campus_ops.main import main
from campus_ops.windows_service import run_service_dispatcher, service_mode_requested


if service_mode_requested():
    run_service_dispatcher()
else:
    main()
