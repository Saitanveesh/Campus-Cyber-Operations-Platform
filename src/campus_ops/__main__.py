from campus_ops import main, windows_service


if windows_service.service_mode_requested():
    windows_service.run_service_dispatcher()
else:
    main.main()
