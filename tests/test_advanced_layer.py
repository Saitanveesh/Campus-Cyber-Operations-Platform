from campus_ops.advanced_layer import build_process_dossier, persistence_diff


def test_process_dossier_builds_parent_tree_and_network_context():
    processes = [
        {"pid": 10, "ppid": 1, "name": "WINWORD.EXE", "memory_percent": 1.0},
        {
            "pid": 11,
            "ppid": 10,
            "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -NoProfile",
            "memory_percent": 2.0,
        },
    ]
    connections = [
        {
            "pid": 11,
            "type": "TCP",
            "local": "10.0.0.5:50000",
            "remote": "1.1.1.1:443",
            "status": "ESTABLISHED",
        }
    ]

    result = build_process_dossier(processes, connections)

    child = next(row for row in result["processes"] if row["pid"] == 11)
    assert child["parent_name"] == "WINWORD.EXE"
    assert child["connection_count"] == 1
    assert any(row["type"] == "UNUSUAL_PROCESS_LINEAGE" for row in result["findings"])
    assert any(row["type"] == "LOLBIN_WITH_NETWORK_ACTIVITY" for row in result["findings"])


def test_persistence_diff_reports_added_and_removed_items():
    old = [{"source": "HKCU", "name": "Old", "command": "old.exe"}]
    new = [{"source": "HKCU", "name": "New", "command": "new.exe"}]

    result = persistence_diff(old, new)

    assert result["added"] == new
    assert result["removed"] == old
