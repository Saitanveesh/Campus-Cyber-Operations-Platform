import pytest

from campus_ops.ioc_store import IocStore


def test_ioc_store_normalizes_and_persists_indicators(tmp_path):
    path = tmp_path / "iocs.json"
    store = IocStore(path)

    ip = store.add(kind="IP", value="10.0.0.8", severity="HIGH", label="lab target")
    domain = store.add(kind="DOMAIN", value="Example.COM.", severity="MEDIUM")
    digest = store.add(kind="SHA256", value="A" * 64, severity="CRITICAL")

    assert ip["value"] == "10.0.0.8"
    assert domain["value"] == "example.com"
    assert digest["value"] == "a" * 64

    reloaded = IocStore(path)
    assert len(reloaded.list()) == 3


def test_ioc_store_rejects_duplicates_and_invalid_hash(tmp_path):
    store = IocStore(tmp_path / "iocs.json")
    store.add(kind="IP", value="10.0.0.8")

    with pytest.raises(ValueError, match="already exists"):
        store.add(kind="IP", value="10.0.0.8")
    with pytest.raises(ValueError, match="64 hexadecimal"):
        store.add(kind="SHA256", value="bad")
