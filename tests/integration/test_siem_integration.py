import pytest
from integrators.siem_connector import SiemConnector

@pytest.mark.asyncio
async def test_siem_fetch():
    c = SiemConnector()
    items = await c.fetch()
    assert isinstance(items, list)
    assert all(isinstance(i, dict) for i in items)

@pytest.mark.asyncio
async def test_siem_fetch_returns_events():
    connector = SiemConnector()
    events = await connector.fetch()
    assert isinstance(events, list)
    assert len(events) >= 1

@pytest.mark.asyncio
async def test_siem_fetch_monkeypatch(monkeypatch):
    async def dummy_fetch(self):
        return [{"event": "login", "user": "alice"}]
    monkeypatch.setattr(SiemConnector, "fetch", dummy_fetch)
    c = SiemConnector()
    items = await c.fetch()
    assert items == [{"event": "login", "user": "alice"}]
import pytest

from integrators.siem_connector import SiemConnector


@pytest.mark.asyncio
async def test_siem_fetch():
    c = SiemConnector()
    items = await c.fetch()
    assert isinstance(items, list)
    assert all(isinstance(i, dict) for i in items)


@pytest.mark.asyncio
async def test_siem_fetch_returns_events():
    connector = SiemConnector()
    events = await connector.fetch()
    assert isinstance(events, list)
    assert len(events) >= 1
