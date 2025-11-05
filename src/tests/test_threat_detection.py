"""
Pytest suite for ThreatDetectionEngine.
"""
import pytest
import asyncio
from secureops_ai.src.scanners.threat_detection import ThreatDetectionEngine

@pytest.mark.asyncio
async def test_analyze_events_detects_threat():
    engine = ThreatDetectionEngine()
    events = [
        {"description": "Suspicious login attempt"},
        {"description": "Normal activity"},
    ]
    threats = await engine.analyze_events(events)
    assert any(t["threat_level"] in ("high", "critical") for t in threats)

@pytest.mark.asyncio
async def test_analyze_events_no_threat():
    engine = ThreatDetectionEngine()
    events = [
        {"description": "Normal activity"},
    ]
    threats = await engine.analyze_events(events)
    assert threats == []
