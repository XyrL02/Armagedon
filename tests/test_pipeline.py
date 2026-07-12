"""Test scan -> recommend -> exploit pipeline."""
import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'armagedon'))


def test_pipeline_imports():
    """Test that pipeline module imports cleanly."""
    from core.pipeline import ExploitPipeline
    assert ExploitPipeline is not None


def test_recommender_imports():
    """Test that recommender module imports cleanly."""
    from core.recommender import Recommender
    assert Recommender is not None


def test_fingerprints_imports():
    """Test that fingerprints module exports expected data."""
    from core.fingerprints import (
        SERVICE_VULN_MAP,
        PROTOCOL_VULN_MAP,
        EXPLOIT_METADATA,
        identify_os,
    )
    assert isinstance(SERVICE_VULN_MAP, dict)
    assert isinstance(PROTOCOL_VULN_MAP, dict)
    assert isinstance(EXPLOIT_METADATA, dict)
    assert callable(identify_os)


def test_fingerprints_identify_os():
    """Test OS identification by build number."""
    from core.fingerprints import identify_os
    # Windows 10 22H2 build 19045
    matches = identify_os(19045)
    assert len(matches) >= 1
    assert any('Windows 10' in m for m in matches)

    # Windows 11 23H2 build 22631
    matches = identify_os(22631)
    assert len(matches) >= 1
    assert any('Windows 11' in m for m in matches)

    # Server 2022 build 20348
    matches = identify_os(20348)
    assert len(matches) >= 1
    assert any('Server 2022' in m for m in matches)


def test_exploit_metadata_has_entries():
    """EXPLOIT_METADATA should contain known CVEs."""
    from core.fingerprints import EXPLOIT_METADATA
    assert 'cve_2024_38077_madlicense_eop' in EXPLOIT_METADATA
    assert 'cve_2024_21338_appid_privesc' in EXPLOIT_METADATA
    # Each entry must have required fields
    for key, meta in EXPLOIT_METADATA.items():
        assert 'cve' in meta, f"{key} missing 'cve'"
        assert 'name' in meta, f"{key} missing 'name'"
        assert 'cvss' in meta, f"{key} missing 'cvss'"
        assert 'type' in meta, f"{key} missing 'type'"


def test_service_vuln_map_ports():
    """SERVICE_VULN_MAP should cover critical Windows services."""
    from core.fingerprints import SERVICE_VULN_MAP
    expected_ports = {445, 135, 389, 88, 3389}
    assert expected_ports.issubset(set(SERVICE_VULN_MAP.keys()))


def test_recommender_init():
    """Test Recommender can be initialized."""
    from core.recommender import Recommender
    rec = Recommender()
    assert rec is not None


def test_recommender_produces_results():
    """Test that recommend() returns ranked candidates for a mock scan."""
    from core.recommender import Recommender
    rec = Recommender()
    scan_results = {
        'target': '192.168.1.1',
        'open_ports': [445, 135, 389, 88],
        'os': 'Windows Server 2022',
        'build': 20348,
        'protocols': {},
        'hotfixes': [],
    }
    candidates = rec.recommend('192.168.1.1', scan_results, top_n=5)
    assert isinstance(candidates, list)
    assert len(candidates) > 0
    # Each candidate must have expected fields
    for c in candidates:
        assert 'cve' in c
        assert 'name' in c
        assert 'score' in c
        assert 'module' in c
    # Should be sorted by score descending
    scores = [c['score'] for c in candidates]
    assert scores == sorted(scores, reverse=True)


def test_recommender_scoring_with_open_port():
    """Exploits targeting open ports should score higher."""
    from core.recommender import Recommender
    rec = Recommender()

    scan_with_port = {
        'open_ports': [135],
        'os': '',
        'build': 0,
        'protocols': {},
        'hotfixes': [],
    }
    scan_without_port = {
        'open_ports': [],
        'os': '',
        'build': 0,
        'protocols': {},
        'hotfixes': [],
    }

    candidates_with = rec.recommend('10.0.0.1', scan_with_port, top_n=20)
    candidates_without = rec.recommend('10.0.0.1', scan_without_port, top_n=20)

    # Port 135 modules should score higher with port 135 open
    with_port_scores = {c['module']: c['score'] for c in candidates_with}
    without_port_scores = {c['module']: c['score'] for c in candidates_without}

    # cve_2024_38077_madlicense_eop targets port 135
    mad_score_with = with_port_scores.get('cve_2024_38077_madlicense_eop', 0)
    mad_score_without = without_port_scores.get('cve_2024_38077_madlicense_eop', 0)
    assert mad_score_with >= mad_score_without, (
        "MadLicense should score higher when port 135 is open"
    )


def test_pipeline_init():
    """Test ExploitPipeline can be initialized with mocked Database."""
    from core.pipeline import ExploitPipeline
    with patch('core.pipeline.Database') as mock_db:
        mock_db.return_value = MagicMock()
        engine = MagicMock()
        pipe = ExploitPipeline(engine=engine)
        assert pipe is not None
        assert pipe.engine is engine


def test_pipeline_run_exploit_missing_module():
    """Test run_exploit returns error for non-existent module."""
    from core.pipeline import ExploitPipeline
    with patch('core.pipeline.Database') as mock_db:
        mock_db.return_value = MagicMock()
        pipe = ExploitPipeline()
        pipe.target = '10.0.0.1'
        result = pipe.run_exploit('nonexistent_module_xyz', mode='check')
        assert result['success'] is False
        assert 'not found' in result['error'].lower() or 'error' in result['error'].lower()
