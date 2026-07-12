"""Test ArmagedonEngine module loading."""
import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'armagedon'))


def test_engine_imports():
    """Test that engine module imports cleanly."""
    from core.engine import ArmagedonEngine
    assert ArmagedonEngine is not None


def test_engine_init():
    """Test ArmagedonEngine initialization discovers modules."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    assert engine is not None
    assert engine.modules_dir.exists()
    assert isinstance(engine.modules, list)


def test_engine_discovers_modules():
    """Test that engine discovers real module files."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    # The framework has 21+ modules across 6 categories
    assert len(engine.modules) >= 15, (
        f"Expected at least 15 modules, found {len(engine.modules)}"
    )


def test_engine_module_has_metadata():
    """Each discovered module should have expected metadata fields."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    for mod_info in engine.modules:
        assert 'name' in mod_info, f"Module missing 'name': {mod_info}"
        assert 'filepath' in mod_info, f"Module missing 'filepath': {mod_info}"
        assert 'module' in mod_info, f"Module missing 'module': {mod_info}"
        assert 'type' in mod_info, f"Module missing 'type': {mod_info}"
        assert 'desc' in mod_info, f"Module missing 'desc': {mod_info}"
        assert 'options' in mod_info, f"Module missing 'options': {mod_info}"


def test_engine_list_modules_by_category():
    """Test filtering modules by category."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    exploits = engine.list_modules('exploits')
    assert len(exploits) >= 8, f"Expected >=8 exploit modules, found {len(exploits)}"
    for m in exploits:
        assert m['type'] == 'exploits'


def test_engine_get_module_names():
    """Test that get_module_names returns a sorted list of strings."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    names = engine.get_module_names()
    assert isinstance(names, list)
    assert len(names) >= 15
    assert all(isinstance(n, str) for n in names)
    assert names == sorted(names)


def test_engine_search_modules():
    """Test search finds modules by CVE or name."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    results = engine.search_modules('zerologon')
    assert len(results) >= 1
    assert any('zerologon' in m['name'].lower() for m in results)


def test_engine_load_module():
    """Test load_module sets active_module."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    # Load by full name
    loaded = engine.load_module('exploits/zerologon')
    assert loaded is True
    assert engine.active_module is not None
    assert 'zerologon' in engine.active_module['name'].lower()


def test_engine_load_module_by_short_name():
    """Test load_module works with just the stem name."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    loaded = engine.load_module('zerologon')
    assert loaded is True
    assert engine.active_module is not None


def test_engine_load_nonexistent_module():
    """Test load_module returns False for unknown module."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    loaded = engine.load_module('nonexistent_module_xyz')
    assert loaded is False


def test_engine_set_module_option():
    """Test set_module_option updates the active module."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    engine.load_module('zerologon')
    result = engine.set_module_option('RHOSTS', '10.0.0.1')
    assert result is True
    assert engine.active_module['options']['RHOSTS'] == '10.0.0.1'


def test_engine_set_option_without_module():
    """Test set_module_option returns False when no module is active."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    result = engine.set_module_option('RHOSTS', '10.0.0.1')
    assert result is False


def test_engine_run_module_without_selection():
    """Test run_module returns error when no module is selected."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    result = engine.run_module()
    assert result['success'] is False
    assert 'No module selected' in result['error']


def test_engine_check_module_without_selection():
    """Test check_module returns False when no module is selected."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    result = engine.check_module()
    assert result is False


def test_engine_modules_directory_exists():
    """Test that the modules directory exists on disk."""
    from core.engine import ArmagedonEngine
    engine = ArmagedonEngine()
    assert os.path.exists(engine.modules_dir)
    # Should have at least these subdirectories
    for sub in ['exploits', 'privesc', 'post', 'auxiliary']:
        assert (engine.modules_dir / sub).is_dir(), f"Missing modules/{sub}/"
