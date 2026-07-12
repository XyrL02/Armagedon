"""Test safety gate functionality."""
import importlib
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'armagedon'))

# Modules with safety gates that accept mode= parameter in run()
SAFETY_MODULES = [
    'modules.exploits.zerologon',
    'modules.exploits.samaccountname_spoof',
    'modules.exploits.potato_attacks',
    'modules.exploits.cve_2024_21338_appid_privesc',
    'modules.exploits.cve_2024_26234_proxy_key_spoofing',
    'modules.exploits.cve_2024_26229_csc_privesc',
    'modules.exploits.cve_2025_21217_kernel_type_confusion',
    'modules.exploits.printnightmare_rce',
    'modules.post.persistence',
]

# Modules that do network/socket calls BEFORE the safety gate — need mocking
MODULES_NEEDING_MOCK = {
    'modules.exploits.zerologon': '_check_dc_reachable',
    'modules.exploits.samaccountname_spoof': '_check_dc_reachable',
}


@pytest.mark.parametrize("module_path", SAFETY_MODULES)
def test_exploit_blocked_in_safe_mode(module_path):
    """When SAFE_MODE=1, exploit mode should return BLOCKED."""
    mod = importlib.import_module(module_path)
    mod.SAFE_MODE = 1

    options = {
        'RHOSTS': '192.168.1.1',
        'SMB_USER': 'test',
        'SMB_PASS': 'test',
        'SMB_DOMAIN': 'TEST',
        'DC_IP': '192.168.1.1',
        'DOMAIN': 'test.local',
    }

    # Modules with pre-gate network calls need _check_dc_reachable mocked
    mock_target = MODULES_NEEDING_MOCK.get(module_path)
    if mock_target:
        with patch.object(mod, mock_target, return_value=True):
            result = mod.run(options=options, mode='EXPLOIT')
    else:
        result = mod.run(options=options, mode='EXPLOIT')

    blocked_by_gate = (
        result.get('data', {}).get('status') == 'BLOCKED'
        or 'BLOCKED' in str(result.get('error', ''))
    )
    assert blocked_by_gate, (
        f"{module_path} did not block in SAFE_MODE. "
        f"status={result.get('data', {}).get('status')!r} error={result.get('error')!r}"
    )


@pytest.mark.parametrize("module_path", SAFETY_MODULES)
def test_exploit_proceeds_when_safe_mode_off(module_path):
    """When SAFE_MODE=0, the safety gate allows exploit to proceed (past the gate)."""
    mod = importlib.import_module(module_path)
    mod.SAFE_MODE = 0

    options = {
        'RHOSTS': '192.168.1.1',
        'SMB_USER': 'test',
        'SMB_PASS': 'test',
        'SMB_DOMAIN': 'TEST',
        'DC_IP': '192.168.1.1',
        'DOMAIN': 'test.local',
    }

    mock_target = MODULES_NEEDING_MOCK.get(module_path)
    if mock_target:
        with patch.object(mod, mock_target, return_value=True):
            result = mod.run(options=options, mode='EXPLOIT')
    else:
        result = mod.run(options=options, mode='EXPLOIT')

    # Must NOT be blocked by safety gate (may fail for other reasons like
    # unreachable DC, missing tools, etc.)
    assert 'BLOCKED' not in str(result.get('error', '')), (
        f"{module_path} was blocked even with SAFE_MODE=0: {result.get('error')}"
    )


@pytest.mark.parametrize("module_path", SAFETY_MODULES)
def test_check_always_runs(module_path):
    """CHECK mode should never be blocked by the safety gate."""
    mod = importlib.import_module(module_path)
    mod.SAFE_MODE = 1

    options = {'RHOSTS': '192.168.1.1'}
    result = mod.run(options=options, mode='CHECK')

    # CHECK mode must not produce a BLOCKED status from the safety gate
    assert result.get('data', {}).get('status') != 'BLOCKED', (
        f"{module_path} safety gate blocked CHECK mode"
    )
    error = str(result.get('error', ''))
    assert 'BLOCKED' not in error or 'RHOSTS' in error or 'DC_IP' in error or 'required' in error, (
        f"{module_path} safety gate blocked CHECK mode with error: {error}"
    )


def test_safety_gate_is_callable():
    """Every safety-gated module defines _safety_gate()."""
    for module_path in SAFETY_MODULES:
        mod = importlib.import_module(module_path)
        assert callable(getattr(mod, '_safety_gate', None)), (
            f"{module_path} missing _safety_gate()"
        )


def test_safe_mode_defaults_to_one():
    """Modules default SAFE_MODE to 1 (safe) when env var is not set."""
    env = os.environ.copy()
    env.pop('ARMAGEDON_SAFE_MODE', None)
    with patch.dict(os.environ, env, clear=True):
        for module_path in SAFETY_MODULES:
            if module_path in sys.modules:
                del sys.modules[module_path]
            mod = importlib.import_module(module_path)
            assert mod.SAFE_MODE == 1, (
                f"{module_path} SAFE_MODE should default to 1, got {mod.SAFE_MODE}"
            )
