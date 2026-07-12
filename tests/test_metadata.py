"""Test module metadata consistency."""
import importlib
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'armagedon'))

# Every module in the framework
ALL_MODULES = [
    'modules.exploits.zerologon',
    'modules.exploits.samaccountname_spoof',
    'modules.exploits.printnightmare_rce',
    'modules.exploits.potato_attacks',
    'modules.exploits.cve_2024_21338_appid_privesc',
    'modules.exploits.cve_2024_26234_proxy_key_spoofing',
    'modules.exploits.cve_2024_26229_csc_privesc',
    'modules.exploits.cve_2025_21217_kernel_type_confusion',
    'modules.exploits.cve_2024_38077_madlicense_eop',
    'modules.exploits.cve_2024_43641_ffi_registry_eop',
    'modules.privesc.token_steal',
    'modules.privesc.uac_bypass',
    'modules.privesc.service_privesc',
    'modules.privesc.stored_creds',
    'modules.post.credential_dump',
    'modules.post.persistence',
    'modules.post.lateral_movement',
    'modules.post.network_discovery',
    'modules.auxiliary.kerberos_attack',
    'modules.auxiliary.password_spray',
    'modules.auxiliary.ldap_enum',
]

# Modules that expose a NAME attribute (privesc + post + potato_attacks)
MODULES_WITH_NAME = [
    'modules.exploits.potato_attacks',
    'modules.privesc.token_steal',
    'modules.privesc.uac_bypass',
    'modules.privesc.service_privesc',
    'modules.privesc.stored_creds',
    'modules.post.credential_dump',
    'modules.post.persistence',
    'modules.post.lateral_movement',
    'modules.post.network_discovery',
]

# Modules that expose a public check() function
MODULES_WITH_CHECK = [
    'modules.exploits.cve_2024_21338_appid_privesc',
    'modules.exploits.cve_2024_26234_proxy_key_spoofing',
    'modules.exploits.cve_2024_26229_csc_privesc',
    'modules.exploits.cve_2025_21217_kernel_type_confusion',
    'modules.exploits.cve_2024_38077_madlicense_eop',
    'modules.exploits.cve_2024_43641_ffi_registry_eop',
    'modules.privesc.token_steal',
    'modules.privesc.uac_bypass',
    'modules.privesc.service_privesc',
    'modules.privesc.stored_creds',
    'modules.auxiliary.kerberos_attack',
    'modules.auxiliary.password_spray',
    'modules.auxiliary.ldap_enum',
]


@pytest.mark.parametrize("module_path", ALL_MODULES)
def test_module_has_description(module_path):
    """Every module must define a DESCRIPTION string (or DESCRIPTIONS dict for legacy modules)."""
    mod = importlib.import_module(module_path)
    has_desc = hasattr(mod, 'DESCRIPTION') and isinstance(mod.DESCRIPTION, str) and len(mod.DESCRIPTION) > 0
    has_descs = hasattr(mod, 'DESCRIPTIONS') and isinstance(mod.DESCRIPTIONS, dict) and len(mod.DESCRIPTIONS) > 0
    assert has_desc or has_descs, f"{module_path} missing DESCRIPTION or DESCRIPTIONS"


@pytest.mark.parametrize("module_path", ALL_MODULES)
def test_module_has_run(module_path):
    """Every module must define a callable run()."""
    mod = importlib.import_module(module_path)
    assert callable(getattr(mod, 'run', None)), f"{module_path} missing callable run()"


@pytest.mark.parametrize("module_path", MODULES_WITH_NAME)
def test_module_has_name(module_path):
    """Modules that define NAME must have it as a non-empty string."""
    mod = importlib.import_module(module_path)
    assert hasattr(mod, 'NAME'), f"{module_path} missing NAME"
    assert isinstance(mod.NAME, str), f"{module_path} NAME is not a string"
    assert len(mod.NAME) > 0, f"{module_path} NAME is empty"


@pytest.mark.parametrize("module_path", MODULES_WITH_CHECK)
def test_module_has_check(module_path):
    """Modules that define check() must have it as a callable."""
    mod = importlib.import_module(module_path)
    assert callable(getattr(mod, 'check', None)), f"{module_path} missing callable check()"


# Modules that define an OPTIONS dict (exploits except potato + auxiliary)
MODULES_WITH_OPTIONS = [
    'modules.exploits.zerologon',
    'modules.exploits.samaccountname_spoof',
    'modules.exploits.printnightmare_rce',
    'modules.exploits.cve_2024_21338_appid_privesc',
    'modules.exploits.cve_2024_26234_proxy_key_spoofing',
    'modules.exploits.cve_2024_26229_csc_privesc',
    'modules.exploits.cve_2025_21217_kernel_type_confusion',
    'modules.exploits.cve_2024_38077_madlicense_eop',
    'modules.exploits.cve_2024_43641_ffi_registry_eop',
    'modules.auxiliary.kerberos_attack',
    'modules.auxiliary.password_spray',
    'modules.auxiliary.ldap_enum',
]


@pytest.mark.parametrize("module_path", MODULES_WITH_OPTIONS)
def test_module_has_options(module_path):
    """Modules with OPTIONS must define it as a dict with RHOSTS."""
    mod = importlib.import_module(module_path)
    assert hasattr(mod, 'OPTIONS'), f"{module_path} missing OPTIONS"
    assert isinstance(mod.OPTIONS, dict), f"{module_path} OPTIONS is not a dict"
    assert 'RHOSTS' in mod.OPTIONS, f"{module_path} OPTIONS missing RHOSTS"


@pytest.mark.parametrize("module_path", MODULES_WITH_OPTIONS)
def test_module_has_rhosts_default(module_path):
    """RHOSTS should default to empty string."""
    mod = importlib.import_module(module_path)
    assert mod.OPTIONS.get('RHOSTS') == '', f"{module_path} RHOSTS should default to empty"
