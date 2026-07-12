"""Pytest fixtures for Armagedon integration tests."""

import pytest
from armagedon.tests.mock_rpc_server import MockTSLSPServer


@pytest.fixture(scope="module")
def server():
    """Module-scoped mock TSLSP RPC server."""
    srv = MockTSLSPServer(port=24444, verbose=False)
    srv.start()
    import time
    time.sleep(0.5)
    yield srv
    srv.stop()
