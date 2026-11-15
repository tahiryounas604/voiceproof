import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from voiceproof import VoiceProof  # noqa: E402


@pytest.fixture()
def vp():
    instance = VoiceProof(db_path=":memory:", secret="test-secret-for-tests",
                          threshold=1000.0, token_ttl_seconds=3600)
    instance.register_approver("alice", credential="alice-credential-123")
    instance.register_approver("bob", credential="bob-credential-456")
    instance.register_approver("carol", credential="carol-credential-789")
    yield instance
    instance.close()
