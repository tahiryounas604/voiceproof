"""VoiceProof — self-hosted payment approval on a signed channel."""
from .core import (
    DuplicateApprovalError,
    InvalidStateError,
    NotFoundError,
    SelfApprovalError,
    TokenError,
    TokenExpiredError,
    TokenReplayError,
    VoiceProof,
    VoiceProofError,
)

__version__ = "0.1.0"
__all__ = [
    "VoiceProof",
    "VoiceProofError",
    "TokenError",
    "TokenExpiredError",
    "TokenReplayError",
    "SelfApprovalError",
    "DuplicateApprovalError",
    "NotFoundError",
    "InvalidStateError",
    "__version__",
]
