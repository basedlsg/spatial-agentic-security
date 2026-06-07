"""Protocol failure reasons."""

from __future__ import annotations

from enum import Enum


class FailureReason(str, Enum):
    SWARM_COLLAPSED = "swarm_collapsed"
    MALFORMED_PACKET = "malformed_packet"
    UNREGISTERED_AGENT = "unregistered_agent"
    INACTIVE_AGENT = "inactive_agent"
    WRONG_EPOCH = "wrong_epoch"
    WRONG_MESSAGE_HASH = "wrong_message_hash"
    WRONG_CHALLENGE = "wrong_challenge"
    INVALID_SUBMISSION_NUMBER = "invalid_submission_number"
    DUPLICATE_SUBMISSION = "duplicate_submission"
    OVER_BUDGET = "over_budget"
    UNDER_BUDGET = "under_budget"
    LATE_PACKET = "late_packet"
    WRONG_SIGNATURE = "wrong_signature"
    DECRYPTION_FAILED = "decryption_failed"
    RESPONSE_BINDING_FAILED = "response_binding_failed"
    WRONG_PROOF_COMMITMENT = "wrong_proof_commitment"
    WRONG_GEOMETRY = "wrong_geometry"
    MISSING_PACKET = "missing_packet"
    ASSEMBLY_FAILED = "assembly_failed"
