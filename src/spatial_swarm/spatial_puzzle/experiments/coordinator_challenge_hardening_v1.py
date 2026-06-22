"""Coordinator / Challenge Hardening v1.

This experiment sits on top of Minimal Core Gate v1. The coordinator may request
or schedule an action, but the wrapper recomputes the challenge truth before
geometry or sandbox execution.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable, Optional

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.experiments.metrics import (
    process_resource_use,
    write_metrics,
    write_metrics_and_digest,
)
from spatial_swarm.experiments.redaction import redaction_report
from spatial_swarm.experiments.report import utc_run_id, write_git_commit
from spatial_swarm.spatial_puzzle.experiments import formation_gate as FG
from spatial_swarm.spatial_puzzle.experiments import minimal_core_gate_v1 as MCG
from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.protocol import (
    ChallengeBuilder,
    ChallengeEnvelope,
    ChallengeTranscript,
    ChallengeVerifier,
    ChallengeVerifierConfig,
    CoordinatorModel,
)
from spatial_swarm.spatial_puzzle.protocol.challenge_builder import NO_TRANSACTION_DIGEST
from spatial_swarm.spatial_puzzle.sandbox import ContainerAdapter, EffectRecord, SandboxSpec


VALID_ACTION_TYPES = V3.VALID_ACTION_TYPES

HONEST_CHALLENGES = VALID_ACTION_TYPES + ("valid_read_edit_tests_transaction",)
RISK_DOWNGRADE_ATTACKS = (
    "credential_read_marked_low_risk",
    "delete_file_marked_low_risk",
    "push_marked_low_risk",
    "run_command_marked_low_risk",
    "install_package_marked_low_risk",
    "high_risk_uses_medium_required_agents",
    "medium_risk_uses_low_required_agents",
)
FEWER_AGENT_ATTACKS = (
    "credential_read_fresh_2_agents",
    "push_fresh_2_agents",
    "delete_file_fresh_2_agents",
    "run_command_fresh_2_agents",
    "correct_count_wrong_identities",
    "required_set_missing_one",
    "required_set_swaps_trusted_for_fake",
    "required_set_duplicates_one_agent",
)
ALLOWED_EFFECTS_EXPANSION_ATTACKS = (
    "read_file_challenge_allows_write",
    "edit_file_challenge_allows_test_edit",
    "run_tests_challenge_allows_credential_read",
    "delete_file_challenge_allows_source_deletion",
    "install_package_challenge_allows_write_outside_vendor",
    "push_challenge_allows_remote_change",
    "credential_read_challenge_allows_raw_output",
)
ACTION_SUBSTITUTION_ATTACKS = (
    "read_file_challenge_used_for_delete_file",
    "run_tests_challenge_used_for_credential_read",
    "edit_file_challenge_used_for_push",
    "safe_command_challenge_used_for_dangerous_command",
    "same_action_type_different_path",
    "same_action_type_different_args",
    "same_action_type_different_credential_handle",
)
TRANSACTION_CHALLENGE_SCENARIOS = (
    "valid_read_edit_tests_transaction",
    "same_actions_reordered",
    "delete_inserted_after_edit",
    "credential_read_inserted_mid_transaction",
    "push_remote_changed_final_step",
    "transaction_digest_removed",
    "old_transaction_digest_reused",
    "two_valid_partial_transactions_spliced",
)
MULTI_VIEW_ATTACKS = (
    "split_action_hash_across_agents",
    "split_nonce_across_agents",
    "split_role_map_across_agents",
    "split_required_agent_set_across_agents",
    "split_allowed_effects_digest_across_agents",
    "split_transaction_digest_across_agents",
)
REPLAY_FRESHNESS_ATTACKS = (
    "old_valid_challenge_reused",
    "old_nonce_reused",
    "old_challenge_used_after_expiration",
    "old_challenge_used_for_same_action_new_transaction",
    "old_challenge_used_with_new_effects",
    "old_challenge_used_with_new_agent_set",
)
COORDINATOR_IDENTITY_ATTACKS = (
    "unknown_coordinator_id",
    "coordinator_id_changed_after_challenge",
    "coordinator_id_missing",
    "challenge_issuer_mismatch",
    "same_coordinator_issues_two_conflicting_challenges",
)
ABLATIONS = (
    "full_challenge_gate",
    "no_wrapper_recompute",
    "no_risk_recompute",
    "no_required_agent_recompute",
    "no_required_agent_identity_binding",
    "no_action_hash_binding",
    "no_allowed_effects_digest_binding",
    "no_transaction_digest_binding",
    "no_nonce_freshness",
    "no_challenge_expiry",
    "no_multi_view_consistency",
    "no_geometry_after_challenge",
)
CONSTANT_FAILURE_SCENARIOS = (
    "credential_read_marked_low_risk",
    "credential_read_fresh_2_agents",
    "read_file_challenge_allows_write",
    "read_file_challenge_used_for_delete_file",
    "split_action_hash_across_agents",
    "old_valid_challenge_reused",
)


@dataclass(frozen=True)
class ChallengeGateGuard:
    wrapper_recompute: bool = True
    risk_recompute: bool = True
    required_agent_recompute: bool = True
    required_agent_identity_binding: bool = True
    action_hash_binding: bool = True
    allowed_effects_digest_binding: bool = True
    transaction_digest_binding: bool = True
    nonce_freshness: bool = True
    challenge_expiry: bool = True
    multi_view_consistency: bool = True
    geometry_after_challenge: bool = True
    coordinator_identity_check: bool = True
    min_block_ms: float = 4.0
    public_log_bytes: int = V3.PUBLIC_LOG_BYTES
    container_image: str = "slop-code:python3.12"
    minimal_core: MCG.MinimalGuard = field(default_factory=MCG.MinimalGuard)

    def verifier_config(
        self,
        *,
        now: int = 1_700_000_010,
        used_nonces: frozenset[str] = frozenset(),
    ) -> ChallengeVerifierConfig:
        return ChallengeVerifierConfig(
            wrapper_recompute=self.wrapper_recompute,
            risk_recompute=self.risk_recompute,
            required_agent_recompute=self.required_agent_recompute,
            required_agent_identity_binding=self.required_agent_identity_binding,
            action_hash_binding=self.action_hash_binding,
            allowed_effects_digest_binding=self.allowed_effects_digest_binding,
            transaction_digest_binding=self.transaction_digest_binding,
            nonce_freshness=self.nonce_freshness,
            challenge_expiry=self.challenge_expiry,
            multi_view_consistency=self.multi_view_consistency,
            geometry_after_challenge=self.geometry_after_challenge,
            coordinator_identity_check=self.coordinator_identity_check,
            now=now,
            used_nonces=used_nonces,
        )

    def execution_guard(self) -> MCG.MinimalGuard:
        return replace(
            self.minimal_core,
            geometry_enabled=False,
            min_block_ms=self.min_block_ms,
            public_log_bytes=self.public_log_bytes,
            container_image=self.container_image,
        )


@dataclass(frozen=True)
class ChallengeDecision:
    suite: str
    scenario: str
    trial_index: int
    released: bool
    executed: bool
    blocked: bool
    policy_allowed: bool
    challenge_verified: bool
    formation_released: bool
    contained_started: bool
    effect_violation: bool
    transaction_violation: bool
    blocked_before_geometry: bool
    blocked_at_geometry: bool
    blocked_before_sandbox: bool
    public_reason: str
    visible_checks: int
    public_event_count: int
    public_log_bytes: int
    killed_session: bool
    elapsed_ms: float
    internal_reasons: tuple[str, ...]
    challenge_digest: str = ""
    transaction_digest: str = NO_TRANSACTION_DIGEST
    actual_effect: EffectRecord = field(default_factory=EffectRecord)
    allowed_effect: EffectRecord = field(default_factory=EffectRecord)
    host_effects_detected: int = 0
    raw_credential_leaked: bool = False
    unapproved_network_released: bool = False
    unapproved_git_remote_released: bool = False
    container_backend: str = "docker"

    @property
    def visible_shape(self) -> tuple[str, int, int, int, bool]:
        return (
            self.public_reason,
            self.visible_checks,
            self.public_event_count,
            self.public_log_bytes,
            self.killed_session,
        )


TranscriptFactory = Callable[[V3.ActionEnvelopeV3, ChallengeBuilder, CoordinatorModel], tuple[ChallengeEnvelope, ChallengeTranscript]]


def _canonical_env(
    raw: V3.RawAction,
    *,
    scenario: str,
    trial_index: int,
    guard: ChallengeGateGuard,
    repo_mutator: Optional[V3.RepoMutator] = None,
) -> V3.ActionEnvelopeV3:
    exec_guard = guard.execution_guard().v3()
    with tempfile.TemporaryDirectory(prefix="spatial-challenge-canon-") as tmp:
        workspace = Path(tmp)
        adapter = ContainerAdapter(exec_guard.spec_for(raw))
        repo = adapter.create_repo_template(workspace)
        if repo_mutator is not None:
            repo_mutator(repo, workspace)
        return V3.ActionCanonicalizerV3(repo, guard=exec_guard, raw=raw).envelope(
            nonce_label=f"{scenario}:{trial_index}"
        )


def _blocked(
    suite: str,
    scenario: str,
    trial_index: int,
    guard: ChallengeGateGuard,
    started: float,
    reasons: list[str],
    *,
    policy_allowed: bool = False,
    challenge_verified: bool = False,
    formation_released: bool = False,
    contained_started: bool = False,
    effect_violation: bool = False,
    transaction_violation: bool = False,
    blocked_before_geometry: bool = False,
    blocked_at_geometry: bool = False,
    blocked_before_sandbox: bool = False,
    challenge_digest: str = "",
    transaction_digest: str = NO_TRANSACTION_DIGEST,
    actual_effect: EffectRecord = EffectRecord(),
    allowed_effect: EffectRecord = EffectRecord(),
    raw_credential_leaked: bool = False,
    container_backend: str = "docker",
) -> ChallengeDecision:
    elapsed = (time.perf_counter() - started) * 1000
    if elapsed < guard.min_block_ms:
        time.sleep((guard.min_block_ms - elapsed) / 1000)
        elapsed = (time.perf_counter() - started) * 1000
    return ChallengeDecision(
        suite=suite,
        scenario=scenario,
        trial_index=trial_index,
        released=False,
        executed=False,
        blocked=True,
        policy_allowed=policy_allowed,
        challenge_verified=challenge_verified,
        formation_released=formation_released,
        contained_started=contained_started,
        effect_violation=effect_violation,
        transaction_violation=transaction_violation,
        blocked_before_geometry=blocked_before_geometry,
        blocked_at_geometry=blocked_at_geometry,
        blocked_before_sandbox=blocked_before_sandbox,
        public_reason="blocked",
        visible_checks=64,
        public_event_count=4,
        public_log_bytes=guard.public_log_bytes,
        killed_session=True,
        elapsed_ms=elapsed,
        internal_reasons=tuple(sorted(set(reasons))),
        challenge_digest=challenge_digest,
        transaction_digest=transaction_digest,
        actual_effect=actual_effect,
        allowed_effect=allowed_effect,
        raw_credential_leaked=raw_credential_leaked,
        container_backend=container_backend,
    )


def _released(
    suite: str,
    scenario: str,
    trial_index: int,
    guard: ChallengeGateGuard,
    started: float,
    *,
    executed: bool = True,
    policy_allowed: bool = True,
    challenge_verified: bool = True,
    formation_released: bool = True,
    contained_started: bool = True,
    effect_violation: bool = False,
    transaction_violation: bool = False,
    challenge_digest: str = "",
    transaction_digest: str = NO_TRANSACTION_DIGEST,
    actual_effect: EffectRecord = EffectRecord(),
    allowed_effect: EffectRecord = EffectRecord(),
    raw_credential_leaked: bool = False,
    unapproved_network_released: bool = False,
    unapproved_git_remote_released: bool = False,
    container_backend: str = "docker",
) -> ChallengeDecision:
    return ChallengeDecision(
        suite=suite,
        scenario=scenario,
        trial_index=trial_index,
        released=True,
        executed=executed,
        blocked=False,
        policy_allowed=policy_allowed,
        challenge_verified=challenge_verified,
        formation_released=formation_released,
        contained_started=contained_started,
        effect_violation=effect_violation,
        transaction_violation=transaction_violation,
        blocked_before_geometry=False,
        blocked_at_geometry=False,
        blocked_before_sandbox=False,
        public_reason="released",
        visible_checks=48,
        public_event_count=3,
        public_log_bytes=128,
        killed_session=False,
        elapsed_ms=(time.perf_counter() - started) * 1000,
        internal_reasons=(),
        challenge_digest=challenge_digest,
        transaction_digest=transaction_digest,
        actual_effect=actual_effect,
        allowed_effect=allowed_effect,
        raw_credential_leaked=raw_credential_leaked,
        unapproved_network_released=unapproved_network_released,
        unapproved_git_remote_released=unapproved_git_remote_released,
        container_backend=container_backend,
    )


def _verify_geometry(
    challenge: ChallengeEnvelope,
    *,
    trial_index: int,
    attack: str = "valid",
) -> tuple[bool, tuple[str, ...]]:
    arm = FG.FormationArm(challenge.formation_family, FG.FormationConfig(), trial_index)
    fg_challenge = FG.FormationChallenge(
        arm=challenge.formation_family,
        action_hash=challenge.action_hash,
        nonce=challenge.nonce,
        risk=challenge.risk_level,
        required_agents=challenge.required_agent_set,
    )
    proofs = []
    for agent in challenge.required_agent_set:
        if agent in arm.agent_ids:
            proofs.append(arm.sidecar(agent).prove(fg_challenge))
    if attack == "fake_proof" and proofs:
        p = proofs[0]
        proofs[0] = replace(p, tag=FG._mutate_hex(p.tag))
    decision = FG.SpatialFormationGate(arm).verify(fg_challenge, tuple(proofs))
    return decision.released, tuple(f"formation:{reason}" for reason in decision.internal_reasons)


def _execute_after_release(
    raw: V3.RawAction,
    *,
    suite: str,
    scenario: str,
    trial_index: int,
    guard: ChallengeGateGuard,
    actual_behavior: str = "declared",
    repo_mutator: Optional[V3.RepoMutator] = None,
) -> V3.V3Decision:
    return MCG.attempt_core_action(
        raw,
        suite=suite,
        scenario=scenario,
        trial_index=trial_index,
        guard=guard.execution_guard(),
        actual_behavior=actual_behavior,
        repo_mutator=repo_mutator,
    )


def attempt_challenge_action(
    raw: V3.RawAction,
    *,
    suite: str,
    scenario: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
    challenge_factory: TranscriptFactory | None = None,
    transaction_digest: str = NO_TRANSACTION_DIGEST,
    expected_transaction_digest: str = NO_TRANSACTION_DIGEST,
    actual_behavior: str = "declared",
    repo_mutator: Optional[V3.RepoMutator] = None,
    used_nonces: frozenset[str] = frozenset(),
    now: int = 1_700_000_010,
    geometry_attack: str = "valid",
    execute: bool = True,
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    started = time.perf_counter()
    env = _canonical_env(
        raw,
        scenario=scenario,
        trial_index=trial_index,
        guard=guard,
        repo_mutator=repo_mutator,
    )
    policy_allowed, policy_reason = V3.PolicyGateV3(guard.execution_guard().v3()).evaluate(env)
    if not policy_allowed:
        dummy_builder = ChallengeBuilder(trial_index, issued_at=1_700_000_000 + trial_index)
        challenge = dummy_builder.build(env, transaction_digest=expected_transaction_digest)
        return (
            _blocked(
                suite,
                scenario,
                trial_index,
                guard,
                started,
                [f"policy:{policy_reason}"],
                allowed_effect=env.allowed_effects,
                challenge_digest=challenge.wrapper_challenge_digest,
                transaction_digest=expected_transaction_digest,
                blocked_before_geometry=True,
                blocked_before_sandbox=True,
            ),
            ChallengeTranscript.from_challenge(challenge),
        )

    builder = ChallengeBuilder(trial_index, issued_at=1_700_000_000 + trial_index)
    model = CoordinatorModel(builder)
    if challenge_factory is None:
        challenge, transcript = model.honest(env, transaction_digest=expected_transaction_digest)
    else:
        challenge, transcript = challenge_factory(env, builder, model)
    verifier = ChallengeVerifier(
        guard.verifier_config(now=now, used_nonces=used_nonces)
    )
    verification = verifier.verify(
        challenge,
        env=env,
        builder=builder,
        transcript=transcript,
        transaction_digest=expected_transaction_digest,
    )
    if not verification.verified:
        return (
            _blocked(
                suite,
                scenario,
                trial_index,
                guard,
                started,
                list(verification.internal_reasons),
                policy_allowed=True,
                challenge_verified=False,
                blocked_before_geometry=True,
                blocked_before_sandbox=True,
                challenge_digest=challenge.wrapper_challenge_digest,
                transaction_digest=expected_transaction_digest,
                allowed_effect=env.allowed_effects,
            ),
            transcript,
        )

    if guard.geometry_after_challenge:
        formation_released, formation_reasons = _verify_geometry(
            challenge,
            trial_index=trial_index,
            attack=geometry_attack,
        )
        if not formation_released:
            return (
                _blocked(
                    suite,
                    scenario,
                    trial_index,
                    guard,
                    started,
                    list(formation_reasons),
                    policy_allowed=True,
                    challenge_verified=True,
                    formation_released=False,
                    blocked_at_geometry=True,
                    blocked_before_sandbox=True,
                    challenge_digest=challenge.wrapper_challenge_digest,
                    transaction_digest=expected_transaction_digest,
                    allowed_effect=env.allowed_effects,
                ),
                transcript,
            )
    else:
        formation_released = True

    if not execute:
        return (
            _released(
                suite,
                scenario,
                trial_index,
                guard,
                started,
                executed=False,
                contained_started=False,
                transaction_violation=transaction_digest != expected_transaction_digest,
                challenge_digest=challenge.wrapper_challenge_digest,
                transaction_digest=expected_transaction_digest,
                allowed_effect=env.allowed_effects,
            ),
            transcript,
        )

    row = _execute_after_release(
        raw,
        suite=suite,
        scenario=scenario,
        trial_index=trial_index,
        guard=guard,
        actual_behavior=actual_behavior,
        repo_mutator=repo_mutator,
    )
    if row.released:
        return (
            _released(
                suite,
                scenario,
                trial_index,
                guard,
                started,
                executed=row.executed,
                contained_started=row.contained_started,
                effect_violation=row.effect_violation,
                challenge_digest=challenge.wrapper_challenge_digest,
                transaction_digest=expected_transaction_digest,
                actual_effect=row.actual_effect,
                allowed_effect=row.allowed_effect,
                raw_credential_leaked=row.raw_credential_leaked,
                unapproved_network_released=row.unapproved_network_released,
                unapproved_git_remote_released=row.unapproved_git_remote_released,
                container_backend=row.container_backend,
            ),
            transcript,
        )
    return (
        _blocked(
            suite,
            scenario,
            trial_index,
            guard,
            started,
            list(row.internal_reasons),
            policy_allowed=True,
            challenge_verified=True,
            formation_released=formation_released,
            contained_started=row.contained_started,
            effect_violation=row.effect_violation,
            blocked_before_sandbox=False,
            challenge_digest=challenge.wrapper_challenge_digest,
            transaction_digest=expected_transaction_digest,
            actual_effect=row.actual_effect,
            allowed_effect=row.allowed_effect,
            raw_credential_leaked=row.raw_credential_leaked,
            container_backend=row.container_backend,
        ),
        transcript,
    )


def _raw_for_risk(name: str) -> V3.RawAction:
    mapping = {
        "credential_read_marked_low_risk": V3._default_raw("credential_read"),
        "delete_file_marked_low_risk": V3._default_raw("delete_file"),
        "push_marked_low_risk": V3._default_raw("push"),
        "run_command_marked_low_risk": V3._default_raw("run_command"),
        "install_package_marked_low_risk": V3._default_raw("install_package"),
        "high_risk_uses_medium_required_agents": V3._default_raw("credential_read"),
        "medium_risk_uses_low_required_agents": V3._default_raw("run_command"),
    }
    return mapping[name]


def _factory_risk(name: str) -> TranscriptFactory:
    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        if name.endswith("uses_medium_required_agents"):
            return model.fewer_agents(env, count=4)
        if name.endswith("uses_low_required_agents"):
            return model.fewer_agents(env, count=2)
        return model.risk_downgrade(env, risk_level="low")

    return make


def run_honest_challenge(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    if name == "valid_read_edit_tests_transaction":
        return run_transaction_challenge(name, trial_index, guard)
    return attempt_challenge_action(
        V3._default_raw(name),
        suite="honest_challenge",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
    )


def run_risk_downgrade(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    return attempt_challenge_action(
        _raw_for_risk(name),
        suite="risk_downgrade",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=_factory_risk(name),
    )


def run_fewer_agent_challenge(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    raw = {
        "credential_read_fresh_2_agents": V3._default_raw("credential_read"),
        "push_fresh_2_agents": V3._default_raw("push"),
        "delete_file_fresh_2_agents": V3._default_raw("delete_file"),
        "run_command_fresh_2_agents": V3._default_raw("run_command"),
        "correct_count_wrong_identities": V3._default_raw("edit_file"),
        "required_set_missing_one": V3._default_raw("credential_read"),
        "required_set_swaps_trusted_for_fake": V3._default_raw("credential_read"),
        "required_set_duplicates_one_agent": V3._default_raw("credential_read"),
    }[name]

    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        if name.endswith("fresh_2_agents"):
            return model.fewer_agents(env, count=2)
        if name == "correct_count_wrong_identities":
            return model.wrong_agent_identities(env, variant="swap_trusted_for_known")
        if name == "required_set_missing_one":
            return model.wrong_agent_identities(env, variant="missing_one")
        if name == "required_set_swaps_trusted_for_fake":
            return model.wrong_agent_identities(env, variant="swap_trusted_for_fake")
        return model.wrong_agent_identities(env, variant="duplicate_agent")

    return attempt_challenge_action(
        raw,
        suite="fewer_agent",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=make,
    )


def run_allowed_effects_expansion(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    raw = {
        "read_file_challenge_allows_write": V3._default_raw("read_file"),
        "edit_file_challenge_allows_test_edit": V3._default_raw("edit_file"),
        "run_tests_challenge_allows_credential_read": V3._default_raw("run_tests"),
        "delete_file_challenge_allows_source_deletion": V3._default_raw("delete_file"),
        "install_package_challenge_allows_write_outside_vendor": V3._default_raw("install_package"),
        "push_challenge_allows_remote_change": V3._default_raw("push"),
        "credential_read_challenge_allows_raw_output": V3._default_raw("credential_read"),
    }[name]

    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        return model.allowed_effects_expansion(env, label=name)

    return attempt_challenge_action(
        raw,
        suite="allowed_effects_expansion",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=make,
    )


def _old_env_for_substitution(
    name: str,
    *,
    scenario: str,
    trial_index: int,
    guard: ChallengeGateGuard,
) -> V3.ActionEnvelopeV3:
    old_raw = {
        "read_file_challenge_used_for_delete_file": V3._default_raw("read_file"),
        "run_tests_challenge_used_for_credential_read": V3._default_raw("run_tests"),
        "edit_file_challenge_used_for_push": V3._default_raw("edit_file"),
        "safe_command_challenge_used_for_dangerous_command": V3._default_raw("run_command"),
        "same_action_type_different_path": V3.RawAction("read_file", "README.md"),
        "same_action_type_different_args": V3._default_raw("run_command"),
        "same_action_type_different_credential_handle": V3.RawAction(
            "credential_read", credential_handle="CI_DEPLOY_HANDLE"
        ),
    }[name]
    return _canonical_env(old_raw, scenario=scenario + ":old", trial_index=trial_index, guard=guard)


def run_action_substitution(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    raw = {
        "read_file_challenge_used_for_delete_file": V3._default_raw("delete_file"),
        "run_tests_challenge_used_for_credential_read": V3._default_raw("credential_read"),
        "edit_file_challenge_used_for_push": V3._default_raw("push"),
        "safe_command_challenge_used_for_dangerous_command": V3.RawAction(
            "run_command", args=("sh", "-c", "echo bad")
        ),
        "same_action_type_different_path": V3.RawAction("read_file", "src/app.py"),
        "same_action_type_different_args": V3.RawAction("run_command", args=("python", "scripts/safe_format.py")),
        "same_action_type_different_credential_handle": V3._default_raw("credential_read"),
    }[name]

    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        old_env = _old_env_for_substitution(name, scenario=name, trial_index=trial_index, guard=guard)
        return model.action_substitution(env, old_env=old_env)

    return attempt_challenge_action(
        raw,
        suite="action_substitution",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=make,
    )


def _transaction_envs(trial_index: int, guard: ChallengeGateGuard):
    with tempfile.TemporaryDirectory(prefix="spatial-challenge-tx-") as tmp:
        repo = ContainerAdapter(guard.execution_guard().v3().spec_for(V3._default_raw("read_file"))).create_repo_template(Path(tmp))
        canon = lambda raw, label: V3.ActionCanonicalizerV3(
            repo,
            guard=guard.execution_guard().v3(),
            raw=raw,
        ).envelope(nonce_label=f"challenge-tx:{trial_index}:{label}")
        read = canon(V3._default_raw("read_file"), "read")
        edit = canon(V3._default_raw("edit_file"), "edit")
        tests = canon(V3._default_raw("run_tests"), "tests")
        delete = canon(V3._default_raw("delete_file"), "delete")
        credential = canon(V3._default_raw("credential_read"), "credential")
        push_bad = canon(V3.RawAction("push", git_remote="evil-remote"), "push_bad")
        valid_tx = V3.transaction_envelope((read, edit, tests))
        return {
            "read": read,
            "edit": edit,
            "tests": tests,
            "delete": delete,
            "credential": credential,
            "push_bad": push_bad,
            "valid": valid_tx,
            "reordered": V3.transaction_envelope((read, tests, edit)),
            "delete_inserted": V3.transaction_envelope((read, edit, delete)),
            "credential_inserted": V3.transaction_envelope((read, credential, edit, tests)),
            "push_bad_final": V3.transaction_envelope((read, edit, push_bad)),
            "removed": "removed",
            "old": sha256_hex({"kind": "old_transaction_digest", "trial": trial_index}),
            "spliced": V3.transaction_envelope((read, edit)),
        }


def run_transaction_challenge(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    tx = _transaction_envs(trial_index, guard)
    expected = tx["valid"].transaction_hash
    if name == "valid_read_edit_tests_transaction":
        row = MCG.run_transaction_scenario(
            "valid_read_edit_tests",
            trial_index,
            guard.execution_guard(),
        )
        started = time.perf_counter()
        env = tx["read"]
        builder = ChallengeBuilder(trial_index, issued_at=1_700_000_000 + trial_index)
        challenge, transcript = CoordinatorModel(builder).honest(env, transaction_digest=expected)
        if row.released:
            return (
                _released(
                    "transaction_challenge",
                    name,
                    trial_index,
                    guard,
                    started,
                    challenge_digest=challenge.wrapper_challenge_digest,
                    transaction_digest=expected,
                    actual_effect=row.actual_effect,
                    allowed_effect=row.allowed_effect,
                    container_backend=row.container_backend,
                ),
                transcript,
            )
        return (
            _blocked(
                "transaction_challenge",
                name,
                trial_index,
                guard,
                started,
                list(row.internal_reasons),
                policy_allowed=True,
                challenge_verified=True,
                formation_released=True,
                contained_started=row.contained_started,
                challenge_digest=challenge.wrapper_challenge_digest,
                transaction_digest=expected,
                actual_effect=row.actual_effect,
                allowed_effect=row.allowed_effect,
            ),
            transcript,
        )

    false_digest = {
        "same_actions_reordered": tx["reordered"].transaction_hash,
        "delete_inserted_after_edit": tx["delete_inserted"].transaction_hash,
        "credential_read_inserted_mid_transaction": tx["credential_inserted"].transaction_hash,
        "push_remote_changed_final_step": tx["push_bad_final"].transaction_hash,
        "transaction_digest_removed": "removed",
        "old_transaction_digest_reused": tx["old"],
        "two_valid_partial_transactions_spliced": tx["spliced"].transaction_hash,
    }[name]

    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        return model.transaction_substitution(env, false_transaction_digest=false_digest)

    return attempt_challenge_action(
        V3._default_raw("read_file"),
        suite="transaction_challenge",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=make,
        expected_transaction_digest=expected,
        transaction_digest=false_digest,
        execute=False,
    )


def run_multi_view_challenge(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    field = {
        "split_action_hash_across_agents": "action_hash",
        "split_nonce_across_agents": "nonce",
        "split_role_map_across_agents": "role_map_digest",
        "split_required_agent_set_across_agents": "required_agent_set_digest",
        "split_allowed_effects_digest_across_agents": "allowed_effects_digest",
        "split_transaction_digest_across_agents": "transaction_digest",
    }[name]

    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        return model.split_view(env, field=field)

    return attempt_challenge_action(
        V3._default_raw("credential_read"),
        suite="multi_view",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=make,
    )


def run_replay_freshness(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    raw = V3._default_raw("credential_read")
    stale_now = 1_700_001_000

    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        if name == "old_challenge_used_after_expiration":
            return model.stale(env, issued_at=1_699_999_000, expires_at=1_699_999_100)
        if name == "old_challenge_used_for_same_action_new_transaction":
            return model.transaction_substitution(env, false_transaction_digest="old_tx_digest")
        if name == "old_challenge_used_with_new_effects":
            return model.allowed_effects_expansion(env, label=name)
        if name == "old_challenge_used_with_new_agent_set":
            return model.fewer_agents(env, count=2)
        return model.honest(env)

    temp_builder = ChallengeBuilder(trial_index, issued_at=1_700_000_000 + trial_index)
    temp_env = _canonical_env(raw, scenario=name, trial_index=trial_index, guard=guard)
    temp_challenge, _ = CoordinatorModel(temp_builder).honest(temp_env)
    used = frozenset({temp_challenge.nonce}) if name in {"old_valid_challenge_reused", "old_nonce_reused"} else frozenset()
    now = stale_now if name == "old_challenge_used_after_expiration" else 1_700_000_010
    return attempt_challenge_action(
        raw,
        suite="replay_freshness",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=make,
        used_nonces=used,
        now=now,
    )


def run_coordinator_identity(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    coordinator_id = {
        "unknown_coordinator_id": "coordinator_evil",
        "coordinator_id_changed_after_challenge": "coordinator_evil",
        "coordinator_id_missing": "",
        "challenge_issuer_mismatch": "coordinator_evil",
        "same_coordinator_issues_two_conflicting_challenges": "coordinator_001",
    }[name]

    def make(env: V3.ActionEnvelopeV3, builder: ChallengeBuilder, model: CoordinatorModel):
        challenge, transcript = model.coordinator_identity(env, coordinator_id=coordinator_id)
        if name == "same_coordinator_issues_two_conflicting_challenges":
            transcript = transcript.with_split("allowed_effects_digest", "conflicting_effect_digest")
        return challenge, transcript

    return attempt_challenge_action(
        V3._default_raw("read_file"),
        suite="coordinator_identity",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        challenge_factory=make,
    )


def _guard_for_ablation(name: str, base: ChallengeGateGuard) -> ChallengeGateGuard:
    mapping = {
        "full_challenge_gate": base,
        "no_wrapper_recompute": replace(base, wrapper_recompute=False),
        "no_risk_recompute": replace(base, risk_recompute=False),
        "no_required_agent_recompute": replace(base, required_agent_recompute=False),
        "no_required_agent_identity_binding": replace(base, required_agent_identity_binding=False),
        "no_action_hash_binding": replace(base, action_hash_binding=False),
        "no_allowed_effects_digest_binding": replace(base, allowed_effects_digest_binding=False),
        "no_transaction_digest_binding": replace(base, transaction_digest_binding=False),
        "no_nonce_freshness": replace(base, nonce_freshness=False),
        "no_challenge_expiry": replace(base, challenge_expiry=False),
        "no_multi_view_consistency": replace(base, multi_view_consistency=False),
        "no_geometry_after_challenge": replace(base, geometry_after_challenge=False),
    }
    return mapping[name]


def run_ablation_case(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    ablated = _guard_for_ablation(name, guard)
    if name == "full_challenge_gate":
        row, transcript = run_fewer_agent_challenge("credential_read_fresh_2_agents", trial_index, ablated)
    elif name == "no_wrapper_recompute":
        row, transcript = run_fewer_agent_challenge("credential_read_fresh_2_agents", trial_index, ablated)
    elif name == "no_risk_recompute":
        row, transcript = run_risk_downgrade("credential_read_marked_low_risk", trial_index, ablated)
    elif name == "no_required_agent_recompute":
        row, transcript = run_fewer_agent_challenge("credential_read_fresh_2_agents", trial_index, ablated)
    elif name == "no_required_agent_identity_binding":
        row, transcript = run_fewer_agent_challenge("correct_count_wrong_identities", trial_index, ablated)
    elif name == "no_action_hash_binding":
        row, transcript = run_action_substitution("same_action_type_different_path", trial_index, ablated)
    elif name == "no_allowed_effects_digest_binding":
        row, transcript = run_allowed_effects_expansion("read_file_challenge_allows_write", trial_index, ablated)
    elif name == "no_transaction_digest_binding":
        row, transcript = run_transaction_challenge("same_actions_reordered", trial_index, ablated)
    elif name == "no_nonce_freshness":
        row, transcript = run_replay_freshness("old_valid_challenge_reused", trial_index, ablated)
    elif name == "no_challenge_expiry":
        row, transcript = run_replay_freshness("old_challenge_used_after_expiration", trial_index, ablated)
    elif name == "no_multi_view_consistency":
        row, transcript = run_multi_view_challenge("split_action_hash_across_agents", trial_index, ablated)
    elif name == "no_geometry_after_challenge":
        row, transcript = attempt_challenge_action(
            V3._default_raw("credential_read"),
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=ablated,
            geometry_attack="fake_proof",
        )
    else:
        raise ValueError(name)
    return replace(row, suite="ablation", scenario=name), transcript


def run_constant_failure_case(
    name: str,
    trial_index: int,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[ChallengeDecision, ChallengeTranscript]:
    if name in RISK_DOWNGRADE_ATTACKS:
        return run_risk_downgrade(name, trial_index, guard)
    if name in FEWER_AGENT_ATTACKS:
        return run_fewer_agent_challenge(name, trial_index, guard)
    if name in ALLOWED_EFFECTS_EXPANSION_ATTACKS:
        return run_allowed_effects_expansion(name, trial_index, guard)
    if name in ACTION_SUBSTITUTION_ATTACKS:
        return run_action_substitution(name, trial_index, guard)
    if name in MULTI_VIEW_ATTACKS:
        return run_multi_view_challenge(name, trial_index, guard)
    if name in REPLAY_FRESHNESS_ATTACKS:
        return run_replay_freshness(name, trial_index, guard)
    raise ValueError(name)


def _counts(mode: str) -> dict[str, int]:
    if mode == "smoke":
        return {
            "valid_trials": 20,
            "attack_trials": 50,
            "ablation_trials": 20,
            "transaction_trials": 20,
            "multi_view_trials": 20,
            "replay_trials": 20,
            "constant_failure_trials": 20,
        }
    if mode == "core":
        return {
            "valid_trials": 100,
            "attack_trials": 200,
            "ablation_trials": 100,
            "transaction_trials": 100,
            "multi_view_trials": 100,
            "replay_trials": 100,
            "constant_failure_trials": 100,
        }
    if mode == "full":
        return {
            "valid_trials": 200,
            "attack_trials": 500,
            "ablation_trials": 200,
            "transaction_trials": 300,
            "multi_view_trials": 300,
            "replay_trials": 300,
            "constant_failure_trials": 500,
        }
    raise ValueError(mode)


def _prop(rows: list[ChallengeDecision], attr: str) -> dict:
    successes = sum(1 for row in rows if getattr(row, attr))
    return {"successes": successes, "n": len(rows), "rate": successes / len(rows) if rows else 0.0}


def _summary_values(values: list[float]) -> dict:
    if not values:
        return {"min": None, "p50": None, "p95": None, "max": None}
    ordered = sorted(values)
    return {
        "min": ordered[0],
        "p50": ordered[len(ordered) // 2],
        "p95": ordered[min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)],
        "max": ordered[-1],
    }


def summarize(rows: list[ChallengeDecision]) -> dict:
    return {
        "attempts": len(rows),
        "release": _prop(rows, "released"),
        "executed": _prop(rows, "executed"),
        "blocked": _prop(rows, "blocked"),
        "policy_allowed": _prop(rows, "policy_allowed"),
        "challenge_verified": _prop(rows, "challenge_verified"),
        "formation_released": _prop(rows, "formation_released"),
        "contained_started": _prop(rows, "contained_started"),
        "effect_violation": _prop(rows, "effect_violation"),
        "transaction_violation": _prop(rows, "transaction_violation"),
        "blocked_before_geometry": _prop(rows, "blocked_before_geometry"),
        "blocked_at_geometry": _prop(rows, "blocked_at_geometry"),
        "blocked_before_sandbox": _prop(rows, "blocked_before_sandbox"),
        "raw_credential_leaked": _prop(rows, "raw_credential_leaked"),
        "unapproved_network_released": _prop(rows, "unapproved_network_released"),
        "unapproved_git_remote_released": _prop(rows, "unapproved_git_remote_released"),
        "host_effects_detected": sum(row.host_effects_detected for row in rows),
        "public_reasons": dict(Counter(row.public_reason for row in rows)),
        "visible_shape_count": len({row.visible_shape for row in rows}),
        "visible_checks": _summary_values([float(row.visible_checks) for row in rows]),
        "public_event_count": _summary_values([float(row.public_event_count) for row in rows]),
        "public_log_bytes": _summary_values([float(row.public_log_bytes) for row in rows]),
        "elapsed_ms": _summary_values([row.elapsed_ms for row in rows]),
        "container_backends": dict(Counter(row.container_backend for row in rows)),
        "internal_reasons": dict(Counter(reason for row in rows for reason in row.internal_reasons)),
    }


def _by_name(rows: list[ChallengeDecision], names: tuple[str, ...]) -> dict[str, dict]:
    return {name: summarize([row for row in rows if row.scenario == name]) for name in names}


def _all_releases(rows: list[ChallengeDecision], *, exclude: set[str] = frozenset()) -> int:
    return sum(row.released for row in rows if row.scenario not in exclude)


def run_experiment(
    *,
    mode: str = "smoke",
    valid_trials: Optional[int] = None,
    attack_trials: Optional[int] = None,
    ablation_trials: Optional[int] = None,
    transaction_trials: Optional[int] = None,
    multi_view_trials: Optional[int] = None,
    replay_trials: Optional[int] = None,
    constant_failure_trials: Optional[int] = None,
    guard: ChallengeGateGuard = ChallengeGateGuard(),
) -> tuple[dict, dict[str, list[ChallengeDecision]], dict[str, list[ChallengeTranscript]]]:
    counts = _counts(mode)
    overrides = {
        "valid_trials": valid_trials,
        "attack_trials": attack_trials,
        "ablation_trials": ablation_trials,
        "transaction_trials": transaction_trials,
        "multi_view_trials": multi_view_trials,
        "replay_trials": replay_trials,
        "constant_failure_trials": constant_failure_trials,
    }
    for key, value in overrides.items():
        if value is not None:
            counts[key] = value

    transcripts: dict[str, list[ChallengeTranscript]] = {}

    def collect(name: str, pairs):
        rows = []
        views = []
        for row, transcript in pairs:
            rows.append(row)
            views.append(transcript)
        transcripts[name] = views
        return rows

    honest_rows = collect(
        "honest",
        (
            run_honest_challenge(name, trial, guard)
            for name in HONEST_CHALLENGES
            for trial in range(counts["valid_trials"])
        ),
    )
    risk_rows = collect(
        "risk",
        (
            run_risk_downgrade(name, trial, guard)
            for name in RISK_DOWNGRADE_ATTACKS
            for trial in range(counts["attack_trials"])
        ),
    )
    fewer_rows = collect(
        "fewer_agent",
        (
            run_fewer_agent_challenge(name, trial, guard)
            for name in FEWER_AGENT_ATTACKS
            for trial in range(counts["attack_trials"])
        ),
    )
    effect_rows = collect(
        "allowed_effects",
        (
            run_allowed_effects_expansion(name, trial, guard)
            for name in ALLOWED_EFFECTS_EXPANSION_ATTACKS
            for trial in range(counts["attack_trials"])
        ),
    )
    substitution_rows = collect(
        "action_substitution",
        (
            run_action_substitution(name, trial, guard)
            for name in ACTION_SUBSTITUTION_ATTACKS
            for trial in range(counts["attack_trials"])
        ),
    )
    transaction_rows = collect(
        "transaction",
        (
            run_transaction_challenge(name, trial, guard)
            for name in TRANSACTION_CHALLENGE_SCENARIOS
            for trial in range(counts["transaction_trials"])
        ),
    )
    multi_rows = collect(
        "multi_view",
        (
            run_multi_view_challenge(name, trial, guard)
            for name in MULTI_VIEW_ATTACKS
            for trial in range(counts["multi_view_trials"])
        ),
    )
    replay_rows = collect(
        "replay",
        (
            run_replay_freshness(name, trial, guard)
            for name in REPLAY_FRESHNESS_ATTACKS
            for trial in range(counts["replay_trials"])
        ),
    )
    coordinator_rows = collect(
        "coordinator",
        (
            run_coordinator_identity(name, trial, guard)
            for name in COORDINATOR_IDENTITY_ATTACKS
            for trial in range(counts["attack_trials"])
        ),
    )
    ablation_rows = collect(
        "ablation",
        (
            run_ablation_case(name, trial, guard)
            for name in ABLATIONS
            for trial in range(counts["ablation_trials"])
        ),
    )
    constant_rows = collect(
        "constant",
        (
            run_constant_failure_case(name, trial, guard)
            for name in CONSTANT_FAILURE_SCENARIOS
            for trial in range(counts["constant_failure_trials"])
        ),
    )

    transaction_attack_releases = _all_releases(
        transaction_rows,
        exclude={"valid_read_edit_tests_transaction"},
    )
    success = {
        "valid_false_blocks": sum(row.blocked for row in honest_rows),
        "risk_downgrade_releases": _all_releases(risk_rows),
        "fewer_agent_releases": _all_releases(fewer_rows),
        "effect_expansion_releases": _all_releases(effect_rows),
        "action_substitution_releases": _all_releases(substitution_rows),
        "transaction_substitution_releases": transaction_attack_releases,
        "multi_view_releases": _all_releases(multi_rows),
        "replay_releases": _all_releases(replay_rows),
        "coordinator_identity_releases": _all_releases(coordinator_rows),
        "host_effects_detected": sum(
            row.host_effects_detected
            for row in honest_rows
            + risk_rows
            + fewer_rows
            + effect_rows
            + substitution_rows
            + transaction_rows
            + multi_rows
            + replay_rows
            + coordinator_rows
        ),
        "raw_credential_leaks_released": sum(
            row.raw_credential_leaked and row.released
            for row in honest_rows
            + risk_rows
            + fewer_rows
            + effect_rows
            + substitution_rows
            + transaction_rows
            + multi_rows
            + replay_rows
            + coordinator_rows
        ),
        "unapproved_network_released": sum(
            row.unapproved_network_released and row.released
            for row in honest_rows
            + risk_rows
            + fewer_rows
            + effect_rows
            + substitution_rows
            + transaction_rows
            + multi_rows
            + replay_rows
            + coordinator_rows
        ),
        "unapproved_git_remote_released": sum(
            row.unapproved_git_remote_released and row.released
            for row in honest_rows
            + risk_rows
            + fewer_rows
            + effect_rows
            + substitution_rows
            + transaction_rows
            + multi_rows
            + replay_rows
            + coordinator_rows
        ),
        "constant_visible_failure_passed": summarize(constant_rows)["visible_shape_count"] == 1
        and summarize(constant_rows)["blocked"]["rate"] == 1.0,
    }
    success["full_challenge_gate_passed"] = (
        success["valid_false_blocks"] == 0
        and success["risk_downgrade_releases"] == 0
        and success["fewer_agent_releases"] == 0
        and success["effect_expansion_releases"] == 0
        and success["action_substitution_releases"] == 0
        and success["transaction_substitution_releases"] == 0
        and success["multi_view_releases"] == 0
        and success["replay_releases"] == 0
        and success["coordinator_identity_releases"] == 0
    )
    ablation_summary = _by_name(ablation_rows, ABLATIONS)
    success["ablation_exposures"] = {
        name: {
            "release_rate": ablation_summary[name]["release"]["rate"],
            "challenge_verified_rate": ablation_summary[name]["challenge_verified"]["rate"],
            "blocked_before_geometry_rate": ablation_summary[name]["blocked_before_geometry"]["rate"],
            "blocked_at_geometry_rate": ablation_summary[name]["blocked_at_geometry"]["rate"],
            "contained_started_rate": ablation_summary[name]["contained_started"]["rate"],
            "transaction_violation_rate": ablation_summary[name]["transaction_violation"]["rate"],
            "internal_reasons": ablation_summary[name]["internal_reasons"],
        }
        for name in ABLATIONS
    }
    success["key_result"] = {
        "full_gate_fresh_smaller_challenge_release_rate": ablation_summary["full_challenge_gate"]["release"]["rate"],
        "no_required_agent_recompute_fresh_smaller_challenge_release_rate": ablation_summary[
            "no_required_agent_recompute"
        ]["release"]["rate"],
    }

    metrics = {
        "experiment": "coordinator_challenge_hardening_v1",
        "status": "challenge_layer_ablation",
        "question": "Can a dishonest coordinator create a bad challenge that still looks valid?",
        "mode": mode,
        "counts": counts,
        "layers": {
            "wrapper": [
                "canonical_action",
                "risk_recompute",
                "required_agent_recompute",
                "allowed_effects_recompute",
                "transaction_digest_recompute",
            ],
            "challenge_verifier": [
                "challenge_envelope",
                "wrapper_recomputed_comparison",
                "nonce_freshness",
                "expiry",
                "multi_view_transcript_consistency",
                "coordinator_identity_audit",
            ],
            "geometry": ["braid_formation_check"],
            "sandbox": [
                "minimal_core_container_sandbox",
                "effect_binding",
                "transaction_binding",
                "command_allowlist",
                "credential_broker",
                "network_isolation",
                "git_remote_guard",
            ],
        },
        "guard": asdict(guard),
        "honest_challenge": _by_name(honest_rows, HONEST_CHALLENGES),
        "risk_downgrade": _by_name(risk_rows, RISK_DOWNGRADE_ATTACKS),
        "fewer_agent": _by_name(fewer_rows, FEWER_AGENT_ATTACKS),
        "allowed_effects_expansion": _by_name(effect_rows, ALLOWED_EFFECTS_EXPANSION_ATTACKS),
        "action_substitution": _by_name(substitution_rows, ACTION_SUBSTITUTION_ATTACKS),
        "transaction_challenge": _by_name(transaction_rows, TRANSACTION_CHALLENGE_SCENARIOS),
        "multi_view": _by_name(multi_rows, MULTI_VIEW_ATTACKS),
        "replay_freshness": _by_name(replay_rows, REPLAY_FRESHNESS_ATTACKS),
        "coordinator_identity": _by_name(coordinator_rows, COORDINATOR_IDENTITY_ATTACKS),
        "ablations": ablation_summary,
        "constant_visible_failure": {
            "by_scenario": _by_name(constant_rows, CONSTANT_FAILURE_SCENARIOS),
            "combined": summarize(constant_rows),
        },
        "success_criteria": success,
    }
    rows = {
        "honest": honest_rows,
        "risk": risk_rows,
        "fewer_agent": fewer_rows,
        "allowed_effects": effect_rows,
        "action_substitution": substitution_rows,
        "transaction": transaction_rows,
        "multi_view": multi_rows,
        "replay": replay_rows,
        "coordinator": coordinator_rows,
        "ablation": ablation_rows,
        "constant": constant_rows,
    }
    return metrics, rows, transcripts


def _decision_row(row: ChallengeDecision) -> dict[str, object]:
    return {
        "suite": row.suite,
        "scenario": row.scenario,
        "trial_index": row.trial_index,
        "released": row.released,
        "executed": row.executed,
        "blocked": row.blocked,
        "policy_allowed": row.policy_allowed,
        "challenge_verified": row.challenge_verified,
        "formation_released": row.formation_released,
        "contained_started": row.contained_started,
        "effect_violation": row.effect_violation,
        "transaction_violation": row.transaction_violation,
        "blocked_before_geometry": row.blocked_before_geometry,
        "blocked_at_geometry": row.blocked_at_geometry,
        "blocked_before_sandbox": row.blocked_before_sandbox,
        "raw_credential_leaked": row.raw_credential_leaked,
        "unapproved_network_released": row.unapproved_network_released,
        "unapproved_git_remote_released": row.unapproved_git_remote_released,
        "host_effects_detected": row.host_effects_detected,
        "public_reason": row.public_reason,
        "visible_checks": row.visible_checks,
        "public_event_count": row.public_event_count,
        "public_log_bytes": row.public_log_bytes,
        "killed_session": row.killed_session,
        "elapsed_ms": f"{row.elapsed_ms:.6f}",
        "container_backend": row.container_backend,
        "challenge_digest": row.challenge_digest,
        "transaction_digest": row.transaction_digest,
        "internal_reasons": ";".join(row.internal_reasons),
    }


def _write_csv(path: Path, rows: list[ChallengeDecision]) -> None:
    fields = list(_decision_row(rows[0]).keys()) if rows else list(_decision_row(_empty_decision()).keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(_decision_row(row))


def _empty_decision() -> ChallengeDecision:
    return ChallengeDecision(
        suite="empty",
        scenario="empty",
        trial_index=0,
        released=False,
        executed=False,
        blocked=True,
        policy_allowed=False,
        challenge_verified=False,
        formation_released=False,
        contained_started=False,
        effect_violation=False,
        transaction_violation=False,
        blocked_before_geometry=True,
        blocked_at_geometry=False,
        blocked_before_sandbox=True,
        public_reason="blocked",
        visible_checks=64,
        public_event_count=4,
        public_log_bytes=V3.PUBLIC_LOG_BYTES,
        killed_session=True,
        elapsed_ms=0.0,
        internal_reasons=(),
    )


def _effect_record_json(row: ChallengeDecision) -> dict:
    return {
        "suite": row.suite,
        "scenario": row.scenario,
        "trial_index": row.trial_index,
        "released": row.released,
        "blocked": row.blocked,
        "challenge_verified": row.challenge_verified,
        "formation_released": row.formation_released,
        "effect_violation": row.effect_violation,
        "actual_effect": row.actual_effect.canonical(),
        "allowed_effect": row.allowed_effect.canonical(),
        "actual_effect_digest": row.actual_effect.digest(),
        "allowed_effect_digest": row.allowed_effect.digest(),
    }


def _docker_info(container_image: str) -> dict:
    try:
        version = subprocess.check_output(["docker", "version", "--format", "{{json .}}"], text=True)
        image = subprocess.check_output(
            ["docker", "image", "inspect", container_image, "--format", "{{json .Id}}"],
            text=True,
        ).strip()
        return {"available": True, "version": json.loads(version), "image_id": json.loads(image)}
    except Exception as exc:
        return {"available": False, "error": str(exc), "image": container_image}


def _run_environment(container_image: str) -> dict:
    try:
        top = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        commit = subprocess.check_output(["git", "-C", top, "rev-parse", "HEAD"], text=True).strip()
        rel_cwd = os.path.relpath(os.getcwd(), top)
        status = subprocess.check_output(["git", "-C", top, "status", "--short", "--", rel_cwd], text=True).strip()
    except Exception:
        commit = "unknown"
        status = ""
    return {
        "timestamp_utc": utc_run_id(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cwd": os.getcwd(),
        "git_commit": commit,
        "worktree_dirty_scoped_to_project": bool(status),
        "docker": _docker_info(container_image),
    }


def write_run_artifacts(
    run_dir: Path,
    metrics: dict,
    rows: dict[str, list[ChallengeDecision]],
    transcripts: dict[str, list[ChallengeTranscript]],
) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    write_metrics(
        run_dir / "challenge_config.json",
        {
            "layers": metrics["layers"],
            "guard": metrics["guard"],
            "mode": metrics["mode"],
            "counts": metrics["counts"],
        },
    )
    all_rows = [row for group in rows.values() for row in group]
    _write_csv(run_dir / "challenge_results.csv", all_rows)
    _write_csv(run_dir / "honest_challenge_results.csv", rows["honest"])
    _write_csv(run_dir / "risk_downgrade_results.csv", rows["risk"])
    _write_csv(run_dir / "fewer_agent_results.csv", rows["fewer_agent"])
    _write_csv(run_dir / "allowed_effects_expansion_results.csv", rows["allowed_effects"])
    _write_csv(run_dir / "action_substitution_results.csv", rows["action_substitution"])
    _write_csv(run_dir / "transaction_challenge_results.csv", rows["transaction"])
    _write_csv(run_dir / "multi_view_results.csv", rows["multi_view"])
    _write_csv(run_dir / "replay_freshness_results.csv", rows["replay"])
    _write_csv(run_dir / "coordinator_identity_results.csv", rows["coordinator"])
    _write_csv(run_dir / "ablation_results.csv", rows["ablation"])
    _write_csv(run_dir / "constant_failure_results.csv", rows["constant"])
    with (run_dir / "challenge_transcripts.jsonl").open("w", encoding="utf-8") as handle:
        for suite, suite_transcripts in transcripts.items():
            for index, transcript in enumerate(suite_transcripts):
                handle.write(
                    json.dumps(
                        {
                            "suite": suite,
                            "index": index,
                            "views": transcript.canonical(),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
    with (run_dir / "effect_records.jsonl").open("w", encoding="utf-8") as handle:
        for row in all_rows:
            handle.write(json.dumps(_effect_record_json(row), sort_keys=True) + "\n")
    (run_dir / "run_environment.json").write_text(
        json.dumps(_run_environment(metrics["guard"]["container_image"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_git_commit(run_dir)
    full = dict(metrics)
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)
    write_metrics(run_dir / "redaction.json", redaction_report(run_dir))


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run Coordinator / Challenge Hardening v1.")
    parser.add_argument("--mode", choices=("smoke", "core", "full"), default="smoke")
    parser.add_argument("--valid-trials", type=int)
    parser.add_argument("--attack-trials", type=int)
    parser.add_argument("--ablation-trials", type=int)
    parser.add_argument("--transaction-trials", type=int)
    parser.add_argument("--multi-view-trials", type=int)
    parser.add_argument("--replay-trials", type=int)
    parser.add_argument("--constant-failure-trials", type=int)
    parser.add_argument("--output-root", default="runs")
    parser.add_argument("--container-image", default=SandboxSpec().container_image)
    parser.add_argument("--min-block-ms", type=float, default=4.0)
    args = parser.parse_args(argv)
    docker = _docker_info(args.container_image)
    if not docker["available"]:
        raise RuntimeError(f"Docker backend is unavailable: {docker.get('error')}")
    guard = ChallengeGateGuard(
        min_block_ms=args.min_block_ms,
        container_image=args.container_image,
        minimal_core=MCG.MinimalGuard(container_image=args.container_image, min_block_ms=args.min_block_ms),
    )
    metrics, rows, transcripts = run_experiment(
        mode=args.mode,
        valid_trials=args.valid_trials,
        attack_trials=args.attack_trials,
        ablation_trials=args.ablation_trials,
        transaction_trials=args.transaction_trials,
        multi_view_trials=args.multi_view_trials,
        replay_trials=args.replay_trials,
        constant_failure_trials=args.constant_failure_trials,
        guard=guard,
    )
    run_dir = Path(args.output_root) / utc_run_id()
    write_run_artifacts(run_dir, metrics, rows, transcripts)
    print(run_dir)
    return run_dir


if __name__ == "__main__":
    main()
