"""Agent registry for the gateway and verifier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from nacl.signing import VerifyKey

from spatial_swarm.core.epoch import SwarmState
from spatial_swarm.geometry.fragment import Fragment
from spatial_swarm.protocol.policies import ProofEnvelope


@dataclass
class AgentRegistration:
    agent_id: str
    verify_key: VerifyKey
    fragment_commitment: str
    envelope: ProofEnvelope
    fragment: Fragment
    active: bool = True


class Registry:
    def __init__(self, epoch: str, registrations: Iterable[AgentRegistration]):
        self.epoch = epoch
        self.state = SwarmState.ACTIVE
        self._registrations = {registration.agent_id: registration for registration in registrations}
        self.original_agent_ids = tuple(sorted(self._registrations, key=_agent_sort_key))

    def get(self, agent_id: str) -> Optional[AgentRegistration]:
        return self._registrations.get(agent_id)

    def require(self, agent_id: str) -> AgentRegistration:
        registration = self.get(agent_id)
        if registration is None:
            raise KeyError(agent_id)
        return registration

    def all_registrations(self) -> list[AgentRegistration]:
        return [self._registrations[agent_id] for agent_id in self.original_agent_ids]

    def active_fragments(self) -> dict[str, Fragment]:
        return {
            agent_id: self._registrations[agent_id].fragment
            for agent_id in self.original_agent_ids
            if self._registrations[agent_id].active
        }

    def original_fragments(self) -> dict[str, Fragment]:
        return {
            agent_id: self._registrations[agent_id].fragment
            for agent_id in self.original_agent_ids
        }

    def eject(self, agent_id: Optional[str]) -> None:
        if agent_id and agent_id in self._registrations:
            self._registrations[agent_id].active = False
        self.state = SwarmState.COLLAPSED


def _agent_sort_key(agent_id: str) -> tuple[str, int]:
    prefix, _, suffix = agent_id.rpartition("_")
    if suffix.isdigit():
        return (prefix, int(suffix))
    return (agent_id, -1)
